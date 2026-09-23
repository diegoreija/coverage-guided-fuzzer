"""
toy_ftp_parser.py
--------------------
A deliberately buggy parser for a small text-based protocol, modeled
after the kind of custom service you sometimes find on a CTF/THM box
that isn't plain HTTP -- exactly the scenario where `ffuf` gives you
nothing to work with, because there's no URL space to brute-force.

This target has THREE intentional bugs of different classes, used to
validate that the fuzzing engine can find each kind:

    1. An out-of-bounds index (IndexError) on a malformed USERNAME field
    2. Unbounded recursion (RecursionError) on a crafted nested field
    3. A silent logic bug that only crashes on a very specific byte
       sequence, unlikely to be found by pure random fuzzing without
       coverage guidance

This file is the "vulnerable service" the campaign is run against in
examples/sample_campaign_run.md.
"""


def parse_command(data: bytes) -> None:
    """
    Parses a line of a toy protocol with two commands:

        USER:<name>
        NEST:<count>;<payload>

    Any other input is rejected safely. The bugs live inside how
    USER and NEST are handled.
    """
    if not data:
        return

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return  # not a bug: safely rejects invalid UTF-8

    if text.startswith("USER:"):
        _handle_user(text)
    elif text.startswith("NEST:"):
        _handle_nest(text)
    else:
        return  # unknown command, safely ignored


def _handle_user(text: str) -> None:
    """
    Bug #1: if the username field contains a specific control marker
    "\\x01" followed by nothing, the code below indexes past the end
    of the split list -- an IndexError, i.e. a crash.
    """
    payload = text[len("USER:"):]
    parts = payload.split("\x01")
    # Intentional bug: assumes there's always a part AFTER the marker.
    # A crafted payload like "USER:admin\x01" has nothing after it.
    if len(parts) > 1:
        _ = parts[1][0]  # IndexError if parts[1] is empty


def _handle_nest(text: str) -> None:
    """
    Bug #2: the "count" field controls recursion depth with NO upper
    bound check -- a large enough value blows the Python call stack
    (RecursionError), a denial-of-service class finding.
    """
    payload = text[len("NEST:"):]
    if ";" not in payload:
        return
    count_str, rest = payload.split(";", 1)
    try:
        count = int(count_str)
    except ValueError:
        return

    _recurse(count, rest)


def _recurse(remaining: int, payload: str) -> None:
    if remaining <= 0:
        return
    # Bug #3, subtler: a specific payload value ("CRASHME") at the
    # deepest recursion level triggers a ZeroDivisionError that a
    # simple random fuzzer is unlikely to stumble into by chance --
    # it requires BOTH reaching sufficient depth AND the exact
    # payload string, which coverage-guided mutation discovers
    # incrementally (depth first, then the payload) far faster than
    # blind random generation.
    if remaining == 1 and payload == "CRASHME":
        _ = 1 // 0
    _recurse(remaining - 1, payload)
