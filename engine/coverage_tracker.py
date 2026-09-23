"""
coverage_tracker.py
--------------------
Measures code coverage of a single function call using Python's own
sys.settrace hook, with no external dependency (no `coverage.py`).

Why build this instead of using the `coverage` package: the standard
`coverage` library is designed for test-suite reporting (aggregate
coverage across a whole run), not for a tight fuzzing loop that needs
a fast, per-execution coverage SET to compare against a running
"coverage frontier". Writing the tracer directly on top of
sys.settrace gives full control over exactly what is measured and
keeps the engine dependency-free -- the same reasoning AFL/libFuzzer
apply at the compiler-instrumentation level, applied here at the
Python interpreter level.
"""

import sys
from typing import Callable, FrozenSet, Set, Tuple

CoverageSet = FrozenSet[Tuple[str, int]]  # (filename, line_number) pairs executed


class CrashResult:
    """Represents the outcome of running the target on one input."""

    def __init__(self, crashed: bool, exception: BaseException | None, coverage: CoverageSet):
        self.crashed = crashed
        self.exception = exception
        self.coverage = coverage


def _make_tracer(hit_lines: Set[Tuple[str, int]], target_filename_prefix: str):
    """
    Builds a trace function that records every (file, line) pair
    executed, but ONLY within files under `target_filename_prefix`.

    Restricting to the target's own source is important: without it,
    coverage would include the Python standard library and this
    tracer's own code, drowning the signal that actually matters
    (which branches of the TARGET were reached).
    """

    def tracer(frame, event, arg):
        if event == "line":
            filename = frame.f_code.co_filename
            if target_filename_prefix in filename:
                hit_lines.add((filename, frame.f_lineno))
        return tracer

    return tracer


def run_with_coverage(target_fn: Callable[[bytes], None], data: bytes, target_filename_prefix: str) -> CrashResult:
    """
    Executes target_fn(data) under coverage tracing.

    Any exception raised by target_fn is treated as a "crash" -- this
    is the Python-level equivalent of a segfault/ASan abort in a C
    fuzzing target: an unhandled exception means the input reached a
    code path the target's author did not defensively handle.
    """
    hit_lines: Set[Tuple[str, int]] = set()
    tracer = _make_tracer(hit_lines, target_filename_prefix)

    old_tracer = sys.gettrace()
    sys.settrace(tracer)
    crashed = False
    exception: BaseException | None = None
    try:
        target_fn(data)
    except Exception as exc:  # noqa: BLE001 - intentionally broad, this is the fuzzing signal
        crashed = True
        exception = exc
    finally:
        sys.settrace(old_tracer)

    return CrashResult(crashed=crashed, exception=exception, coverage=frozenset(hit_lines))
