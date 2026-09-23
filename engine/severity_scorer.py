"""
severity_scorer.py
--------------------
Gives each unique crash a preliminary severity label based on the
exception type. This is NOT a substitute for manual triage -- it's a
fast first pass to help a human decide which of possibly dozens of
unique crashes to look at first.

Important, honest framing: in a memory-unsafe language (C/C++), a
fuzzer-found crash can mean actual memory corruption -- a real
security vulnerability. In pure Python, an unhandled exception
usually means a logic/parsing bug or a denial-of-service condition
(unbounded recursion, catastrophic backtracking, resource
exhaustion), not memory corruption, since the interpreter itself
is memory-safe. The severity labels below reflect that distinction
explicitly rather than overstating impact.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    HIGH_DOS = "high_dos"                 # infinite loop / unbounded resource use
    MEDIUM_LOGIC_ERROR = "medium_logic"   # unhandled exception indicating a parsing/logic flaw
    LOW_INPUT_VALIDATION = "low_validation"  # e.g. a plain ValueError from bad input, likely benign


# Exception types that typically indicate a DoS-class issue
# (resource exhaustion, not a simple malformed-input rejection).
_DOS_INDICATING_EXCEPTIONS = {"RecursionError", "MemoryError"}

# Exception types that are frequently just "input didn't validate",
# i.e. low severity unless proven otherwise by manual review.
_LIKELY_BENIGN_EXCEPTIONS = {"ValueError", "TypeError"}


@dataclass
class SeverityVerdict:
    severity: Severity
    rationale: str


def score(exception_type: str) -> SeverityVerdict:
    if exception_type in _DOS_INDICATING_EXCEPTIONS:
        return SeverityVerdict(
            severity=Severity.HIGH_DOS,
            rationale=f"{exception_type} typically indicates unbounded resource consumption "
                      f"(denial-of-service class), not a simple rejected input.",
        )

    if exception_type in _LIKELY_BENIGN_EXCEPTIONS:
        return SeverityVerdict(
            severity=Severity.LOW_INPUT_VALIDATION,
            rationale=f"{exception_type} is commonly raised for ordinary malformed input; "
                      f"review manually to confirm it isn't masking a deeper issue.",
        )

    return SeverityVerdict(
        severity=Severity.MEDIUM_LOGIC_ERROR,
        rationale=f"Unhandled {exception_type} reached a code path the target's error handling "
                  f"did not anticipate -- worth manual review to determine real impact.",
    )
