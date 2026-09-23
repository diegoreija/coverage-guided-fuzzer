"""
crash_triage/classifier.py
----------------------------
When a fuzzing campaign runs for a while, the same underlying bug is
usually triggered by MANY different mutated inputs. Without
deduplication, a report would show hundreds of "crashes" that are
really the same root cause repeated over and over.

This module groups crashes by a signature built from the exception
type and the exact line where it was raised -- the same principle
AFL/libFuzzer use with stack-hash deduplication, adapted to Python's
traceback structure.
"""

import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class CrashSignature:
    exception_type: str
    raised_at: str  # "filename:lineno" of the exact line that raised

    def key(self) -> str:
        return f"{self.exception_type}@{self.raised_at}"


@dataclass
class CrashRecord:
    input_data: bytes
    exception: BaseException
    signature: CrashSignature


def build_signature(exception: BaseException) -> CrashSignature:
    tb = exception.__traceback__
    last_frame = tb
    while last_frame.tb_next is not None:
        last_frame = last_frame.tb_next

    filename = last_frame.tb_frame.f_code.co_filename
    lineno = last_frame.tb_lineno

    return CrashSignature(
        exception_type=type(exception).__name__,
        raised_at=f"{filename}:{lineno}",
    )


class CrashClassifier:
    def __init__(self):
        self._groups: Dict[str, List[CrashRecord]] = defaultdict(list)

    def record(self, input_data: bytes, exception: BaseException) -> CrashSignature:
        signature = build_signature(exception)
        record = CrashRecord(input_data=input_data, exception=exception, signature=signature)
        self._groups[signature.key()].append(record)
        return signature

    def unique_crash_count(self) -> int:
        return len(self._groups)

    def representative_crashes(self) -> List[CrashRecord]:
        """One representative input per unique crash signature -- the smallest input found for it."""
        results = []
        for records in self._groups.values():
            smallest = min(records, key=lambda r: len(r.input_data))
            results.append(smallest)
        return results

    def occurrences_of(self, signature_key: str) -> int:
        return len(self._groups.get(signature_key, []))
