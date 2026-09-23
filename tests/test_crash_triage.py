import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

from crash_classifier import CrashClassifier
from severity_scorer import score, Severity


def _raise_value_error():
    raise ValueError("boom")


def _raise_recursion_error():
    def recurse():
        recurse()
    recurse()


def test_classifier_deduplicates_same_signature():
    classifier = CrashClassifier()

    for i in range(5):
        try:
            _raise_value_error()
        except ValueError as e:
            classifier.record(input_data=f"input-{i}".encode(), exception=e)

    # all 5 crashes came from the exact same raise site -> 1 unique signature
    assert classifier.unique_crash_count() == 1


def test_classifier_keeps_distinct_signatures_separate():
    classifier = CrashClassifier()

    try:
        _raise_value_error()
    except ValueError as e:
        classifier.record(input_data=b"a", exception=e)

    try:
        raise TypeError("different error")
    except TypeError as e:
        classifier.record(input_data=b"b", exception=e)

    assert classifier.unique_crash_count() == 2


def test_representative_crash_picks_smallest_input():
    classifier = CrashClassifier()

    try:
        _raise_value_error()
    except ValueError as e:
        classifier.record(input_data=b"a-very-long-triggering-input", exception=e)

    try:
        _raise_value_error()
    except ValueError as e:
        classifier.record(input_data=b"short", exception=e)

    representatives = classifier.representative_crashes()
    assert len(representatives) == 1
    assert representatives[0].input_data == b"short"


def test_severity_scorer_flags_recursion_as_dos():
    verdict = score("RecursionError")
    assert verdict.severity == Severity.HIGH_DOS


def test_severity_scorer_flags_value_error_as_low():
    verdict = score("ValueError")
    assert verdict.severity == Severity.LOW_INPUT_VALIDATION


def test_severity_scorer_defaults_unknown_types_to_medium():
    verdict = score("SomeCustomException")
    assert verdict.severity == Severity.MEDIUM_LOGIC_ERROR


if __name__ == "__main__":
    test_classifier_deduplicates_same_signature()
    test_classifier_keeps_distinct_signatures_separate()
    test_representative_crash_picks_smallest_input()
    test_severity_scorer_flags_recursion_as_dos()
    test_severity_scorer_flags_value_error_as_low()
    test_severity_scorer_defaults_unknown_types_to_medium()
    print("All crash_classifier / severity_scorer tests passed.")
