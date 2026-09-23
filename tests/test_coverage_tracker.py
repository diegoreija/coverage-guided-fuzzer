import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

from coverage_tracker import run_with_coverage


def _sample_target(data: bytes) -> None:
    if len(data) > 0:
        x = data[0]
        if x == 42:
            raise ValueError("hit the magic byte")


def test_coverage_records_lines_in_target_file():
    result = run_with_coverage(_sample_target, b"\x00", target_filename_prefix="test_coverage_tracker.py")
    assert not result.crashed
    assert len(result.coverage) > 0


def test_different_inputs_produce_different_coverage():
    result_short_path = run_with_coverage(_sample_target, b"", target_filename_prefix="test_coverage_tracker.py")
    result_long_path = run_with_coverage(_sample_target, b"\x00", target_filename_prefix="test_coverage_tracker.py")

    assert result_short_path.coverage != result_long_path.coverage


def test_exception_is_caught_and_reported_as_crash():
    result = run_with_coverage(_sample_target, bytes([42]), target_filename_prefix="test_coverage_tracker.py")

    assert result.crashed
    assert isinstance(result.exception, ValueError)


def test_coverage_excludes_files_outside_prefix():
    # target_filename_prefix that matches nothing real -> no lines recorded
    result = run_with_coverage(_sample_target, b"\x00", target_filename_prefix="this_file_does_not_exist.py")
    assert len(result.coverage) == 0


if __name__ == "__main__":
    test_coverage_records_lines_in_target_file()
    test_different_inputs_produce_different_coverage()
    test_exception_is_caught_and_reported_as_crash()
    test_coverage_excludes_files_outside_prefix()
    print("All coverage_tracker tests passed.")
