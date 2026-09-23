#!/usr/bin/env python3
"""
main.py
-------
CLI entry point: loads a target module, runs a fuzzing campaign
against a chosen function, and prints a triaged report.

Usage:
    python3 main.py --target targets.toy_ftp_parser --function parse_command \\
        --seeds "USER:admin" "NEST:5;CRASHME" --iterations 50000

The target function must accept a single `bytes` argument and raise
on invalid/dangerous input -- that's the only contract this engine
requires.
"""

import argparse
import importlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))
sys.path.insert(0, os.path.dirname(__file__))

from campaign_manager import run_campaign
from severity_scorer import score


def main():
    parser = argparse.ArgumentParser(
        description="Coverage-guided fuzzing engine for Python parsers, built from scratch (no AFL/libFuzzer dependency)"
    )
    parser.add_argument("--target", required=True, help="Python module path, e.g. targets.toy_ftp_parser")
    parser.add_argument("--function", required=True, help="Function name inside the module, must accept bytes")
    parser.add_argument("--seeds", nargs="+", required=True, help="Initial seed strings (encoded as UTF-8 bytes)")
    parser.add_argument("--iterations", type=int, default=20000, help="Number of fuzzing iterations to run")
    parser.add_argument("--seed-value", type=int, default=None, help="RNG seed for reproducibility")
    args = parser.parse_args()

    module = importlib.import_module(args.target)
    target_fn = getattr(module, args.function)
    target_filename_prefix = os.path.basename(module.__file__)

    seeds = [s.encode("utf-8") for s in args.seeds]

    print(f"[1/2] Running {args.iterations} iterations against {args.target}.{args.function}...")
    result = run_campaign(
        target_fn=target_fn,
        target_filename_prefix=target_filename_prefix,
        seeds=seeds,
        iterations=args.iterations,
        seed_value=args.seed_value,
    )

    print(f"      -> {result.stats.corpus_growth_events} corpus growth events, "
          f"{result.stats.total_coverage_lines} unique lines covered, "
          f"{result.stats.unique_crashes} unique crash(es) found "
          f"({result.stats.elapsed_seconds:.2f}s)\n")

    print("[2/2] Triaged crash report:")
    print("=" * 80)

    if result.stats.unique_crashes == 0:
        print("No crashes found in this campaign. Try more iterations or a different seed corpus.")
        return

    for record in result.classifier.representative_crashes():
        verdict = score(record.signature.exception_type)
        print(f"\n[{verdict.severity.value.upper()}] {record.signature.key()}")
        print(f"    Smallest triggering input: {record.input_data!r}")
        print(f"    Rationale: {verdict.rationale}")


if __name__ == "__main__":
    main()
