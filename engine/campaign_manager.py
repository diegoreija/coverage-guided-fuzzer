"""
campaign_manager.py
----------------------
Runs a complete coverage-guided fuzzing campaign against a target
function: pick a seed from the corpus, mutate it, run it under
coverage tracing, and decide what to do with the result.

The core loop, in plain terms:

    1. pick an input already known to be "interesting" from the corpus
    2. mutate it slightly
    3. run the target on the mutated input, tracing coverage
    4. if it crashed -> record it (deduplicated by signature)
    5. if it didn't crash but reached NEW code -> add it to the corpus
       (it becomes a future seed for more mutations)
    6. repeat

This is the same feedback loop AFL/AFL++/libFuzzer use at the
compiled-binary level; here it operates at the Python bytecode level
via sys.settrace, which is why this project targets Python parsers
rather than compiled C/C++ binaries. See docs/ARCHITECTURE.md for
the full comparison and when a compiled-target fuzzer (AFL++) would
be the right tool instead.
"""

import time
from dataclasses import dataclass, field
from typing import Callable, List

from coverage_tracker import run_with_coverage
from corpus_manager import CorpusManager
from crash_classifier import CrashClassifier


@dataclass
class CampaignStats:
    iterations: int = 0
    corpus_growth_events: int = 0
    unique_crashes: int = 0
    total_coverage_lines: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class CampaignResult:
    stats: CampaignStats
    classifier: CrashClassifier
    corpus: CorpusManager


def run_campaign(
    target_fn: Callable[[bytes], None],
    target_filename_prefix: str,
    seeds: List[bytes],
    iterations: int,
    seed_value: int | None = None,
) -> CampaignResult:
    import random
    rng = random.Random(seed_value)

    corpus = CorpusManager(seeds=seeds, rng=rng)
    classifier = CrashClassifier()
    stats = CampaignStats()

    start = time.time()

    for i in range(iterations):
        parent = corpus.pick_seed()
        candidate = corpus.mutate(parent.data)

        result = run_with_coverage(target_fn, candidate, target_filename_prefix)
        stats.iterations += 1

        if result.crashed:
            classifier.record(candidate, result.exception)
        else:
            grew = corpus.consider(candidate, result.coverage, generation=parent.generation + 1)
            if grew:
                stats.corpus_growth_events += 1

    stats.elapsed_seconds = time.time() - start
    stats.unique_crashes = classifier.unique_crash_count()
    stats.total_coverage_lines = len(corpus.total_coverage)

    return CampaignResult(stats=stats, classifier=classifier, corpus=corpus)
