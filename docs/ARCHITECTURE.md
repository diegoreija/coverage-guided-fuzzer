# Architecture

## The feedback loop, in detail

```
┌─────────────┐     ┌──────────┐     ┌────────────────────┐
│ pick a seed │────►│  mutate  │────►│ run under settrace  │
└─────────────┘     └──────────┘     └──────────┬──────────┘
       ▲                                          │
       │                                ┌─────────┴─────────┐
       │                                ▼                   ▼
       │                          crashed?             new coverage?
       │                                │                   │
       │                          record + dedupe      add to corpus
       │                          (crash_classifier)   (corpus_manager)
       │                                                    │
       └────────────────────────────────────────────────────┘
```

## Why `sys.settrace` and not bytecode instrumentation

Python exposes `sys.settrace` as a built-in hook that fires on every line executed, every function call, and every exception raised, with zero external dependency. It's slower than compiled instrumentation (there's real per-line overhead), which is an accepted tradeoff for a project whose goal is demonstrating and building the coverage-guided algorithm itself, not achieving the raw execution throughput of a production fuzzer.

The tracer restricts recorded lines to files matching `target_filename_prefix` (see `coverage_tracker.py`). Without this filter, coverage would include every standard-library function the target happens to call internally (string methods, `int()` parsing, etc.), which would make "new coverage" trigger constantly on noise rather than on genuinely new *target* logic.

## Why mutation-based, not generation-based

There are two broad families of fuzzers: **generation-based** (build inputs from a grammar/spec of the protocol) and **mutation-based** (start from real seed inputs and randomly perturb them). AFL, libFuzzer, and this project are all mutation-based, because it requires no prior knowledge of the target's input format — you don't need to write a grammar for the protocol, you just need a handful of valid example inputs to start from.

## Why BFS-style breadth over the corpus, not a queue by discovery order

Unlike a naive queue (fuzz seed 1 exhaustively, then seed 2, etc.), this engine picks the next seed to mutate **uniformly at random from the whole corpus** on every iteration. This means newly discovered corpus entries get mixed in with older ones immediately, rather than waiting for older entries to be exhausted first — closer in spirit to AFL's queue-cycling behavior than to a strict depth-first or breadth-first traversal of the input space.

## Mutation strategies implemented

| Strategy | What it does | Why it's useful |
|---|---|---|
| Bit flip | Flips one random bit in one random byte | Finds off-by-one conditions in bit-level parsing |
| Byte insert | Inserts one random byte at a random position | Grows inputs to reach length-dependent code paths |
| Byte delete | Removes one random byte | Shrinks inputs, can trigger under-length edge cases |
| Byte overwrite | Replaces one random byte with another random value | The most common AFL-style "havoc" mutation |
| Splice | Combines a prefix of one corpus entry with a suffix of another | Recombines two different "interesting" behaviors into a new input that might trigger both code paths in sequence |

## Crash deduplication: why exception type + exact line, not full stack trace

A full stack-trace hash (like AFL's default) is more precise but also more fragile — two crashes that are conceptually "the same bug" can end up with slightly different call stacks depending on which mutation path reached them. Using `(exception type, exact line that raised)` as the signature is a deliberate simplification: it's coarser, but stable across the many different input variants that tend to trigger the same underlying logic error, which matters more for a small-scale engine like this one where the goal is a short, readable list of *distinct* bugs rather than exhaustive stack-level precision.

## What a production-grade version would add

This project intentionally stops short of reimplementing AFL's more advanced heuristics — see the Roadmap in the README. The two most impactful additions for scaling this beyond toy targets would be:

1. **Energy scheduling** — instead of picking the next seed uniformly at random, weight the choice by how much new coverage that seed has historically produced per execution, so the search concentrates effort where it's paying off.
2. **Dictionary-based mutation** — inject known tokens (numbers, protocol keywords, magic strings) instead of relying purely on byte-level mutation to accidentally construct them, which is inefficient for anything requiring an exact multi-character match (as demonstrated by the `RecursionError` bug this engine currently fails to find — see README Limitations).
