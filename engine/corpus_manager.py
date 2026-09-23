"""
corpus_manager.py
-------------------
Holds the growing set of "interesting" inputs -- those that expanded
the total coverage frontier when they were first tried -- and
generates new candidate inputs by mutating entries already in the
corpus.

This is the "guided" part of the fuzzer: instead of generating
completely random bytes on every iteration (which wastes almost all
effort on inputs that never get past the first validation check),
new candidates are built by mutating inputs that are ALREADY known
to reach interesting code, biasing the search toward the unexplored
frontier instead of restarting from nothing each time.
"""

import random
from dataclasses import dataclass, field
from typing import List

from coverage_tracker import CoverageSet


@dataclass
class CorpusEntry:
    data: bytes
    coverage: CoverageSet
    generation: int  # how many mutation steps removed from the original seed


class CorpusManager:
    def __init__(self, seeds: List[bytes], rng: random.Random | None = None):
        self.entries: List[CorpusEntry] = [CorpusEntry(data=s, coverage=frozenset(), generation=0) for s in seeds]
        self.total_coverage: set = set()
        self.rng = rng or random.Random()

    def consider(self, data: bytes, coverage: CoverageSet, generation: int) -> bool:
        """
        Adds `data` to the corpus IF it reaches at least one
        (file, line) pair never seen before. Returns True if it was
        added (i.e. the coverage frontier grew).
        """
        new_lines = coverage - self.total_coverage
        if not new_lines:
            return False

        self.total_coverage |= coverage
        self.entries.append(CorpusEntry(data=data, coverage=coverage, generation=generation))
        return True

    def pick_seed(self) -> CorpusEntry:
        """
        Picks a corpus entry to mutate next. Favors entries with
        fewer generations behind them slightly less than pure random
        choice would -- in this simple engine, uniform random choice
        is used, which is a documented simplification (see README
        Limitations: no energy scheduling like AFL's).
        """
        return self.rng.choice(self.entries)

    def mutate(self, data: bytes) -> bytes:
        """Applies one randomly chosen mutation strategy to `data`."""
        if len(data) == 0:
            return self._insert_random_byte(data)

        strategy = self.rng.choice([
            self._bit_flip,
            self._byte_insert,
            self._byte_delete,
            self._byte_overwrite,
            self._splice,
        ])
        return strategy(data)

    # --- mutation strategies -------------------------------------------------

    def _bit_flip(self, data: bytes) -> bytes:
        if not data:
            return data
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf))
        bit = 1 << self.rng.randrange(8)
        buf[idx] ^= bit
        return bytes(buf)

    def _byte_insert(self, data: bytes) -> bytes:
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf) + 1)
        buf.insert(idx, self.rng.randrange(256))
        return bytes(buf)

    def _byte_delete(self, data: bytes) -> bytes:
        if len(data) <= 1:
            return data
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf))
        del buf[idx]
        return bytes(buf)

    def _byte_overwrite(self, data: bytes) -> bytes:
        if not data:
            return data
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf))
        buf[idx] = self.rng.randrange(256)
        return bytes(buf)

    def _splice(self, data: bytes) -> bytes:
        """Combines a random prefix of `data` with a random suffix of another corpus entry."""
        if len(self.entries) < 2 or not data:
            return self._byte_insert(data)
        other = self.rng.choice(self.entries).data
        if not other:
            return self._byte_insert(data)
        cut_a = self.rng.randrange(len(data))
        cut_b = self.rng.randrange(len(other))
        return data[:cut_a] + other[cut_b:]

    def _insert_random_byte(self, data: bytes) -> bytes:
        return bytes([self.rng.randrange(256)])
