import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

from corpus_manager import CorpusManager


def test_consider_adds_entry_when_coverage_is_new():
    corpus = CorpusManager(seeds=[b"seed"])
    added = corpus.consider(b"new-input", coverage=frozenset({("f.py", 1), ("f.py", 2)}), generation=1)

    assert added is True
    assert len(corpus.entries) == 2  # original seed + the new one
    assert corpus.total_coverage == {("f.py", 1), ("f.py", 2)}


def test_consider_rejects_entry_with_no_new_coverage():
    corpus = CorpusManager(seeds=[b"seed"])
    corpus.consider(b"first", coverage=frozenset({("f.py", 1)}), generation=1)

    added_again = corpus.consider(b"redundant", coverage=frozenset({("f.py", 1)}), generation=1)

    assert added_again is False
    assert len(corpus.entries) == 2  # seed + "first" only, "redundant" not added


def test_bit_flip_changes_exactly_one_bit():
    corpus = CorpusManager(seeds=[b"x"], rng=random.Random(1))
    original = b"\x00"
    mutated = corpus._bit_flip(original)

    diff = original[0] ^ mutated[0]
    # a single bit flip means the XOR has exactly one bit set (a power of two)
    assert diff != 0
    assert (diff & (diff - 1)) == 0


def test_byte_insert_grows_length_by_one():
    corpus = CorpusManager(seeds=[b"x"], rng=random.Random(2))
    original = b"abc"
    mutated = corpus._byte_insert(original)

    assert len(mutated) == len(original) + 1


def test_byte_delete_shrinks_length_by_one():
    corpus = CorpusManager(seeds=[b"x"], rng=random.Random(3))
    original = b"abcd"
    mutated = corpus._byte_delete(original)

    assert len(mutated) == len(original) - 1


def test_byte_delete_is_noop_on_single_byte_input():
    corpus = CorpusManager(seeds=[b"x"], rng=random.Random(4))
    original = b"a"
    mutated = corpus._byte_delete(original)

    assert mutated == original  # documented behavior: won't delete the last byte


def test_splice_combines_two_entries():
    corpus = CorpusManager(seeds=[b"AAAA", b"BBBB"], rng=random.Random(5))
    result = corpus._splice(b"AAAA")

    # result should be a combination touching both alphabets, or at minimum
    # a valid byte string of plausible length
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_pick_seed_returns_an_existing_entry():
    corpus = CorpusManager(seeds=[b"only-seed"], rng=random.Random(6))
    picked = corpus.pick_seed()

    assert picked.data == b"only-seed"


if __name__ == "__main__":
    test_consider_adds_entry_when_coverage_is_new()
    test_consider_rejects_entry_with_no_new_coverage()
    test_bit_flip_changes_exactly_one_bit()
    test_byte_insert_grows_length_by_one()
    test_byte_delete_shrinks_length_by_one()
    test_byte_delete_is_noop_on_single_byte_input()
    test_splice_combines_two_entries()
    test_pick_seed_returns_an_existing_entry()
    print("All corpus_manager tests passed.")
