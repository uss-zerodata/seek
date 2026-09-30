"""Release order, and ranges that cannot be decided."""

from __future__ import annotations

import itertools

import pytest

from seek.vulndb.versions import compare, in_range, segments


@pytest.mark.parametrize(("a", "b"), [
    ("1.9", "1.10"), ("8.9", "8.9p1"), ("8.9p1", "8.10"), ("1.0rc1", "1.0"),
    ("2.4.41", "2.4.100"), ("1.0alpha", "1.0beta"), ("1.0beta2", "1.0rc1"),
    ("1.0", "1.0.1"), ("1.0.1", "1.0.2"), ("7.4", "7.4.33"), ("1.16.1", "1.20.1"),
    ("9.0.1", "9.0.31"), ("8.2p1", "8.9p1"), ("1.0.2k", "1.0.2u"), ("1.0.2u", "1.1.0"),
    ("v2.1.3", "2.1.4"), ("4.6.2", "4.6.16"),
])
def test_release_order(a, b):
    assert compare(a, b) == -1
    assert compare(b, a) == 1


@pytest.mark.parametrize(("a", "b"), [("1.0", "1.0.0"), ("2.4", "2.4"), ("V1.2", "1.2")])
def test_equal(a, b):
    assert compare(a, b) == 0


@pytest.mark.parametrize("v", ["3.X - 4.X", "2.*", "5.x", "", "-", "*", "4.0 to 4.2", "beta"])
def test_undecidable(v):
    assert segments(v) is None
    assert compare(v, "1.0") is None


CORPUS = ["1.9", "1.10", "8.9", "8.9p1", "8.10", "1.0rc1", "1.0", "1.0.0", "2.4.41",
          "2.4.100", "1.0alpha", "1.0beta", "10.0p2", "1.16.1", "1.24.0", "7.4.33",
          "3.8", "2.1.3", "4.6.2", "9.0.1", "1.0.2k", "1.1.0", "0.6.18", "2020.81"]


def test_order_is_consistent():
    for a, b in itertools.permutations(CORPUS, 2):
        assert compare(a, b) == -compare(b, a), (a, b)
    for a, b, c in itertools.permutations(CORPUS, 3):
        if compare(a, b) <= 0 and compare(b, c) <= 0:
            assert compare(a, c) <= 0, (a, b, c)


def test_a_version_inside_and_past_a_range():
    assert in_range("1.16.1", start_incl="0.6.18", end_excl="1.20.1") is True
    assert in_range("1.24.0", start_incl="0.6.18", end_excl="1.20.1") is False
    assert in_range("1.20.1", end_excl="1.20.1") is False
    assert in_range("1.20.1", end_incl="1.20.1") is True
    assert in_range("0.6.18", start_excl="0.6.18") is False


def test_exact_versions():
    assert in_range("2.4.41", exact="2.4.41") is True
    assert in_range("2.4.41", exact="2.4.42") is False
    assert in_range("2.4.41", exact="*") is True, "any version"
    assert in_range("2.4.41", exact="-") is None


def test_undecidable_is_never_an_answer():
    assert in_range("3.X - 4.X", end_excl="4.2") is None
    assert in_range("4.1", end_excl="4.x") is None
    assert in_range("5.0", start_incl="4.x", end_excl="4.2") is False, \
        "a decidable bound that excludes still excludes"
