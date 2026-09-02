"""Incremental narrowing must be invisible: same results as a full rescan.

The failure mode of getting this wrong is *silently missing results*, so these
tests compare a narrowing engine (one instance, reused across an edit sequence,
so its pool survives) against a fresh engine per query (no pool, full rescan).
"""

from __future__ import annotations

import pytest

from seek.config import Config
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import can_narrow, parse_query
from seek.scope import build_scope
from seek.walk import walk

WORDS = ["main", "mainly", "domain", "maintain", "remains", "plain", "amino"]


@pytest.fixture
def corpus(tmp_path):
    for i, w in enumerate(WORDS):
        (tmp_path / f"{w}_{i}.py").write_text(
            f"def {w}_handler():\n    return '{w}'\n# a {w} comment\nMAIN = {i}\n"
        )
    (tmp_path / "other.txt").write_text("nothing relevant here\nsecond line\n")
    return tmp_path


def _store(root, config):
    store = CandidateStore()
    for cand in walk(root, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    return store


def _fresh(root, config) -> SearchEngine:
    return SearchEngine(config, _store(root, config))


def _key(rs):
    return (
        rs.total,
        rs.state,
        [(r.kind, r.rel, r.line_no, r.score, tuple(r.spans)) for r in rs.results],
    )


def _assert_sequence_matches_rescan(root, queries, modes=None, **cfg):
    config = Config(**cfg)
    modes = modes or Modes()
    narrowing = _fresh(root, config)  # reused -> keeps its pool between queries
    for i, q in enumerate(queries):
        parsed = parse_query(q)
        got = narrowing.search(parsed, modes, i)
        want = _fresh(root, config).search(parsed, modes, i)  # no pool
        assert _key(got) == _key(want), f"narrowed result differs at {q!r}"


# --- the predicate ---------------------------------------------------------


@pytest.mark.parametrize(
    "old,new",
    [
        ("ma", "mai"),            # ordinary typing
        ("ma", "main"),
        ("main", "main py"),      # adding a whole term
        ("main", "main !test"),   # adding a negated term still narrows
        ("main", "main"),         # unchanged
        ("^ma", "^mai"),          # prefix extended
        ("'ma", "'mai"),          # exact extended
        ("ma", "ma'x"),           # fuzzy gains a literal
        ("a b", "a bc"),          # last of several terms extended
    ],
)
def test_can_narrow_accepts(old, new):
    assert can_narrow(parse_query(old), parse_query(new))


@pytest.mark.parametrize(
    "old,new",
    [
        ("main", "mai"),          # deletion widens
        ("main", "xmain"),        # edit at the front
        ("a b", "ax b"),          # edit to a non-final term
        ("!ma", "!main"),         # extending a negation excludes fewer
        ("ma$", "ma$x"),          # `$` re-types the term: suffix -> fuzzy
        ("^ma$", "^ma$x"),        # equal -> prefix, also widens
        ("main", ""),             # cleared
        ("", "main"),             # no previous query
        ("main py", "main"),      # a term removed
    ],
)
def test_can_narrow_rejects(old, new):
    assert not can_narrow(parse_query(old), parse_query(new))


def test_suffix_retype_would_have_widened(corpus):
    """`ma$` -> `ma$x` is the case that makes a raw-prefix rule unsound."""
    config = Config()
    old, new = parse_query("ma$"), parse_query("ma$x")
    assert not can_narrow(old, new)
    # a line matching `ma$x` fuzzily that `ma$` never matched really does exist
    (corpus / "z.txt").write_text("ma$x\n")
    eng2 = _fresh(corpus, config)
    assert eng2.search(new, Modes(), 1).total > 0


# --- end-to-end equivalence -------------------------------------------------


def test_typing_sequence_matches_rescan(corpus):
    _assert_sequence_matches_rescan(corpus, ["ma", "mai", "main", "main."])


def test_adding_terms_matches_rescan(corpus):
    _assert_sequence_matches_rescan(corpus, ["main", "main py", "main py !x"])


def test_deletion_falls_back_and_recovers_results(corpus):
    # narrow down, then delete - the widened query must get its results back
    _assert_sequence_matches_rescan(corpus, ["maintain", "main", "ma", "m"])


def test_anchored_and_exact_sequences_match_rescan(corpus):
    _assert_sequence_matches_rescan(corpus, ["^ma", "^mai", "^main"])
    _assert_sequence_matches_rescan(corpus, ["'ma", "'mai", "'main"])
    _assert_sequence_matches_rescan(corpus, ["ma$", "ma$x", "ma"])


def test_mode_toggle_invalidates_the_pool(corpus):
    config = Config()
    eng = _fresh(corpus, config)
    eng.search(parse_query("ma"), Modes(True, True, True), 1)
    # same narrowing query but content mode just came on: must not reuse a pool
    # that was built without content matches
    got = eng.search(parse_query("mai"), Modes(file=False, dir=False, content=True), 2)
    want = _fresh(corpus, config).search(
        parse_query("mai"), Modes(file=False, dir=False, content=True), 3
    )
    assert _key(got)[:2] == _key(want)[:2]


def test_reroot_invalidates_the_pool(corpus):
    config = Config()
    store = _store(corpus, config)
    eng = SearchEngine(config, store)
    eng.search(parse_query("ma"), Modes(), 1)
    store.clear()  # what a re-root / refresh does
    for cand in walk(corpus, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    got = eng.search(parse_query("main"), Modes(), 2)
    want = _fresh(corpus, config).search(parse_query("main"), Modes(), 3)
    assert _key(got) == _key(want)


def test_narrowing_is_actually_engaged(corpus):
    """Guard against the tests passing only because narrowing never happens."""
    eng = _fresh(corpus, Config())
    eng.search(parse_query("ma"), Modes(), 1)
    assert eng._pool is not None
    assert eng._usable_pool(parse_query("mai"), Modes(), eng.store.view()[1]) is not None
    assert eng._usable_pool(parse_query("m"), Modes(), eng.store.view()[1]) is None


def test_pool_not_seeded_by_a_cancelled_search(corpus):
    eng = _fresh(corpus, Config())
    eng.search(parse_query("ma"), Modes(), 1, is_stale=lambda: True)
    assert eng._pool is None


def test_narrowing_respects_the_result_cap(corpus):
    _assert_sequence_matches_rescan(corpus, ["ma", "mai", "main"], max_results=3)
