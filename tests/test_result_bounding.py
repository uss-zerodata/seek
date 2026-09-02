"""Bounded result accumulation must not change ranking, totals, or spans."""

from __future__ import annotations

from seek.config import Config
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import parse_query
from seek.engine.score import match_score, match_spans
from seek.models import MatchKind
from seek.scope import build_scope
from seek.walk import walk


def _engine(root, **cfg) -> SearchEngine:
    config = Config(**cfg)
    store = CandidateStore()
    for cand in walk(root, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    return SearchEngine(config, store)


def _corpus(tmp_path, files=40, lines=30):
    for i in range(files):
        (tmp_path / f"alpha_{i}.py").write_text(
            "".join(f"alpha value {j} in file {i}\n" for j in range(lines))
        )
    return tmp_path


def test_capping_preserves_the_uncapped_ranking(tmp_path):
    root = _corpus(tmp_path)
    uncapped = _engine(root, max_results=0).search(parse_query("alpha"), Modes(), 1)
    capped = _engine(root, max_results=10).search(parse_query("alpha"), Modes(), 1)

    assert len(capped.results) == 10
    assert capped.total == uncapped.total
    # the capped set is exactly the head of the full ranking, in the same order
    key = lambda r: (r.score, r.rel, r.line_no)  # noqa: E731
    assert [key(r) for r in capped.results] == [key(r) for r in uncapped.results[:10]]


def test_total_counts_every_match_not_just_the_kept_ones(tmp_path):
    root = _corpus(tmp_path, files=20, lines=25)
    rs = _engine(root, max_results=5).search(parse_query("alpha"), Modes(), 1)
    assert len(rs.results) == 5
    # 20 files x 25 content lines + 20 filename matches
    assert rs.total == 20 * 25 + 20


def test_scores_are_non_increasing_and_match_the_scorer(tmp_path):
    root = _corpus(tmp_path, files=8, lines=8)
    rs = _engine(root, max_results=20).search(parse_query("alpha"), Modes(), 1)
    query = parse_query("alpha")
    scores = [r.score for r in rs.results]
    assert scores == sorted(scores, reverse=True)
    for r in rs.results:
        text = r.line_text if r.kind is MatchKind.CONTENT else r.rel.rsplit("/", 1)[-1]
        assert r.score == match_score(query, text)


def test_every_capped_result_still_has_its_spans(tmp_path):
    root = _corpus(tmp_path, files=30, lines=20)
    query = parse_query("alpha")
    rs = _engine(root, max_results=7).search(query, Modes(), 1)
    assert len(rs.results) == 7
    for r in rs.results:
        text = r.line_text if r.kind is MatchKind.CONTENT else r.rel.rsplit("/", 1)[-1]
        assert r.spans, f"no spans on {r.rel}:{r.line_no}"
        assert r.spans == match_spans(query, text)[1]
        # spans point at real matched characters
        assert all(0 <= p < len(text) for p in r.spans)


def test_bounded_memory_for_a_very_broad_query(tmp_path):
    """A query matching far more than the cap must not retain one Result each."""
    root = _corpus(tmp_path, files=60, lines=100)
    rs = _engine(root, max_results=25).search(parse_query("alpha"), Modes(), 1)
    assert rs.total >= 6000          # matched a lot
    assert len(rs.results) == 25     # kept only the cap
