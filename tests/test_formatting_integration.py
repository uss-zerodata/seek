"""Formatting end to end: cache, engine, line numbers, actions, narrowing."""

from __future__ import annotations

import json

import pytest

from seek import actions
from seek.config import Config
from seek.engine.content import ContentCache
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import parse_query
from seek.models import MatchKind
from seek.scope import build_scope
from seek.walk import walk

BLOB = json.dumps(
    {"users": [{"id": i, "name": f"user{i}", "role": "admin"} for i in range(80)]}
)


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "data.json").write_text(BLOB + "\n")          # one huge line
    (tmp_path / "pretty.json").write_text('{\n  "name": "admin"\n}\n')
    (tmp_path / "code.py").write_text("role = 'admin'\n")
    return tmp_path


def _engine(root, **cfg) -> SearchEngine:
    config = Config(**cfg)
    store = CandidateStore()
    for cand in walk(root, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    return SearchEngine(config, store)


# --- cache ------------------------------------------------------------------


def test_cache_stores_formatted_lines_and_the_origin_map(tree):
    cache = ContentCache(10_000_000, config=Config())
    lines, origin = cache.content(tree / "data.json")
    assert len(lines) > 80
    assert origin == [1] * len(lines)
    # second call is served from the cache, identically
    assert cache.content(tree / "data.json") == (lines, origin)


def test_cache_returns_no_map_for_an_unformatted_file(tree):
    cache = ContentCache(10_000_000, config=Config())
    lines, origin = cache.content(tree / "pretty.json")
    assert origin is None
    assert lines == ['{', '  "name": "admin"', '}']


def test_cache_clear_empties_everything(tree):
    cache = ContentCache(10_000_000, config=Config())
    cache.content(tree / "data.json")
    assert cache.cached_bytes > 0
    cache.clear()
    assert cache.cached_bytes == 0
    assert cache.content(tree / "data.json") is not None  # re-reads fine


def test_cache_honours_the_toggle(tree):
    cache = ContentCache(10_000_000, config=Config())
    assert len(cache.content(tree / "data.json")[0]) > 80
    cache.format_content = False
    cache.clear()
    lines, origin = cache.content(tree / "data.json")
    assert lines == [BLOB]
    assert origin is None


# --- engine + line numbers --------------------------------------------------


def test_matches_report_the_original_line_but_distinct_identities(tree):
    rs = _engine(tree, max_results=0).search(parse_query("admin"), Modes(), 1)
    hits = [r for r in rs.results if r.rel == "data.json"]
    assert len(hits) > 10, "the minified file should yield many separate matches"
    assert {r.line_no for r in hits} == {1}, "all on line 1 of the file as stored"
    assert len({r.view_line for r in hits}) == len(hits), "view positions differ"
    assert len({r.identity() for r in hits}) == len(hits), "identities must not collide"


def test_editor_and_export_use_the_original_line(tree):
    rs = _engine(tree).search(parse_query("admin"), Modes(), 1)
    hit = next(r for r in rs.results if r.rel == "data.json")
    assert hit.format_output(absolute=False) == "data.json:1"
    argv = actions.editor_argv(Config(), [hit])
    assert "+1" in argv or any(a.endswith(":1") for a in argv)


def test_formatting_off_gives_one_noisy_match_instead(tree):
    on = _engine(tree, max_results=0).search(parse_query("admin"), Modes(), 1)
    off = _engine(tree, max_results=0, format_content=False).search(
        parse_query("admin"), Modes(), 1
    )
    on_hits = [r for r in on.results if r.rel == "data.json"]
    off_hits = [r for r in off.results if r.rel == "data.json"]
    assert len(off_hits) == 1, "unformatted, the whole document is one line"
    assert len(on_hits) > len(off_hits)


def test_formatting_stops_a_nonsense_query_matching_the_long_line(tree):
    """The point of the feature: long lines match any subsequence."""
    q = parse_query("uinm")  # scattered chars, present in order in the raw blob
    off = _engine(tree, max_results=0, format_content=False).search(q, Modes(), 1)
    on = _engine(tree, max_results=0).search(q, Modes(), 1)
    off_content = [r for r in off.results if r.kind is MatchKind.CONTENT]
    on_content = [r for r in on.results if r.kind is MatchKind.CONTENT]
    assert off_content, "unformatted, the giant line matches this nonsense"
    assert len(on_content) < len(off_content) or not on_content


# --- narrowing over reformatted content -------------------------------------


def test_narrowing_over_a_reformatted_file_matches_a_full_rescan(tree):
    narrowing = _engine(tree)
    for i, q in enumerate(["adm", "admi", "admin"]):
        got = narrowing.search(parse_query(q), Modes(), i)
        want = _engine(tree).search(parse_query(q), Modes(), i)
        key = lambda rs: [  # noqa: E731
            (r.rel, r.line_no, r.view_line, r.score) for r in rs.results
        ]
        assert key(got) == key(want), f"narrowed result differs at {q!r}"
        assert got.total == want.total
