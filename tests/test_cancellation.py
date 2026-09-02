"""A superseded search must stop promptly, even inside one enormous file."""

from __future__ import annotations

from seek.config import Config
from seek.engine import engine as engine_mod
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import parse_query
from seek.scope import build_scope
from seek.walk import walk

LINES = 40_000


def _engine(root, config):
    store = CandidateStore()
    for cand in walk(root, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    return SearchEngine(config, store)


def test_search_abandons_a_huge_file_partway(tmp_path, monkeypatch):
    (tmp_path / "huge.txt").write_text("needle here\n" * LINES)
    config = Config()
    eng = _engine(tmp_path, config)

    calls = {"n": 0}
    stale = {"v": False}
    real = engine_mod.match_score

    def counting(query, text):
        calls["n"] += 1
        if calls["n"] > 1_000:
            stale["v"] = True  # the query changed mid-file
        return real(query, text)

    monkeypatch.setattr(engine_mod, "match_score", counting)
    eng.search(parse_query("needle"), Modes(), 1, is_stale=lambda: stale["v"])

    # Without an in-file staleness check this would have scored all 40,000
    # lines before noticing.
    assert calls["n"] < LINES // 4, f"scanned {calls['n']} lines before stopping"


def test_uncancelled_search_still_scans_the_whole_file(tmp_path):
    (tmp_path / "huge.txt").write_text("needle here\n" * 5_000)
    eng = _engine(tmp_path, Config(max_results=0))
    rs = eng.search(parse_query("needle"), Modes(), 1)
    # every content line; "huge.txt" itself has no `n`, so no filename match
    assert rs.total == 5_000


def test_cancelled_search_reports_what_it_had(tmp_path):
    (tmp_path / "a.txt").write_text("needle\n" * 2_000)
    eng = _engine(tmp_path, Config())
    rs = eng.search(parse_query("needle"), Modes(), 7, is_stale=lambda: True)
    assert rs.generation == 7
    assert rs.total == 0  # stopped before scoring anything
