"""Progress snapshots are throttled by wall-clock time, not by hit count."""

from __future__ import annotations

import time

from seek.config import Config
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import parse_query
from seek.scope import build_scope
from seek.walk import walk


def _engine(root, **cfg) -> SearchEngine:
    config = Config(**cfg)
    store = CandidateStore()
    for cand in walk(root, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    return SearchEngine(config, store)


def _corpus(tmp_path, files=40, lines=200):
    for i in range(files):
        (tmp_path / f"f{i}.txt").write_text(f"needle line here {i}\n" * lines)
    return tmp_path


def _run(engine, publish=True):
    seen = []
    engine.search(
        parse_query("needle"), Modes(), 1,
        publish=(lambda snap, gen, total: seen.append(total)) if publish else None,
    )
    return seen


def test_a_long_interval_suppresses_intermediate_publishes(tmp_path):
    eng = _engine(_corpus(tmp_path), publish_interval_ms=60_000)
    assert _run(eng) == [], "no snapshot should fire inside the interval"


def test_zero_interval_publishes_every_batch(tmp_path):
    eng = _engine(_corpus(tmp_path), publish_interval_ms=0)
    seen = _run(eng)
    assert len(seen) > 5
    assert seen == sorted(seen), "reported totals must be non-decreasing"


def test_throttled_run_publishes_far_less_than_unthrottled(tmp_path):
    root = _corpus(tmp_path, files=60, lines=300)
    unthrottled = len(_run(_engine(root, publish_interval_ms=0)))
    throttled = len(_run(_engine(root, publish_interval_ms=200)))
    assert unthrottled > 10
    assert throttled < unthrottled


def test_interval_is_actually_honoured(tmp_path):
    """With a short interval, publishes are spaced by at least that interval."""
    eng = _engine(_corpus(tmp_path, files=80, lines=400), publish_interval_ms=50)
    stamps: list[float] = []
    eng.search(
        parse_query("needle"), Modes(), 1,
        publish=lambda snap, gen, total: stamps.append(time.monotonic()),
    )
    gaps = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    assert all(g >= 0.045 for g in gaps), f"publishes too close together: {gaps}"


def test_throttling_does_not_change_the_final_result(tmp_path):
    root = _corpus(tmp_path)
    fast = _engine(root, publish_interval_ms=0)
    slow = _engine(root, publish_interval_ms=60_000)
    a = fast.search(parse_query("needle"), Modes(), 1, publish=lambda *x: None)
    b = slow.search(parse_query("needle"), Modes(), 1, publish=lambda *x: None)
    assert a.total == b.total
    assert [(r.rel, r.line_no, r.score) for r in a.results] == [
        (r.rel, r.line_no, r.score) for r in b.results
    ]


def test_default_interval_is_configurable_and_sane():
    assert Config().publish_interval_ms == 500
    assert Config(publish_interval_ms=250).publish_interval_ms == 250
