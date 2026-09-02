from pathlib import Path

from seek.config import Config
from seek.engine.content import ContentCache
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import parse_query
from seek.models import Candidate, MatchKind, ResultSetState
from seek.scope import build_scope
from seek.walk import walk


def _engine(tree: Path, config: Config | None = None) -> SearchEngine:
    config = config or Config()
    store = CandidateStore()
    for cand in walk(tree, config, build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    return SearchEngine(config, store)


def test_modes_resolve():
    assert Modes.resolve((False, False, False)) == Modes(True, True, True)
    assert Modes.resolve((True, False, False)) == Modes(True, False, False)


def test_name_and_content_are_separate_results(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query("main"), Modes(), 1)
    kinds = {(r.kind, r.rel) for r in rs.results}
    assert (MatchKind.FILENAME, "src/main.py") in kinds
    assert any(k is MatchKind.CONTENT and rel == "src/main.py" for k, rel in kinds)


def test_content_disabled_no_content_results(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query("hello"), Modes(file=True, dir=True, content=False), 1)
    assert all(r.kind is not MatchKind.CONTENT for r in rs.results)


def test_min_content_query_gate(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query("m"), Modes(), 1)
    assert all(r.kind is not MatchKind.CONTENT for r in rs.results)


def test_empty_query_state(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query(""), Modes(), 1)
    assert rs.state is ResultSetState.EMPTY_QUERY
    assert rs.results == []


def test_no_match_state(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query("zzzznotpresent"), Modes(), 1)
    assert rs.state is ResultSetState.NO_MATCH


def test_one_row_per_matching_line(tmp_path):
    f = tmp_path / "many.txt"
    f.write_text("\n".join(["needle here"] * 40) + "\n")
    store = CandidateStore()
    store.add(Candidate(path=f, is_dir=False, rel="many.txt"))
    store.finish()
    eng = SearchEngine(Config(), store)
    rs = eng.search(parse_query("needle"), Modes(), 1)
    content = [r for r in rs.results if r.kind is MatchKind.CONTENT]
    assert len(content) == 40
    assert {r.line_no for r in content} == set(range(1, 41))


def test_binary_skipped_for_content(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query("main"), Modes(), 1)
    assert not any(
        r.kind is MatchKind.CONTENT and r.rel == "data.bin" for r in rs.results
    )
    # Asserted through the path production actually takes: the cache sniffs
    # the header itself and never reads the body of a binary.
    assert eng.cache.content(tree / "data.bin") is None


def test_stale_generation_discarded(tree):
    eng = _engine(tree)
    rs = eng.search(parse_query("main"), Modes(), 5, is_stale=lambda: True)
    assert rs.results == []


def test_scope_restricts_candidates(tree):
    config = Config()
    store = CandidateStore()
    for cand in walk(tree, config, build_scope(["src/**"], regex=False)):
        store.add(cand)
    store.finish()
    eng = SearchEngine(config, store)
    rs = eng.search(parse_query("main"), Modes(), 1)
    assert all(r.rel.startswith("src/") for r in rs.results)


def test_content_cache_overflow_still_correct(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text(f"alpha line {i}\n" * 20)
    store = CandidateStore()
    for cand in walk(tmp_path, Config(), build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    eng = SearchEngine(Config(content_cache_budget=50), store)  # tiny budget
    rs = eng.search(parse_query("alpha"), Modes(), 1)
    hit_files = {r.rel for r in rs.results if r.kind is MatchKind.CONTENT}
    assert hit_files == {f"f{i}.txt" for i in range(5)}
    assert eng.cache.cached_bytes <= 50


def test_result_cap_and_total(tmp_path):
    for i in range(50):
        (tmp_path / f"match_{i}.py").write_text("x\n")
    store = CandidateStore()
    for cand in walk(tmp_path, Config(), build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    eng = SearchEngine(Config(max_results=10), store)
    rs = eng.search(parse_query("match"), Modes(), 1)
    assert len(rs.results) == 10
    assert rs.total == 50
    # still the 10 best by score, sorted
    assert [r.score for r in rs.results] == sorted(
        (r.score for r in rs.results), reverse=True
    )


def test_progressive_publish(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("needle\n" * 100)
    store = CandidateStore()
    for cand in walk(tmp_path, Config(), build_scope([], regex=False)):
        store.add(cand)
    store.finish()
    # publish_interval_ms=0 disables the time throttle, so every batch reports
    eng = SearchEngine(Config(publish_interval_ms=0), store)
    snapshots = []
    eng.search(
        parse_query("needle"), Modes(), 1,
        publish=lambda snap, gen, total: snapshots.append((len(snap), total)),
    )
    assert snapshots  # progress was reported at least once
    assert all(gen_total >= shown for shown, gen_total in snapshots)


def test_cache_reads_once(tmp_path, monkeypatch):
    f = tmp_path / "a.txt"
    f.write_text("target\n")
    cache = ContentCache(1_000_000)
    calls = {"n": 0}
    real = Path.open

    # The cache reads header-first through Path.open (so a large binary costs
    # only a header read), not Path.read_bytes.
    def counting(self, *args, **kwargs):
        calls["n"] += 1
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counting)
    cache.lines(f)
    cache.lines(f)
    cache.lines(f)
    assert calls["n"] == 1
