"""ContentCache invariants: O(1) bookkeeping and a budget that means bytes."""

from __future__ import annotations

import sys
import time

from seek.engine.content import _STR_OVERHEAD, ContentCache


def _make_files(tmp_path, count: int, lines_each: int = 4):
    paths = []
    for i in range(count):
        p = tmp_path / f"f{i}.txt"
        p.write_text("".join(f"line {j} of file {i}\n" for j in range(lines_each)))
        paths.append(p)
    return paths


def test_budget_counts_object_overhead_not_just_characters(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("ab\ncd\n")  # 2 lines, 2 characters each
    cache = ContentCache(1_000_000)
    cache.lines(p)
    # characters alone would be 4; the real cost includes the str headers
    assert cache.cached_bytes == 2 * (2 + _STR_OVERHEAD)
    assert cache.cached_bytes >= 2 * sys.getsizeof("")


def test_budget_bounds_retained_bytes(tmp_path):
    paths = _make_files(tmp_path, 40)
    budget = 4_000
    cache = ContentCache(budget)
    for p in paths:
        cache.lines(p)
    assert 0 < cache.cached_bytes <= budget


def test_evicted_file_is_still_searchable(tmp_path):
    paths = _make_files(tmp_path, 20)
    cache = ContentCache(500)  # forces heavy eviction
    for p in paths:
        assert cache.lines(p) is not None
    # every file still returns correct content, cached or not
    for i, p in enumerate(paths):
        assert cache.lines(p)[0] == f"line 0 of file {i}"


def test_lru_keeps_the_most_recently_used(tmp_path):
    paths = _make_files(tmp_path, 3)
    one_file = _STR_OVERHEAD * 4 + 100
    cache = ContentCache(one_file * 2)
    cache.lines(paths[0])
    cache.lines(paths[1])
    cache.lines(paths[0])  # touch 0 so 1 becomes the eviction victim
    cache.lines(paths[2])
    assert paths[0] in cache._data
    assert paths[2] in cache._data


def test_binary_file_is_remembered_and_not_re_read(tmp_path, monkeypatch):
    from pathlib import Path

    p = tmp_path / "blob.bin"
    p.write_bytes(b"abc\x00def")
    cache = ContentCache(1_000_000)
    assert cache.lines(p) is None

    calls = {"n": 0}
    real = Path.read_bytes

    def counting(self):
        calls["n"] += 1
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", counting)
    assert cache.lines(p) is None
    assert calls["n"] == 0  # the negative result was cached


def test_cache_hit_cost_does_not_grow_with_cache_size(tmp_path):
    """The old list-based LRU made every hit O(n); this pins it to O(1)."""

    def hit_time(count: int) -> float:
        paths = _make_files(tmp_path / f"n{count}", count)
        cache = ContentCache(1_000_000_000)
        for p in paths:
            cache.lines(p)
        t0 = time.perf_counter()
        for _ in range(3):
            for p in paths:
                cache.lines(p)
        return (time.perf_counter() - t0) / (3 * count)

    (tmp_path / "n200").mkdir()
    (tmp_path / "n2000").mkdir()
    small = hit_time(200)
    large = hit_time(2000)
    # 10x the cache must not cost anywhere near 10x per hit. The old
    # implementation scaled linearly; allow generous slack for timing noise.
    assert large < small * 4, f"per-hit cost grew: {small:.3e} -> {large:.3e}"
