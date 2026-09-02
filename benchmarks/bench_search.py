"""Repeatable throughput benchmark for the search engine.

Run it against any tree::

    uv run python benchmarks/bench_search.py                     # default corpus
    uv run python benchmarks/bench_search.py ~/src/some-monorepo

Not collected by ``pytest`` (``testpaths = ["tests"]``): it is slow and needs a
corpus. It exists so the numbers in
``openspec/changes/search-performance/proposal.md`` stay reproducible and so
throughput regressions are visible.

Baseline on ``.venv/lib/python3.12/site-packages`` (1,170 text files,
368,618 lines), before and after the `search-performance` change:

                                        before      after
    names   'main'                      3.0 ms     0.6 ms
    content 'self'          warm       1055 ms     583 ms
    content 'asyncio'       warm        896 ms     458 ms
    content 'zzqqnotthere'  warm        773 ms     262 ms
    typing  ma -> ... -> main.p        4108 ms    1398 ms
      of which the last keystroke       786 ms     108 ms

Two rows carry the story. `zzqqnotthere` matches nothing, and used to cost as
much as a query matching everything, because every non-matching line was walked
character by character in Python; it is now rejected in C. And the typing
sequence used to cost the same for every keystroke — it now gets *cheaper* as
the query grows, because a query that only narrows is run against the previous
result set instead of the whole corpus.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from seek.config import Config
from seek.engine.engine import CandidateStore, Modes, SearchEngine
from seek.engine.query import parse_query
from seek.scope import build_scope
from seek.walk import walk

DEFAULT_CORPUS = Path(".venv/lib/python3.12/site-packages")

NAME_QUERIES = ["ma", "main", "test util", "^text", "widget$"]
CONTENT_QUERIES = ["'def ", "def", "self", "asyncio", "zzqqnotthere"]
TYPING = ["ma", "mai", "main", "main.p"]

NAMES = Modes(file=True, dir=True, content=False)
CONTENT = Modes(file=False, dir=False, content=True)
BOTH = Modes(True, True, True)


class Bench:
    def __init__(self, root: Path) -> None:
        self.cfg = Config(apply_noise_excludes=False)
        self.root = root
        self.store = CandidateStore()
        t0 = time.perf_counter()
        for cand in walk(root, self.cfg, build_scope([], regex=False)):
            self.store.add(cand)
        self.store.finish()
        self.walk_s = time.perf_counter() - t0
        self.engine = SearchEngine(self.cfg, self.store)
        self._gen = 0

    def run(self, query: str, modes: Modes) -> tuple[float, int]:
        self._gen += 1
        parsed = parse_query(query)
        t0 = time.perf_counter()
        rs = self.engine.search(parsed, modes, self._gen)
        return time.perf_counter() - t0, rs.total or len(rs.results)


def _row(label: str, secs: float, hits: int) -> None:
    print(f"  {label:<34}{secs * 1000:9.1f} ms  {hits:>9,} hits")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CORPUS
    if not root.is_dir():
        print(f"no such corpus: {root}", file=sys.stderr)
        return 1

    b = Bench(root)
    files = sum(0 if c.is_dir else 1 for c in b.store.snapshot())
    print(f"corpus {root}")
    print(f"walk   {len(b.store):,} candidates ({files:,} files) in {b.walk_s:.2f}s\n")

    print("names only (no I/O)")
    for q in NAME_QUERIES:
        _row(f"names {q!r}", *b.run(q, NAMES))

    print("\ncontent, cold cache (reads every file)")
    _row("content 'def ' cold", *b.run("'def ", CONTENT))

    print("\ncontent, warm cache")
    for q in CONTENT_QUERIES:
        _row(f"content {q!r}", *b.run(q, CONTENT))
    print(f"  cache holds {b.engine.cache.cached_bytes / 1e6:.0f} MB (accounted)")

    print("\nincremental typing (names + content)")
    total = 0.0
    for q in TYPING:
        secs, hits = b.run(q, BOTH)
        total += secs
        _row(f"typing {q!r}", secs, hits)
    print(f"  {'TOTAL keystroke latency':<34}{total * 1000:9.1f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
