"""Search orchestrator: name index + content search, modes, staleness."""

from __future__ import annotations

import heapq
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from itertools import islice
from time import monotonic

from seek.config import Config
from seek.engine.content import ContentCache
from seek.engine.query import ParsedQuery, can_narrow
from seek.engine.score import match_score, match_spans
from seek.models import Candidate, MatchKind, Result, ResultSet, ResultSetState

StaleCheck = Callable[[], bool]
Publish = Callable[[list["Result"], int, int], None]

# Progress snapshots are throttled by wall-clock time, not by hit count: a
# terminal cannot usefully show more than a couple of updates a second, and each
# one costs a ranked snapshot here plus a full result-list rebuild on the UI
# thread. See `Config.publish_interval_ms`.

# Check `is_stale()` every this many lines *within* a file, so a single huge
# file cannot hold a superseded search open until it finishes.
_STALE_EVERY = 512

# Largest number of matching content lines worth remembering for narrowing the
# next query. Above this the pool is dropped rather than allowed to grow with
# the match count.
_POOL_MAX = 200_000

# Heap entries are `(score, -seq, result)`. The negated sequence number makes
# the *latest* insertion the smallest element among equal scores, so it is the
# one evicted when the heap is full - which is what `heapq.nlargest` does, and
# what the previous implementation therefore did.
_HeapEntry = tuple[int, int, Result]


def _admits(heap: list[_HeapEntry], cap: int, s: int) -> bool:
    """Could a result scoring ``s`` still make the cut? If not, do not build it."""
    return cap <= 0 or len(heap) < cap or s > heap[0][0]


def _push(heap: list[_HeapEntry], cap: int, entry: _HeapEntry) -> None:
    if cap > 0 and len(heap) >= cap:
        heapq.heapreplace(heap, entry)
    else:
        heapq.heappush(heap, entry)


def _ranked(heap: list[_HeapEntry], query: ParsedQuery) -> list[Result]:
    """Drain the heap best-first and fill in the spans of the survivors.

    Called once per streamed snapshot as well as at the end, and the heap keeps
    the same `Result` objects across all of them - so a result that survived
    several publishes had its spans recomputed on each one, to the same answer.
    A `Result` is built by one search and never outlives it, so spans already
    filled in are spans for this query.
    """
    out = [entry[2] for entry in sorted(heap, key=lambda e: (e[0], e[1]), reverse=True)]
    for r in out:
        if r.spans:
            continue
        # Name results were scored against the basename, content results
        # against the matched line; span offsets are relative to that same text.
        text = r.line_text if r.kind is MatchKind.CONTENT else r.rel.rsplit("/", 1)[-1]
        m = match_spans(query, text or "")
        if m is not None:
            r.spans = m[1]
    return out


@dataclass(slots=True, frozen=True)
class Modes:
    file: bool = True
    dir: bool = True
    content: bool = True

    @classmethod
    def resolve(cls, flags: tuple[bool, bool, bool]) -> Modes:
        f, d, c = flags
        if not (f or d or c):
            return cls(True, True, True)
        return cls(f, d, c)

    def toggled(self, which: str) -> Modes:
        return replace(self, **{which: not getattr(self, which)})


class CandidateStore:
    """Thread-safe growing list of walked candidates."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[Candidate] = []
        self.scanning = True
        # Bumped on clear() so anything derived from the old contents (the
        # engine's narrowing pool) can tell that it is stale.
        self.epoch = 0

    def add(self, cand: Candidate, epoch: int | None = None) -> None:
        """Append a candidate, unless the store has moved on since ``epoch``.

        A walk that is being torn down can be between its own stop check and
        this call when the store is cleared for a new root; without the guard
        its next candidate - relative to the old root - lands in the new set.
        The check has to happen under the same lock as the append.
        """
        with self._lock:
            if epoch is not None and epoch != self.epoch:
                return
            self._items.append(cand)

    def snapshot(self) -> list[Candidate]:
        with self._lock:
            return list(self._items)

    def view(self) -> tuple[list[Candidate], int]:
        """The backing list plus a count that is safe to iterate up to.

        Avoids copying every candidate on every search. `_items` is append-only
        within a generation, so entries below the returned bound never move, and
        under CPython each `list.__getitem__` is atomic with respect to a
        concurrent `append` - a reader can never observe a torn element. Iterate
        it with `islice(items, n)`; do not hold on to the list.
        """
        with self._lock:
            return self._items, len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self.epoch += 1
        self.scanning = True

    def finish(self) -> None:
        self.scanning = False

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


@dataclass(slots=True)
class _Pool:
    """The previous query's matches, reusable when the next query only narrows.

    ``contents`` is ``None`` when the previous query matched more content lines
    than `_POOL_MAX`; keeping every one of them would undo the bounded-memory
    property of the result heap, so a very broad query simply forfeits
    narrowing for the next keystroke.
    """

    query: ParsedQuery
    modes: Modes
    epoch: int
    n_items: int
    names: list[Candidate]
    contents: list[tuple[Candidate, list[int]]] | None


class SearchEngine:
    def __init__(self, config: Config, store: CandidateStore) -> None:
        self.config = config
        self.store = store
        self.cache = ContentCache(
            config.content_cache_budget, config.content_size_cap, config
        )
        self._pool: _Pool | None = None

    def search(
        self,
        query: ParsedQuery,
        modes: Modes,
        generation: int,
        *,
        is_stale: StaleCheck = lambda: False,
        publish: Publish | None = None,
    ) -> ResultSet:
        if query.is_empty:
            return ResultSet(ResultSetState.EMPTY_QUERY, [], generation, self.store.scanning)

        cap = self.config.max_results
        items, n_items = self.store.view()
        pool = self._usable_pool(query, modes, n_items)
        # Results are kept in a heap bounded by `cap`, so peak memory is set by
        # the cap rather than by how many lines happen to match. `total` counts
        # every match, including the ones the heap never keeps.
        heap: list[_HeapEntry] = []
        seq = 0
        total = 0
        # Rebuilt as we go, to narrow the *next* query against.
        next_names: list[Candidate] = []
        next_contents: list[tuple[Candidate, list[int]]] | None = []
        content_matches = 0

        def snapshot(complete: bool) -> ResultSet:
            if not complete:
                self._pool = None  # a partial scan must never seed a pool
            return ResultSet(
                ResultSetState.RESULTS, _ranked(heap, query), generation,
                self.store.scanning, total=total,
            )

        # --- names & directories ---------------------------------------------
        # Narrowing: `pool.names` already satisfies the previous query, and the
        # new query implies it, so nothing outside the pool can match.
        name_source = pool.names if pool is not None else islice(items, n_items)
        for i, cand in enumerate(name_source):
            if not (i % _STALE_EVERY) and is_stale():
                return snapshot(complete=False)
            if cand.is_dir and not modes.dir:
                continue
            if not cand.is_dir and not modes.file:
                continue
            s = match_score(query, cand.name)
            if s is None:
                continue
            next_names.append(cand)
            total += 1
            if not _admits(heap, cap, s):
                continue
            _push(heap, cap, (s, -seq, Result(
                kind=MatchKind.DIRNAME if cand.is_dir else MatchKind.FILENAME,
                path=cand.path,
                rel=cand.rel,
                score=s,
            )))
            seq += 1

        # --- contents ------------------------------------------------------
        if modes.content and query.content_query_len >= self.config.min_content_query:
            since_publish = 0
            publish_interval = self.config.publish_interval_ms / 1000
            last_publish = monotonic()
            use_pool = pool is not None and pool.contents is not None
            source = pool.contents if use_pool else islice(items, n_items)
            for item in source:
                if is_stale():
                    return snapshot(complete=False)
                cand, want = item if use_pool else (item, None)
                if want is None and cand.is_dir:
                    continue
                got = self.cache.content(cand.path)
                if got is None:
                    continue
                lines, origin = got
                # A content line must satisfy every positive term (AND) and no
                # negatives.
                numbered = (
                    ((ln, lines[ln - 1]) for ln in want if ln <= len(lines))
                    if want is not None
                    else enumerate(lines, start=1)
                )
                kept: list[int] = []
                for line_no, line in numbered:
                    if not (line_no % _STALE_EVERY) and is_stale():
                        return snapshot(complete=False)
                    s = match_score(query, line)
                    if s is None:
                        continue
                    kept.append(line_no)
                    total += 1
                    content_matches += 1
                    since_publish += 1
                    if not _admits(heap, cap, s):
                        continue
                    _push(heap, cap, (s, -seq, Result(
                        kind=MatchKind.CONTENT,
                        path=cand.path,
                        rel=cand.rel,
                        score=s,
                        # `line_no` is the line in the file as stored; `line_no`
                        # here indexes the *indexed* text, so map it back.
                        line_no=origin[line_no - 1] if origin else line_no,
                        line_text=line,
                        view_line=line_no,
                    )))
                    seq += 1
                if kept and next_contents is not None:
                    next_contents.append((cand, kept))
                if next_contents is not None and content_matches > _POOL_MAX:
                    next_contents = None  # too broad to remember; forfeit narrowing
                if publish and since_publish:
                    now = monotonic()
                    if now - last_publish >= publish_interval:
                        since_publish = 0
                        last_publish = now
                        publish(_ranked(heap, query), generation, total)
        else:
            next_contents = None

        self._pool = _Pool(
            query=query, modes=modes, epoch=self.store.epoch, n_items=n_items,
            names=next_names, contents=next_contents,
        )
        state = ResultSetState.RESULTS if heap else ResultSetState.NO_MATCH
        return ResultSet(
            state, _ranked(heap, query), generation, self.store.scanning,
            total=total,
        )

    def _usable_pool(
        self, query: ParsedQuery, modes: Modes, n_items: int
    ) -> _Pool | None:
        """The previous search's matches, if this query can safely reuse them.

        Narrowing is off while the walk is running: new candidates arriving
        after the pool was built would never be considered.
        """
        pool = self._pool
        if pool is None or self.store.scanning:
            return None
        if pool.epoch != self.store.epoch or pool.n_items != n_items:
            return None
        if pool.modes != modes:
            return None
        if not can_narrow(pool.query, query):
            return None
        return pool

    def invalidate_content(self) -> None:
        """Drop everything derived from the contents of files on disk.

        The content cache is keyed on path alone - it has no mtime check - and
        the narrowing pool holds line positions into the text that cache
        returned. Anything that admits the files may have changed underneath
        (the manual refresh) or that changes how they are indexed (the
        formatting toggle) has to drop both, together.
        """
        self.cache.clear()
        self._pool = None

