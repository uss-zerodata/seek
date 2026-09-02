## Why

Content search costs roughly **one second per query** on a small tree, so the
interactive promise of the app breaks down on any real repository.

Measured against `.venv/lib/python3.12/site-packages` — 1,170 text files,
368,618 lines, which is 10–100× *smaller* than a working monorepo:

| query | current |
|---|---:|
| `self` (content) | 959 ms |
| `asyncio` (content) | 868 ms |
| `zzqqnotthere` — matches **nothing** | 783 ms |
| typing `ma` → `mai` → `main` | 3,155 ms total |

A query that matches nothing costs almost as much as one that matches
everything, which locates the problem precisely: the cost is in *rejecting*
lines, not in matching them. `cProfile` confirms it — `score._greedy`, a
pure-Python per-character loop, is 40% of total time (354,717 calls), and the
`len(hay)` re-evaluated inside its inner loop accounts for another 11.7 million
calls on its own. Every non-matching line is walked character by character in
Python before being discarded.

Prototypes of the fixes below were benchmarked head-to-head against the current
scorer on the same corpus, producing **identical hit counts**:

| query | current | with fast path | narrowing (typing) |
|---|---:|---:|---:|
| `self` | 819 ms | 458 ms (1.8×) | — |
| `asyncio` | 779 ms | 374 ms (2.1×) | — |
| `zzqqnotthere` | 726 ms | 101 ms (**7.2×**) | — |
| `widget handler` | 782 ms | 183 ms (**4.3×**) | — |
| `ma`→`mai`→`main`→`main.p` | 3,567 ms | — | 1,640 ms (**2.2×**) |

The two effects multiply, so realistic typing should improve by roughly 4–15×.

Profiling also surfaced hazards that are not about speed at all: a single large
file in the tree is read entirely into memory before it is even checked for
being binary, and cancellation cannot interrupt a file once started.

## What Changes

**Throughput (no observable change to results)**

- **Scorer fast path.** A per-term compiled regex (`m.*?a.*?i.*?n`) rejects
  non-matching lines in C before the Python `_greedy` loop runs; `len(hay)` is
  hoisted out of that loop; each line is lowercased once per line instead of
  once per term; the "score every substring occurrence" scan is bounded.
- **Content cache LRU becomes O(1).** `_touch` currently does `list.remove` +
  shift on every cache hit and `pop(0)` on eviction — quadratic in cached files
  (measured: 38 ms vs 7.6 ms per pass at 20,000 files, and it degrades from
  there).
- **Candidate snapshots stop copying.** Every search copies the entire candidate
  list; a length-bounded read replaces it.

**Bounded work (observable)**

- **Result accumulation is bounded by the result cap.** The engine currently
  appends *every* match to an unbounded list and caps only at the end; a broad
  query on a large repo materialises millions of `Result` objects. A
  cap-sized heap replaces it, and the pre-cap total is kept as a counter.
- **Match spans are computed only for returned results**, not for every match
  that is subsequently discarded.
- **Incremental narrowing.** When an edit can only make the query stricter, the
  next search runs over the previous result set instead of the whole corpus.
  Results SHALL be identical to a full rescan.

**Robustness (observable)**

- **A per-file content size cap** (`content_size_cap`, new config key). Files
  above it are searched up to the cap rather than read whole — today a
  multi-gigabyte log or database file in the tree is fully read, decoded and
  split into lines before anything else happens.
- **Binary detection reads a header chunk first**, instead of after reading the
  entire file.
- **Cancellation is checked within a file**, not only between files, so one huge
  file no longer blocks a superseded search from stopping.
- **The content-cache budget is accounted in bytes**, including per-line object
  overhead. It currently counts characters and ignores ~49 bytes of `str`
  overhead per line, so the "512 MB budget" can mean several GB of resident
  memory.
- **The cache lock is no longer held across disk I/O**, so overlapping search
  threads stop serialising on each other's file reads.

**Streaming and re-rooting (added after the first round of measurement)**

- **Progress snapshots are throttled by time, not hit count.** `CHUNK_SIZE = 300`
  fired 98 snapshots for a 41k-hit query — 28% of engine time, plus 98 full
  result-list rebuilds on the UI thread. A `publish_interval_ms` (default 500)
  replaces it: 1 snapshot, and 699 ms → 590 ms in the engine alone.
- **Changing root reuses the launch scan.** Files are treated as stable for the
  session, so re-rooting and popping a breadcrumb filter the completed scan
  instead of walking again. Popping back to the launch root cost a full re-walk
  — ~3.1 s on a 500k-candidate tree — for files already walked this run. Manual
  refresh stays the explicit escape hatch.

**Tooling**

- A repeatable benchmark harness in the repo so these numbers stay measurable
  and regressions are visible.

## Capabilities

### New Capabilities
<!-- none: this change makes existing capabilities faster and bounds their work -->

### Modified Capabilities
- `fuzzy-search-engine`: result accumulation becomes bounded by the result cap
  rather than unbounded; match spans are guaranteed only for returned results;
  binary detection is defined on a header chunk read without loading the whole
  file; the content-cache budget is defined in bytes including object overhead;
  plus new requirements for a per-file content read cap, bounded cancellation
  latency, and incremental narrowing that must agree with a full rescan.
- `configuration`: the overridable-settings list gains the per-file content
  search size cap and the minimum interval between streamed partial-result
  updates.
- `interactive-tui`: re-rooting and popping a breadcrumb are derived from the
  completed launch scan rather than re-walking, with a defined fallback to a
  real walk; manual refresh is defined as always bypassing the cached scan.

## Impact

- Code: `src/seek/engine/score.py` (fast path — public `score` / `match_spans`
  interface preserved), `src/seek/engine/engine.py` (bounded heap, narrowing,
  cancellation granularity, snapshot), `src/seek/engine/content.py` (O(1) LRU,
  size cap, header-first sniff, byte accounting, lock scope),
  `src/seek/config.py` (`content_size_cap`).
- Config: one new key; `config.example.toml` must be regenerated.
- Tests: existing engine/scorer tests must pass unchanged — the optimisations
  are required to produce identical results. New tests cover the bounded
  accumulation, the narrowing equivalence, and the size cap.
- Benchmark harness (dev-only; no new runtime dependency).
- No CLI flag changes. No TUI changes.
