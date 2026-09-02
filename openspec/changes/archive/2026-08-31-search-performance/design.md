## Context

See `proposal.md` — Why, for the measurements. Constraints that shape the
approach:

- `score.py` documents a deliberately stable public interface — `score(term_text,
  text, *, case_sensitive)` and `match_spans(parsed_query, text)` — "kept stable
  so the scorer can be swapped". Preserve it; the fast path goes underneath.
- `engine.search()` is the only caller that matters for throughput. It runs on a
  worker thread and cooperates with cancellation through the `is_stale` callback
  and a monotonically increasing generation counter.
- Overlapping (cancelled-but-still-running) search threads are expected by
  design, which is why `ContentCache` holds a lock at all.
- Runtime dependencies are deliberately minimal. Everything here uses the
  standard library (`re`, `heapq`, `collections`).
- The existing engine and scorer tests encode the current ranking behaviour.
  They must keep passing untouched: this change is not allowed to alter which
  results come back or in what order.

## Goals / Non-Goals

**Goals:**

- Cut the cost of *rejecting* a line, which is where the time actually goes.
- Bound peak memory by the result cap rather than by the number of matches.
- Make repeated typing cheaper than repeated cold searches.
- Keep results bit-identical to today's, and prove it with an equivalence test
  rather than asserting it.

**Non-Goals:**

- No new runtime dependency, and no native/compiled extension.
- No multi-process or multi-threaded content scanning. The scoring work is
  pure-Python and GIL-bound; parallelism belongs to a later change, if ever.
- No inverted index or persisted cache across sessions.
- No change to the scoring model — the same weights, the same ranking.
- Not tuning `min_content_query`; gating policy is out of scope.

## Decisions

### 1. Subsequence pre-filter in front of `_greedy` — **not** a regex

`score()` already tries `hay.find(needle)` first, which is C-speed. The problem
is the fallback: when there is no substring occurrence, every line enters
`_greedy`, a Python `while` loop over characters, and a line that does not match
at all is walked to its end before returning `None`.

**Corrected during implementation.** This decision originally specified a
compiled lazy regex (`m.*?a.*?i.*?n`, `re.DOTALL`) and asserted that a chain of
literals and `.*?` "has no nested quantifiers, so there is no
catastrophic-backtracking risk". **That was wrong.** When the needle's characters
are common, a failing match makes the engine retry from every candidate position
for every literal, and the cost explodes: the needle `main.p` did not finish at
all over the 368k-line corpus (the benchmark had to be killed), while
`zzqqnotthere` was fine because `z` is rare. The prototype that produced the
original 1.8–7.2× figures only ever used rare-character needles, which is why it
never hit the case.

Two safe alternatives were then measured over the same corpus (pre-filter only,
368,618 lines):

| needle | lazy regex | possessive regex | iterator | iterator + first-char gate |
|---|---:|---:|---:|---:|
| `main.p` | *never finished* | 2,676 ms | 306 ms | **161 ms** |
| `self` | 273 ms | 471 ms | 298 ms | **223 ms** |
| `asyncio` | 320 ms | 557 ms | 321 ms | **235 ms** |
| `zzqqnotthere` | 40 ms | 425 ms | 306 ms | **45 ms** |
| `widget` | — | — | 302 ms | **97 ms** |

Possessive quantifiers (`[^m]*+m…`, available since 3.11) do fix the
backtracking but are slower than plain Python-level iteration everywhere.

The chosen primitive is `query.fuzzy_ok(needle, hay)`: reject outright when
`needle[0] not in hay` (one C scan that discards most lines), then test the
subsequence with `all(c in it for c in needle)` over a *shared* string iterator,
which advances in C and makes a single pass over `hay`. It is uniformly fast,
strictly linear, and has no pathological input.

The irony worth recording: `query.py` already had this exact primitive as the
private `_fuzzy_ok`, used by `Term.matches` for negation gating. It was simply
never used on the scorer's reject path. It is now shared by both.

Alternative also considered: an all-characters-present set check
(`set(needle) <= set(hay)`). Rejected — it still costs a Python-level pass to
build the set and is a weaker filter than an ordered subsequence test.

### 2. Hoist `len(hay)` out of `_greedy`'s inner loop

`while h < len(hay)` re-evaluates `len` on every character. The profile counted
**11,690,374** `len` calls at 0.677 s. Bind it to a local once. Two-line change,
and it still matters after decision 1 because `_greedy` remains the path for
lines that *do* match.

### 3. Lowercase once per line, not once per term

`score()` and `_term_score()` each compute `text.lower()` themselves, so an
N-term query lowercases every line N times (the profile shows 737,236 `lower`
calls for a one-term query — two per line, from `score()` and the `EXACT` path).
Thread an optional pre-lowered `hay` through the internal helpers;
`match_spans` computes it once and passes it down. The public signatures stay
as they are.

### 4. Rejected: caching lowercased lines in `ContentCache`

This looked like the obvious next step and the measurement killed it.
Lowercasing the entire 368,618-line corpus costs **24 ms**, and a pre-filter pass
over pre-lowered lines was 252 ms against 260 ms for lowercasing inline — a 3%
gain for double the cache memory. Not worth it. Recorded here so it is not
re-proposed.

### 5. Bound the substring-occurrence scan

`score()` walks *every* occurrence of the needle with repeated `hay.find(needle,
start+1)`, building a `list(range(...))` and scoring each one. On a long or
repetitive line this is quadratic in occurrences for no ranking benefit. Keep
the first occurrence plus occurrences at word boundaries, and stop after a small
fixed number. Ranking is unaffected in practice because the best-placed
occurrence is almost always the first or a boundary one — this must be covered
by the equivalence test (decision 11), and if it perturbs any ranking the bound
is raised rather than the behaviour accepted.

### 6. Bounded result accumulation via a cap-sized heap

`engine.search` appends every match to `results` and calls `_top(results, cap)`
at the end. Replace with a `heapq` min-heap of at most `config.max_results`
entries, plus an integer `total` counter, so peak memory is bounded by the cap.

Entries are `(score, seq, result)` with a monotonically increasing `seq` as
tie-breaker, which keeps ordering deterministic and stable — `heapq` needs a
total order and `Result` is not comparable. Final output is
`sorted(heap, reverse=True)` on the same key, matching what `heapq.nlargest`
produces today.

The real win is the guard: once the heap is full, compare the candidate score
against `heap[0][0]` *before* constructing the `Result` at all. Building 41,211
`Result` objects measured 75 ms; on a large repo a broad query builds millions.

### 7. Defer span computation past the cap

`match_spans` builds a set and `sorted()`s it for every match, but only up to
`max_results` are ever returned and the preview recomputes spans for the visible
window anyway (`preview.py` calls `match_spans` per displayed line).

Split scoring from span extraction: the scan computes a score only; spans are
computed for the survivors after capping. The `Result.spans` contract is
unchanged for everything the engine returns — see the spec's "Spans survive
capping" scenario.

### 8. Incremental narrowing — the soundness rule

Keep the previous query's raw text and its matched candidates (names) and matched
lines (content) alongside the generation that produced them. On the next search,
reuse that set as the candidate pool if **all** of:

- the new raw query starts with the old raw query (a pure append — no deletion,
  no mid-string edit), and
- the old query's final term is not negated (extending `!foo` to `!foobar`
  excludes *fewer* candidates, so it widens), and
- the modes and the search root are unchanged (a mode toggle or re-root
  invalidates the pool), and
- the walk has not added candidates since — otherwise new candidates would never
  be considered.

Appending to a fuzzy or exact term narrows (a subsequence of a subsequence is
still a subsequence, and a longer substring is a stricter test); appending a
space starts a new AND term, which also narrows. That covers ordinary typing,
which is the case that matters. Anything else falls back to a full rescan.

Measured on `ma`→`mai`→`main`→`main.p`: 3,567 ms → 1,640 ms, and per-keystroke
latency falls as the query gets longer (932 ms → 266 ms for `main`) instead of
staying flat.

The last condition is why the pool is invalidated during the walk: while
`store.scanning` is true, narrowing is disabled and every search is a full pass.
That is acceptable because the walk is the short-lived phase.

### 9. Content size cap, header-first sniff, and the cache

`ContentCache._read` does `path.read_bytes()` and *then* checks for NUL bytes, so
a large binary is read in full before being rejected. Restructure to: open, read
one `_SNIFF_BYTES` header, reject if binary, then read up to
`config.content_size_cap` more.

Truncating at a byte cap can split a line and can split a UTF-8 sequence. Decode
with `errors="replace"` as today, and drop the final partial line when the read
hit the cap, so no half-line is ever reported as a match.

The cap is a new `Config` field defaulting to 5 MB (matching `preview_size_cap`),
which means `config.example.toml` must be regenerated.

### 10. `ContentCache` bookkeeping

Three separate fixes in one file:

- **O(1) LRU.** `_touch` does `self._order.remove(path)` — a linear scan plus a
  shift — on every cache hit, and `_insert` evicts with `pop(0)`. Measured over a
  full pass: 20,000 files takes 38 ms versus 7.6 ms with `OrderedDict.move_to_end`,
  and the gap widens quadratically. Replace `_data` + `_order` with a single
  `OrderedDict`.
- **Byte accounting.** `sum(len(line) for line in lines) + len(lines)` counts
  *characters* and ignores the ~49 bytes of `str` object overhead per line, so a
  512 MB budget can retain several GB. Account
  `sum(len(line) + _STR_OVERHEAD for line in lines)`, or use
  `sys.getsizeof`-derived constants.
- **Lock scope.** `lines()` holds `self._lock` across `self._read()`, i.e. across
  disk I/O, so overlapping search threads serialise on each other. Read outside
  the lock and take the lock only for the dict bookkeeping, accepting that two
  threads may occasionally read the same file concurrently (idempotent, and
  cheaper than blocking).

### 11. Equivalence test as the safety net

The optimisations must not change results. Add a test that runs both the current
and the optimised path over a generated corpus and asserts identical
`(score, spans)` for every line, across fuzzy / exact / prefix / suffix / equal /
negated terms and multi-term queries. Keep the current scorer available as a
reference implementation for the duration of the change (a private
`_reference_score`), then delete it once the test has served its purpose — or
keep it, since it is small and makes future scorer changes safe.

Narrowing gets its own equivalence test: for a sequence of edits, the narrowed
result must equal the full-rescan result exactly.

### 12. Benchmark harness

A `benchmarks/` script (not collected by the default `pytest` run — it is slow
and needs a corpus) that walks a given tree, times the name pass, the cold and
warm content passes, and an incremental typing sequence, and prints a table.
Default corpus is a path argument so it can be pointed at a real repository.
This is what produced the numbers in the proposal; landing it keeps them
reproducible.

### 13. Candidate snapshot without copying

`CandidateStore.snapshot()` returns `list(self._items)` — a full copy of every
candidate on every search. Replace with reading `len(self._items)` under the lock
and indexing up to that bound. Appends beyond the bound cannot affect earlier
indices, and each `list.__getitem__` is atomic under the GIL, so no torn read is
possible. This is a CPython-specific guarantee and must be commented as such.

## Risks / Trade-offs

- **An optimisation silently changes ranking** → the equivalence test (decision
  11) compares against the current scorer over a generated corpus before the old
  path is removed. Decision 5 (bounded occurrence scan) is the one most likely to
  trip it; if it does, raise the bound rather than accept the change.
- **Narrowing returns a stale, too-small result set** → the soundness rule is
  deliberately conservative (pure append, no negation, no mode/root change, walk
  finished), everything else falls back to a full rescan, and an equivalence test
  covers edit sequences. The failure mode is silent missing results, so the
  conservative default matters more than the extra speed.
- **The content size cap changes results for very large files** → it only affects
  files that today risk stalling or OOM-ing the session; it is configurable, and
  the truncation drops the partial final line so nothing malformed is reported.
- **Unlocked reads let two threads read the same file at once** → wasted I/O in a
  rare race, versus blocking every overlapping search on one slow read. The
  cheaper failure is the right one.
- **Byte accounting will shrink the effective cache** at the same configured
  budget, so some sessions will re-read more files from disk. That is the budget
  being honoured rather than a regression, but it should be called out in the
  change notes.

### 10. Progress snapshots throttled by time, not hit count

`CHUNK_SIZE = 300` ties snapshot frequency to how fast matches are found, which
is exactly backwards: a broad query — the one already doing the most work — also
pays the most snapshot overhead. Measured on the 368k-line corpus for a 41k-hit
query: 98 snapshots, +151 ms (28% of engine time) with a *no-op* callback. In
the TUI each one also crosses `call_from_thread` into a full `ResultsList`
rebuild of up to 500 Rich-rendered rows on the main thread, which is the larger
hidden cost and the source of streaming jank.

Replace it with a `monotonic()` interval (`Config.publish_interval_ms`, default
500 ms), publishing only when new matches have arrived since the last snapshot.
A terminal cannot usefully show more than a couple of updates a second, and the
streaming spinner already signals liveness, so a search shorter than the
interval reports nothing intermediate at all — which is the desired outcome, not
a regression. `0` disables the throttle (used by tests).

Measured: 966 snapshots / 1,860 ms unthrottled → 1 snapshot / 590 ms at 500 ms,
against 98 / 699 ms for the old hit-count trigger.

### 11. Changing root reuses the launch scan

`_reset_for_new_root` called `store.clear()` and re-walked. Re-rooting into a
subdirectory re-walked files the launch scan had already visited; popping a
breadcrumb back to the launch root re-walked *the entire tree*. At the measured
6.3 µs/candidate that is ~3.1 s on a 500k-candidate tree, and far worse on a
network mount where the cost is syscalls rather than microseconds.

Treating the filesystem as stable for the session makes both a filter:
`walk.rebase(candidates, rel_root)` re-expresses the completed scan as if it had
started elsewhere, and `SeekApp._reuse_walk()` repopulates the store from it.
`store.clear()` still bumps the epoch, so the engine's narrowing pool is dropped
— the pool is keyed to a candidate set, not to a root.

Falls back to a real walk when the launch scan never completed, when the new
root is outside it, or when a **positional scope is active**: `scope.accepts`
was evaluated against launch-root-relative paths during the walk, so those
decisions do not carry over to a different root. Manual refresh discards the
cached scan first and always hits the filesystem — the explicit escape hatch
from the stability assumption.

Rejected alternative, measured: an **on-disk temp cache** of file contents. The
cost of re-reading a file is not the read, it is rebuilding Python `str`
objects — `read()` 48 ms vs `decode()` 33 ms + `splitlines()` 76 ms over the
corpus. A temp file repays the 109 ms anyway, the OS page cache already covers
the 48 ms, and the in-memory `ContentCache` already spans the whole session.
Also rejected: a **per-file character-set index** (the only index shape that can
serve *fuzzy* queries) — it skips only 6–12% of files for realistic queries
because source files contain nearly every letter; and a **trigram index**, which
cannot serve subsequence queries at all (`aio` matches `asyncio` but shares no
trigram with it).

## Outcome (measured after implementation)

Same corpus (1,170 text files, 368,618 lines), full suite green throughout and
`test_score_equivalence` asserting the scorer's results never changed:

| | before | after |
|---|---:|---:|
| names `main` | 3.0 ms | 0.6 ms |
| content `self` | 1,055 ms | 583 ms |
| content `asyncio` | 896 ms | 458 ms |
| content `zzqqnotthere` (no match) | 773 ms | 262 ms |
| typing `ma`→`mai`→`main`→`main.p` | 4,108 ms | **1,398 ms** |
| — last keystroke alone | 786 ms | **108 ms** |

The headline is the shape change, not the ratio: keystroke latency used to be
flat at ~1 s regardless of how specific the query was, and now falls as the
query grows (598 → 393 → 299 → 108 ms), because narrowing runs each edit against
the previous result set.

Groups landed in order 1 → 2 → 3 → 4/5/8 → 6 → 7, and each was benchmarked; the
scorer fast path and narrowing contributed roughly equally to the typing figure.

## Migration Plan

No persisted state, no data migration. One new config key with a default, so
existing config files stay valid; `config.example.toml` is regenerated in the
same change. The tiers are independent and land in task-group order, so the
change can stop after any group and still be coherent — groups 2–3 alone are the
measured 2–7× with no behaviour change at all.
