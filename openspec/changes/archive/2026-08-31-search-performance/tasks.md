## 1. Benchmark harness and the equivalence safety net

- [x] 1.1 Add `benchmarks/bench_search.py`: walk a tree given as an argument, time the name pass, the cold and warm content passes, and an incremental typing sequence; print a table with hit counts.
- [x] 1.2 Keep it out of the default `pytest` run (own directory, not under `tests/`); document how to run it in AGENTS.md.
- [x] 1.3 Record a baseline for a fixed corpus in the benchmark's docstring so regressions are visible.
- [x] 1.4 Add `tests/test_score_equivalence.py`: keep the current scorer as `_reference_score` and assert identical `(score, spans)` for every optimised path over a generated corpus — fuzzy, exact, prefix, suffix, equal, negated, and multi-term queries.

## 2. Scorer fast path (no behaviour change)

- [x] 2.1 Precompute the case-folded needle on `Term` at parse time (`Term.needle`) and `ParsedQuery.needs_fold`, so neither is recomputed per line. *(Revised: the compiled regex this task originally specified backtracks catastrophically on common-character needles — see design.md decision 1.)*
- [x] 2.2 Add `query.fuzzy_ok()` (first-char gate + shared-iterator subsequence test) and call it in `_score()` after the `find()` miss and before `_greedy`; share it with `Term.matches`.
- [x] 2.3 Hoist `len(hay)` to a local in `_greedy`'s inner loop.
- [x] 2.4 Thread an optional pre-lowered `hay` through `score()` / `_term_score()`; have `match_spans` lowercase once per line and pass it down. Keep the public signatures unchanged.
- [x] 2.5 Bound the substring-occurrence scan in `score()` (first occurrence + word-boundary occurrences, capped at a small fixed count).
- [x] 2.6 `uv run pytest -q` green and `test_score_equivalence` passing; re-run the benchmark and record the delta.

## 3. Content cache: O(1) LRU, honest accounting, lock scope

- [x] 3.1 Replace `_data` + `_order` with a single `OrderedDict`; `_touch` becomes `move_to_end`, eviction becomes `popitem(last=False)`.
- [x] 3.2 Account the budget in bytes including per-line `str` overhead instead of counting characters.
- [x] 3.3 Move `_read()` outside the lock; hold the lock only for dict bookkeeping. Comment why a concurrent duplicate read is acceptable.
- [x] 3.4 Tests: cache lookup cost does not grow with cached-file count; the configured budget bounds retained bytes.

## 4. Bounded result accumulation

- [x] 4.1 Replace the unbounded `results` list in `engine.search` with a `heapq` min-heap of at most `config.max_results` `(score, seq, result)` entries plus an integer total counter.
- [x] 4.2 Skip constructing the `Result` entirely when the heap is full and the score cannot beat `heap[0][0]`.
- [x] 4.3 Produce the final ordering by sorting the heap on the same key, matching today's `heapq.nlargest` output.
- [x] 4.4 Apply the same bounding to the name pass, not just the content pass.
- [x] 4.5 Test: a query matching far more than the cap reports the true total while holding on the order of the cap in result objects.

## 5. Deferred span computation

- [x] 5.1 Split scoring from span extraction in `score.py` so the scan can request a score only.
- [x] 5.2 Compute spans for the capped survivors after the heap is drained.
- [x] 5.3 Test: every result in a capped set still reports correct match positions.

## 6. Incremental query narrowing

- [x] 6.1 Add a `can_narrow(old_raw, new_raw, old_terms)` predicate implementing the soundness rule: pure append, old query's final term not negated.
- [x] 6.2 Cache the previous query's matched pool (names and content lines) with the generation, modes, and root that produced it; invalidate on mode toggle, re-root, refresh, and while `store.scanning`.
- [x] 6.3 Search the cached pool instead of the full candidate set when the predicate holds.
- [x] 6.4 Test: narrowed results are identical to a full rescan across an edit sequence; deletion, mid-string edits, negation extension, and mode toggles all fall back to a full rescan.
- [x] 6.5 Re-run the benchmark's incremental typing sequence and record the delta.

## 7. Per-file content size cap and header-first binary sniff

- [x] 7.1 Add `content_size_cap` to `Config` (default 5 MB) with validation and an example-file comment.
- [x] 7.2 Restructure `ContentCache._read`: open, read the sniff header, reject binaries, then read up to the cap.
- [x] 7.3 Drop the final partial line when the read hit the cap so no half-line is reported as a match.
- [x] 7.4 Regenerate `config.example.toml` via the AGENTS.md command.
- [x] 7.5 Tests: an oversized text file is searched only up to the cap; a large binary is rejected after the header read; a normal file is unaffected.

## 8. Cancellation granularity and candidate snapshots

- [x] 8.1 Check `is_stale()` every N lines inside `_content_hits`, not only per candidate.
- [x] 8.2 Check staleness in batches in the name pass rather than per candidate.
- [x] 8.3 Replace `CandidateStore.snapshot()`'s full list copy with a length-bounded read; comment the CPython atomicity assumption.
- [x] 8.4 Test: a search over a file with very many lines abandons part-way once superseded.

## 9. Finalisation

- [x] 9.1 `uv run ruff check` clean.
- [x] 9.2 `uv run pytest -q` green — existing engine and scorer tests unchanged.
- [x] 9.3 Benchmark re-run; record before/after in the change notes and update the design's measured figures if they moved.
- [x] 9.4 Update AGENTS.md architecture notes (scorer fast path, narrowing pool, cache invariants) and README if any user-visible behaviour changed.
- [x] 9.5 `openspec validate search-performance --strict` passes.

## 10. Time-throttled progress snapshots (follow-up)

- [x] 10.1 Add `publish_interval_ms` to `Config` (default 500) with an example-file comment; regenerate `config.example.toml`.
- [x] 10.2 Replace the `CHUNK_SIZE` hit-count trigger in `engine.search` with a `monotonic()` interval check, publishing only when new matches have arrived since the last snapshot.
- [x] 10.3 Tests: a long interval suppresses intermediate snapshots; `0` publishes every batch; snapshots are spaced by at least the interval; the final result set is identical either way.

## 11. Reuse the launch scan when changing root (follow-up)

- [x] 11.1 Add pure `walk.rebase(candidates, rel_root)` re-expressing a completed walk as if rooted at `rel_root`.
- [x] 11.2 Keep the completed launch-root scan on the app (`_base_candidates`), captured in `_on_walk_finished`.
- [x] 11.3 `_reset_for_new_root` derives the new root's candidates via `_reuse_walk()` and only walks when that fails; `store.clear()` still bumps the epoch so the narrowing pool is dropped.
- [x] 11.4 Fall back to a real walk when a positional scope is active, the new root is outside the launch scan, or the launch scan never completed.
- [x] 11.5 `action_seek_refresh` discards the cached scan first, so refresh always hits the filesystem.
- [x] 11.6 Tests: `rebase` unit tests incl. matching a real walk; re-root and breadcrumb pop perform zero extra walks; refresh performs one; a positional scope falls back.
