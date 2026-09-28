## Context

See proposal.md — Why for the motivation and the measurements.

What shapes the approach:

- The model is plain dataclasses and the overviews are pure projections over
  them (`src/seek/nmap/models.py`, `views.py`). Row projections are already
  cached per model identity, and the Scans tab already builds off the event
  loop in a thread worker with a progress report.
- Reading currently happens in `seek nmap` before the viewer is constructed:
  `load()` → `prepare()` → `run_viewer(scans, …)`. The viewer therefore assumes
  a complete model at mount, and so does every viewer test.
- A thread worker does not give parallelism for this work — it is pure Python
  and holds the interpreter. Measured: median input latency 5.2 ms at the
  default 5 ms switch interval, and worst-case stalls of 1.8 s that are
  generational collections walking millions of tracked objects, not the work.
- The model has no reference cycles (Host → Service → ScriptResult, no
  back-references), which is what makes freezing it safe.
- Discovery is cheap and reading is not: walking 3 000 directories takes ~60 ms,
  while parsing 120 files takes seconds. The two can be separated.

## Goals / Non-Goals

**Goals:**

- One reporting shape for every long step, so the interface renders any of them
  the same way and can name the unit being counted.
- A collector policy that is explicit and scoped, rather than a global setting
  that silently changes how the library behaves for other callers.
- Streaming that leaves the projections pure — no incremental projection paths
  to keep in step with the batch ones.
- The existing viewer contract intact for a model that is already complete, so
  the current tests keep testing what they test today.

**Non-Goals:**

- Incremental projections (updating an overview in place as hosts arrive).
- Process-level parallelism for parsing, and any native extension. Both are the
  follow-up that this change's measurements are meant to inform.
- Changing what a scan file means, what is written, or any configuration.

## Decisions

### Collector policy lives at the callers, not inside the domain functions

A `bulk()` context manager (suspend collection, restore on exit, `try/finally`)
plus an explicit freeze of the built model, applied where a long phase is
*owned* — the reading worker and the projection worker — not inside `load()`,
`merge()` or `timeline.build()`.

Why not inside those functions: they are pure, they are imported directly by
tests and by the export path, and a library call that turns the host program's
collector off is a surprise that outlives the call if anything goes wrong. The
caller knows it is starting a long phase; the callee does not.

Freezing is what removes the stalls rather than merely deferring them: once the
model is in the permanent generation, later collections stop walking it. The
discipline is `unfreeze()` before a re-read and `freeze()` after the new model
is published, so a superseded model does not stay pinned in the permanent
generation. Without cycles its objects are freed by reference counting as soon
as the viewer drops them.

Alternative considered: leaving the collector alone and relying on threads plus
a tighter switch interval. Rejected on the measurements — the switch interval
fixes the median (5.2 ms → 1.2 ms) but not the p95 (189 ms) or the 1.8 s stalls,
which is what "sluggish" actually is.

### One report shape, with the unit named by the producer

A single callable — work done, work total, and the unit those figures count
("files", "scans", "hosts") — replaces the two bespoke callbacks that exist now
(`merge.Progress` with four fields, `timeline`'s `(done, total)`).

The spec requires a determinate report to name its units; carrying the unit with
the numbers is what lets one renderer serve every step. A total of zero means
"cannot count itself yet", which is how the reading phase reports its directory
walk before it knows how many files there are.

Alternative considered: keeping per-step callbacks and mapping them in the app.
Rejected: the mapping table grows with every step that learns to report, and the
renderer ends up knowing which step it is drawing for.

### Streaming publishes immutable snapshots on a cadence

The reading worker parses file by file, folds each into an accumulating set, and
publishes a **new** `ScanSet` — never mutates the one the interface is holding.
Publication is throttled (a minimum interval, and only when something new was
read), and publications are coalesced: if a projection is still running, the
newest snapshot supersedes the pending one rather than queueing.

Why immutable snapshots: the projections stay pure, and the row cache already
keys on model identity, so a new snapshot invalidates exactly what it should
with no new invalidation logic. Mutating in place would require every projection
to gain an incremental path, and a half-updated model to be unobservable.

Why a cadence rather than per file: re-projecting an overview costs more than
reading a file (0.4 s for hosts, 2.5 s for statistics against 12 ms per file),
so per-file publication would spend the time it is trying to save. Only the
tab being looked at is re-projected; the others are built when opened, as now.

Alternative considered: publishing per file with a debounce on the projection.
Rejected — that is the same cadence, expressed twice, with the model churning in
between for no observable gain.

### The command decides "worth opening" from discovery alone

`seek nmap` keeps the directory walk (cheap) and hands the viewer the candidate
file list plus a loader; the viewer does the reading. The command therefore
still answers "is there anything to read or run" without parsing anything: no
candidate file and no nmap available means say so and exit, exactly as today.

Consequence, recorded in the spec: a set where candidates exist but all fail to
parse can no longer exit before the viewer opens. The viewer opens, its empty
state names the failures, and the process ends non-zero when the user leaves.

Alternative considered: parsing the first file before opening to decide. Adds a
special case whose only purpose is preserving an exit path, and gets slower the
larger the first file is.

### Reading reports globally, projecting reports per tab

Reading affects every tab, so its progress belongs to the status line and to the
"still reading" message in an empty list. Projecting belongs to one tab, so it
keeps the content-area report already in place. This is also what keeps the two
distinguishable when both are true: reading in the status line, projecting where
the rows will be.

### Threads, not processes

The model has to be shared with the interface without a copy, and a process pool
would pay for pickling 24 000 hosts back across the boundary. With the collector
out of the way and the switch interval tightened, threads meet the responsiveness
requirement. Processes stay on the table for the parse phase alone, as part of
the deferred follow-up.

## Risks / Trade-offs

- **A forgotten `unfreeze` pins a superseded model in the permanent generation**
  → the freeze/unfreeze pair lives in one place (the publication path), not at
  each call site, and a test asserts a re-read leaves the frozen count no higher
  than before it.
- **Collection left suspended if a phase raises** → `bulk()` restores in
  `finally`, and the worker wraps the whole phase, so an exception cannot leak
  the policy.
- **A stale projection displayed against a newer model** → publication replaces
  the model's identity; the row cache keys on that identity, and the existing
  build token discards a result whose model has been superseded.
- **The cursor moving under the user as rows arrive** → publications preserve
  the selected record through the existing mark-and-restore path rather than the
  row index, which is why that machinery exists.
- **Viewer tests assume a complete model at mount** → the constructor keeps
  taking a finished `ScanSet`; streaming is opt-in by passing a loader instead,
  so existing tests are unaffected and the streaming path gets its own.
- **The latency bound is environment-dependent** → the fifth-of-a-second bound
  in the spec is asserted by hand at scale and by a coarse check in tests, not
  by timing assertions tight enough to flake in CI.
- **Suspended collection raises peak memory while a phase runs** → the phases
  are seconds long and allocate the model they are building either way; the
  freed-by-refcount majority is unaffected by collection being off.

## Migration Plan

No data or configuration migration: nothing is persisted, and no file format or
output changes. The change is behavioural and lands in one piece; rollback is a
revert. The one externally visible change is the exit path described above, and
it only differs for a set where every candidate file fails to parse.

## Open Questions

- The publication interval (~1 s to start) and the projection chunk size are
  tuning figures to settle by measurement at scale; neither changes the specs or
  the task breakdown.
- Whether the terminal progress line for discovery is still worth keeping once
  reading happens inside the viewer, or whether discovery is fast enough to be
  silent. Decidable after the streaming path exists.
