## Why

At engagement scale the viewer stops feeling like a terminal application. Measured
on 120 scan files covering 24 200 hosts (110 MB of XML): roughly 17 s of reading
and projecting before anything is on screen, and once inside, a background build
leaves input latency at a p95 of 189 ms with worst-case stalls of 1.8 s. Only the
Scans tab can say how far it has got, because it is the only step that counts
itself; every other wait is an unquantified spinner.

The cause of the stalls is not the work but the cycle collector: the model is
millions of tracked container objects, and every generational collection walks
all of them. Taking the collector out of the bulk phases and freezing the model
once it is built halves the pipeline and removes the stalls outright — measured,
not estimated. That makes the remaining wait short enough to be worth streaming
rather than blocking on.

## What Changes

- **The cycle collector is kept out of the bulk phases.** Reading, merging and
  projecting run with collection suspended, and the built model is frozen so
  later collections never walk it again. Measured: parse 6.72 s → 2.67 s, merge
  4.07 s → 0.75 s, scan history 5.45 s → 1.00 s, statistics rows 4.97 s →
  2.51 s; worst-case input stall during a build 1821 ms → 2.3 ms.
- **The thread switch interval is tightened while a background build runs**, so
  the event loop gets the interpreter back promptly rather than at 5 ms
  boundaries. Measured: median input latency 5.2 ms → 1.2 ms.
- **Every long build reports its progress**, not just the scan history. Reading
  files, merging and each overview projection report work done against work
  total, so any wait over a moment shows a determinate bar with counts instead
  of a bare spinner.
- **The viewer opens before the scans are read** and fills as they arrive.
  Reading is throttled into the model on a cadence rather than published per
  file, on the same principle the search engine already applies to its result
  snapshots, so the list becomes usable while the rest is still being read.
- **The decision that there is nothing to read moves into the viewer**, since it
  can no longer be made before the viewer starts. An engagement with no
  readable scan and no way to start one still says so and still exits non-zero.

Non-goals for this change: moving any part of the model to a native extension
(Rust or Cython), and replacing the XML parser. Both are deliberately deferred
until this change is measured, because parsing is already C and the cost that
remains is Python object construction — which a native parser returning Python
objects would still pay.

## Capabilities

### New Capabilities

None. This change alters how existing viewer behaviour performs and reports
itself; it introduces no new capability.

### Modified Capabilities

- `nmap-scan-viewer`: opening an engagement no longer blocks on reading it — the
  viewer opens and the model fills as scans are read; every wait long enough to
  notice reports what it is doing and how far it has got, and can be abandoned;
  the "nothing readable" outcome is decided by the viewer rather than before it
  starts.

## Impact

- `src/seek/nmap/parse.py`, `merge.py`, `timeline.py`, `views.py`: progress
  reporting for the reading and projection steps, and the collector policy for
  the bulk phases.
- `src/seek/tui/nmap/app.py`, `views.py`: streaming a growing model into the
  open viewer, invalidating cached projections as it grows, and reporting
  determinate progress for every build rather than only the scan history.
- `src/seek/cli.py`: `seek nmap` starts the viewer before the scans are read;
  the terminal progress line becomes the fallback for the non-interactive path
  only.
- Tests: the viewer's existing tests assume a fully loaded model at mount, which
  remains true for small sets and has to be made explicit for streamed ones.
- No new dependencies. No configuration change. No change to what a scan file
  means or to any output the application writes.
- The specs do not yet describe the recursive scan discovery, the working
  directory default or the terminal progress line added earlier; this change
  touches the same area and its delta is written against the specced behaviour,
  not against those additions.
