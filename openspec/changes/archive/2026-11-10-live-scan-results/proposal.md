# Proposal

## Why

A large scan can run for two days, and today seek shows nothing of it until it
ends: the model is re-read only when the run finishes. But nmap already works in
host groups and writes each finished group to its `-oA` files while it runs, so
most of a long scan's results are on disk long before the end. The one-scan cap
makes the wait worse: while a two-day scan runs, no second scan can start, not
even a quick version scan of what the first scan has already found.

## What Changes

- While a scan runs, seek SHALL fold the hosts nmap has already written into the
  model, so every tab, filter, export, record and the browser shows them. The
  trigger is nmap's own report lines on stdout (a host group is done). The
  re-read is throttled, it is quiet (the list stays where it is), and it uses the
  one existing loading path. It reads the partial file the way an interrupted
  scan's file is already read.
- A scan that is cancelled or fails keeps the hosts it finished in the model,
  marked as incomplete. Today the model is "unchanged", but by then the live
  results are already in it, and taking them out again would lose work.
- Leaving while a scan runs still asks first, but the question now says what is
  kept: the hosts finished so far stay, and only the rest of the scan is lost.
- **BREAKING (behaviour):** the one-nmap-scan-at-a-time rule becomes a warning.
  Starting a scan while another runs is allowed after a review that names the
  running scan(s) and states the cost: both share the network path, each scan's
  timing adapts to the other's traffic, both take longer, and rate-limited
  targets drop more probes. Captures stay one at a time (no change).
- Cancelling with more than one scan running cancels the selected run (TUI: the
  run under the cursor in the Scans tab, or a choice of the running scans; web:
  by run id). With one scan, `c` acts as before.
- The partial file of a running scan is listed once in the Scans tab: as the
  running run, not also as a separate incomplete file.

Not in scope: splitting a scan into batches (nmap's host groups already do it),
and a new builder question for the group size (`--max-hostgroup` is already in
the fine-tune list).

## Capabilities

### New Capabilities
- `nmap-live-results`: the hosts a running scan has already finished, in the
  model before the scan ends: when they are read, how often, and how they are
  labelled.

### Modified Capabilities
- `nmap-scan-runner`: "One scan at a time, every run kept" becomes concurrent
  scans with a warning. "Output streams while the scan runs" changes cancel and
  quit for several runs and what leaving keeps. "A finished scan is written
  where an external one would be" changes the outcome of a failed or cancelled
  scan.

The open change `scan-robustness` adds "One scan at a time holds for
simultaneous starts". It is reworded there to cover the tools that still run one
at a time (gowitness).

## Impact

- `seek/runner.py`: `Runner` supervises several runs (a process and a cancel flag
  per run). `cancel(run)` takes the run.
- `seek/nmap/session.py`: `scan_blocked` no longer blocks on a running scan;
  `scan_warning` names it; `start_scan` accepts concurrent runs (an output base
  that a running scan already writes is still refused). The live trigger and the
  `Owner.scan_grew` hook. The diff baseline is taken when the run starts.
- `seek/tui/nmap/app.py`, `flows.py`, `scope.py`: a quiet live re-read; the
  review shows the warning; cancel picks a run; the quit text.
- `seek/tui/nmap/tabs.py`: dedupe a running run's partial file.
- `seek/web/serve.py` (`HeadlessOwner`), `web/api/v1/runs.py` (warning in the
  review, cancel by run id), `schemas.py`, `actions.js`.
- Specs: `nmap-scan-runner` and the new `nmap-live-results`. No new dependency.
