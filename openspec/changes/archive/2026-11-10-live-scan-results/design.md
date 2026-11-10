# Design

## Context

- **nmap already batches.** nmap scans in host groups (`--min-hostgroup` /
  `--max-hostgroup`; adaptive from about 5 up to 1024 by default). It runs
  every phase on a group and then writes the group's hosts to `-oN` / `-oX` /
  `-oG`. During a scan the XML file grows, but it has no closing `</nmaprun>`.
- **seek can already read such a file.** `parse.parse_file` keeps the hosts of a
  truncated file and sets `ScanFile.complete = False` (scan-robustness).
- **seek reads only at the end.** A run is folded in by its `Owner`
  (`NmapApp._absorb` / `HeadlessOwner._reread`), and only on `State.DONE`. That
  path re-reads every source: one loading path, for runs started here and
  outside alike.
- **One slot.** `Runner` holds one `_process` / `_current` / `_cancelling`, and
  `Session.scan_blocked` / `start_scan` refuse a second scan.

## Goals / Non-Goals

**Goals**
- Hosts that a running scan has finished are in the model within about a minute
  of nmap writing them, in both front ends.
- Several nmap scans can run at once, after a review that states the cost.
- Cancelling a scan, or a scan failing, keeps what it finished.

**Non-Goals**
- Splitting the targets into separate nmap runs.
- An incremental merge. The re-read stays the whole loading path.
- Running captures at the same time as each other.
- A builder question for the group size (it is in the fine-tune list).

## Decisions

### D1: Trigger on nmap's report lines; re-read only when the file grew
nmap prints `Nmap scan report for` for each host of a finished group, in one
burst, and then may say nothing for hours. The first report line starts a timer
per run (`Session._scan_line`). It fires `LIVE_SETTLE` (5 s) later, so the burst
is read whole, or at the end of the pause since the last read (D2), whichever is
later. It fires whether or not more lines come. Waiting for the *next* line
instead would leave the rest of a group unread until the next group. The timer
calls `owner.scan_grew(run)`. `False` means another read was running, and the
timer is set again for `LIVE_SETTLE`. The owner reads only if the XML is larger
than at its last read (`Session.file_grew`). A run's end clears its timer, and
the final read covers it.

**Why both checks:** stdout is the cheap, exact signal that a group is done. The
size check covers the one thing we cannot test here: whether nmap flushes the
XML after each group.

**Rejected:** polling the file on a timer. That reads every N seconds for a
two-day scan, most of them for nothing.

### D2: A live read is the existing re-read, made quiet
- **TUI:** `_absorb(run, live=True)` skips `_Busy` / `_show_busy`. It reuses
  `_reread` (`exclusive=True, group="absorb"`) and the `quiet` rebuild rule
  ("a batch must never take the list away"). It says "<preset>: +N hosts so far"
  on the status line.
- **Coalescing:** a live read never cancels the reading pipeline that is
  streaming the first load. While `_reading` or another absorb is running, the
  trigger is dropped. The next report line asks again.
- **The final read always runs.** `scan_done` calls `_absorb` as today, and its
  token supersedes a live read that is still in flight.
- **Headless:** `HeadlessOwner.scan_grew` calls `_reread(live=True)` and does
  not print per read. Each read is numbered, and only the newest publishes: an
  older read finishing later would put back older files.

**Pacing:** the pause is `max(60 s, 4 × the last re-read's duration)`
(`Session.read_took`). This
is the same headroom idea as `_ABSORB_HEADROOM`, so a 20-second re-read of a
huge engagement runs at most every 80 s.

### D3: One diff baseline per run, taken as it starts; only its own hosts count
`session.diffs[id(run)]` used to be computed from a `snapshot` taken before the
re-read. With live reads, a snapshot before the *final* read would miss
everything read in while the run ran.
- **When:** `start_scan` snapshots the model in a daemon thread
  (`_take_baseline`), and the reader joins it (`Session.baseline`).
- **Why at the start:** the real-nmap test showed that a baseline taken at the
  run's first read is wrong. Every read re-reads every source, so another scan's
  read had already put this run's hosts in the model, and the run said "nothing
  new" for hosts only it found.
- **Why a thread:** the snapshot of a large engagement stays off the event loop.
- **What counts:** `Session.run_diff` compares only the hosts in the run's own
  file, because a read also holds what concurrent scans found. Two scans ending
  together each counted the other's hosts.
- **Cleanup:** a baseline is dropped after the run's final read
  (`forget_baseline`), or at its end when it wrote no file.

### D4: A running file is labelled by the run, not by its completeness
`Session.running_paths()` returns the XML paths of the active runs.
- `_say_unread` skips them.
- `tabs.py` hides a `ScanFile` whose path is a running run's (it already hides
  a done run's file the other way round).
- The record names the file as running.

When the run ends without `DONE` (cancelled, failed), the final read still
happens if the XML exists. The file is then a normal incomplete file, warned
about once.

### D5: A Runner supervises several runs
- `Runner._processes: dict[int, Process]` and `Run.cancelling: bool` replace
  the single fields.
- `active() -> list[Run]` replaces `current`. `busy()` returns the first active
  run (for gowitness, which still refuses).
- `cancel(run=None)`: `None` cancels the only active run, and returns `False`
  if several are active and none was named.
- `claim` keeps its role: a run is active from acceptance.
- The class docstring changes. The contention reasoning becomes the review's
  warning, not a lock.

**Why not one `Runner` per scan:** `runs` is the history the Scans tab, the web
`_runs` and the status count read. One list stays one list.

### D6: Starting a second scan
- `Session.scan_blocked` loses the busy branch.
- `Session.scan_warning() -> str | None` names the running scans and the cost,
  in one sentence.
- `ScanPlan` gains `warning`. The TUI `ReviewScreen` shows it above the choices
  in the warning colour, and the browser review shows it as a note. Start stays
  the primary action, because the user asked for a warning, not a gate.
- `start_scan` refuses only an `out_base` that an active run uses. `output_base`
  stamps to the second, so two scans of one preset in one second would collide.
  `output_base` now adds `-2`, `-3`, … when `<base>.xml` exists or is claimed.

### D7: Cancel and quit with several runs
- **TUI `c`:** in the Scans tab on a running run, it cancels that run. Elsewhere
  with one running, that one. With several, a `ChoiceScreen` of the running
  scans.
- **Web:** `POST /runs/{tool}/cancel` keeps working when one run is active
  (409 with "several running - name one" otherwise). `POST /runs/{rid}/cancel`
  is new. The browser's cancel button sends the selected run's id.
- **Quit question:** it names every running run and says "the hosts finished so
  far are kept". `cancel_all` cancels all of them.

## Risks / Trade-offs

- **nmap may buffer the XML.** Then live reads lag by the buffer size. The size
  check (D1) makes this harmless, just later. A manual check with a real nmap
  is in the tasks.
- **Re-read cost at scale.** Every live read is a full re-read. The pacing (D2)
  bounds it to about 20% of the time at worst.
- **Concurrent scans skew each other's timing.** That is accepted by the user,
  and stated in the review.
- **Hosts can change between reads.** A host from a later group may be merged
  with an older file's view of it. That is the normal merge rule.
