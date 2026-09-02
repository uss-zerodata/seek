## Why

A port scan says a web server is listening; it does not say what is on it. The
viewer already derives the exact list a screenshotting tool wants - HTTP and
HTTPS URLs for every host *and* every name it is known by, which is what
`export_urls` was built for - but that list has to be carried out to gowitness
by hand, and whatever gowitness finds never comes back. The operator ends up
with a directory of screenshots on one side and a host list on the other, and
has to join them mentally.

Running the capture from inside the viewer closes that loop: the URLs go out
with the ports and vhost names already resolved, and the page title, HTTP
status, server and technologies come back onto the host and service records
they belong to - so "which of these 40 web servers is worth looking at" is
answerable in the list the operator is already reading.

## What Changes

- **A gowitness capture runs from inside the viewer.** The export dialog gains
  a recipe that, instead of writing a URL list to a file, hands that list to
  gowitness and runs it. The run appears in the Scans tab beside nmap runs,
  streams its output, and can be cancelled.
- **Docker first, then the native binary.** Availability is detected at start
  up: the `ghcr.io/sensepost/gowitness` image if docker is usable, otherwise a
  `gowitness` on `PATH`. A config key overrides the order or pins one mode. The
  UI carries an indicator showing which backend is in use, greyed out when
  neither is available.
- **Results are read back into the host and service records.** Capture results
  are parsed from gowitness's JSON Lines output and shown in the detail of the
  service they belong to: final URL, HTTP status and reason, page title,
  server, detected technologies, TLS summary, and the screenshot's path. A host
  shows a one-line summary per captured URL. No new tab.
- **The screenshot is reachable.** A key opens the selected capture's image in
  the system viewer; another starts `gowitness report server` against the run's
  own database and opens the browser at its gallery.
- **Output is written where an external run would write it**, under a
  `gowitness/` subdirectory of the scan output directory: `gowitness.sqlite3`,
  `gowitness.jsonl` and `screenshots/`. A capture directory produced outside
  the app is read on start up the same way external nmap files already are.
- **Captures are a separate run slot.** A gowitness capture may run while an
  nmap scan runs; only one capture runs at a time. The quit guard covers both.
- **URLs are supplied fully qualified, and gowitness is told not to guess.**
  Verified against the real tool: a bare name is expanded across
  {http,https} × {80,443} (2 names produced 7 probes), while a URL carrying a
  scheme and an explicit port is probed exactly once. Since the viewer knows
  which ports are actually open, it sends complete URLs, and every result joins
  back to exactly one service.

## Capabilities

### New Capabilities

- `gowitness-capture`: detecting gowitness (docker or native), running a
  capture over a supplied URL list, supervising and cancelling it, writing its
  output where an external run would, and parsing its results back into
  records.

### Modified Capabilities

None. Three were considered and each turned out to need no requirement change:

- `nmap-scan-viewer` states that the record SHALL include everything **the
  scan** carried for an entry. Capture results do not come from the scan, so
  that requirement stays true as written; showing them is new behaviour, owned
  by `gowitness-capture` rather than grafted onto a requirement about nmap
  output.
- `nmap-scan-runner` governs nmap runs. Captures are supervised the same way
  but are not nmap scans, and its "one scan at a time" rule - which exists
  because concurrent nmap scans corrupt each other's timing - is unchanged for
  nmap. The capture slot is specified separately.
- `configuration` already requires that the file SHALL be able to override "at
  least" an enumerated list, and separately that the shipped example lists
  every supported key. New keys are admitted by that wording; nothing normative
  changes.

Note that `nmap-scan-viewer` and `nmap-scan-runner` are not yet in
`openspec/specs/` - their changes are unarchived - so a MODIFIED delta against
them could not be built from a base spec and would misapply at archive time.
That is a reason to be careful here, not the reason for the decision above.

## Impact

- **New**: `src/seek/gowitness/` - detection, command building, result parsing.
  The existing `nmap/runner.py` is generalised to supervise either tool rather
  than being copied; its docstring already anticipates this ("a future feature
  that runs a different tool supplies the same and gets the same supervision"),
  but `ScanRun` is nmap-shaped (`xml_path`, nmap progress regexes, an nmap
  summary) and that shape has to be separated from the supervision.
- **Modified**: `tui/nmap/app.py` (indicator, capture action, screenshot and
  report keys), `tui/nmap/detail.py` (capture facts in the record),
  `tui/nmap/scans.py` (captures in the run list), `nmap/export.py` (the capture
  recipe alongside the write-to-file recipes), `config.py`, help and palette.
- **External**: docker, or a `gowitness` binary - both optional. The feature
  disables itself, visibly, when neither is present. No new Python dependency:
  results are JSON Lines, read with the standard library.
- **Note on the reference commands**: the documented workflow passes an extra
  `gowitness` word (`docker run … ghcr.io/sensepost/gowitness gowitness scan
  file …`), which the current image rejects - its entrypoint is already
  `gowitness`. `-D` is `--debug-log`, not a database flag. The commands this
  change generates are built against the installed v3 interface rather than
  copied from the reference.
