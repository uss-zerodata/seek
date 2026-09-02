## Why

The viewer's output is usually the input to the next tool — a host list for a
focused `nmap -iL`, a URL list for gowitness — but the export it has today can
only answer five fixed questions (hosts, all hosts, ports, `host:port`, URLs),
always over *whole hosts*, always as plain lines, and only over whatever one
view happens to be showing.

Two things are missing. There is no way to **collect** records as you go: the
scan is read by moving between overviews and drill-downs, and the interesting
set is usually assembled along the way — these hosts from the host list, that
whole `443/tcp` bucket from the port grouping — not visible in any single view.
And there is no way to say **what** to write: the service-level facts (port,
product, version, the service name) cannot be exported at all, because every
recipe collapses its input to addresses first.

## What Changes

- **Marks.** Any row can be marked (`m`), and marks persist across filters,
  sorts, drill-downs and tabs until cleared (`M`). A row marks whatever records
  it stands for: a host row marks that host, a service-group or grouping row
  marks every host/service pair in the bucket, a statistics line marks what it
  counts. So "every http/https service" is one keypress on the `by service` tab.
- **Export follows the marks when there are any, and the current filtered view
  when there are none** — the existing behaviour is what you get until you mark
  something. Which of the two is being exported is stated in the status line
  and again in the export dialog, so it is never guessed.
- **A record is a host *and optionally* a service** rather than a host. This is
  what lets `443/tcp on 10.0.0.5` be exported as itself instead of as
  `10.0.0.5`.
- **Field selection.** The named presets stay as one-keypress answers and gain a
  `custom…` path that picks fields from a catalogue spanning both host facts
  (address, hostname, OS, state, reachability, source scans) and service facts
  (port, protocol, service, product, version, tunnel, vulnerability count, URL).
- **Formats: JSON, CSV and text.** CSV carries a header row; JSON writes one
  object per record keyed by field name; text writes the fields space-separated,
  one record per line. Identical output rows are written once.
- **BREAKING (internal):** `nmap.views.EXPORTS` maps a name to a function over
  *records*, not over `list[Host]`. Nothing outside the viewer imports it.
- Not in scope, and deliberately: invoking `nmap`, gowitness or any other tool
  from the viewer. This change puts the record set and the field catalogue
  behind a pure, TUI-free boundary precisely so that a later change can hand the
  same selection to a runner instead of to a file.

## Capabilities

### New Capabilities

None — the viewer already claims exporting; this changes what it can express.

### Modified Capabilities

- `nmap-scan-viewer`: the **Derived lists can be exported** requirement gains
  marks as the export source, records that carry a service, a field catalogue
  and the three formats. The **List navigation** and **The list is the thing
  being operated on** requirements gain marking as an action on the row under
  the cursor. The capability is specified by the unarchived `nmap-scan-viewer`
  change (and amended by `nmap-statistics-rework`), so the delta is written
  against that spec.

## Impact

- New `src/seek/nmap/export.py` — the record type, the field catalogue, the
  three writers, the presets. Pure; no Textual import.
- `src/seek/nmap/views.py` — `EXPORTS` moves to `export.py` and becomes
  record-based; `export_urls` and friends keep their output.
- `src/seek/tui/nmap/app.py` — the marked set, `m` / `M`, the marker in the
  list, "N marked" in the status line, the widened export flow.
- `src/seek/tui/nmap/views.py` — each row says which records it stands for.
- `src/seek/tui/menu.py` — a multi-select modal for the field picker.
- `src/seek/tui/nmap/help.py`, `commands.py`, `README.md`, `AGENTS.md`.
- Tests: a new `tests/test_nmap_export.py` for the pure side; marking, mark
  persistence and the export flow in `tests/test_nmap_viewer.py`.
- No new dependencies (`csv` and `json` are stdlib); nothing persisted between
  runs — marks live for the session, like everything else in the viewer.
