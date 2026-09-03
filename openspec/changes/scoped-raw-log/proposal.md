## Why

The viewer shows what it parsed, and nothing else. When a record looks wrong —
a service named from nmap's port table rather than a probe, a host called `up`
with no evidence, a script result that reads as though something was cut — the
only way to check is to leave the application and open the `.nmap` file by
hand, then find the host in a file that can be twenty thousand lines long.

nmap's own output also carries things the XML does not surface here at all: the
`Not shown: 984 filtered tcp ports (no-response)` summary, the per-port
`REASON` column, latency and scan timing. Today that text exists in the
engagement directory, is already read for the Scans tab, and is unreachable
from the record it describes.

## What Changes

- **A record carries the raw scan output for its own subject.** A host's record
  and a service's record list the scans that recorded them, and each of those
  entries can be opened to show nmap's own text for *that host* or *that port*
  in *that scan* — not the whole file.
- **The detail pane gains a line cursor.** The pane is navigated by moving a
  selection line by line rather than by scrolling blindly, so the position in a
  record is visible and an entry is opened by selecting its line. A key moves
  the cursor to the next line that can be opened, so a long record does not
  have to be walked a line at a time to reach one.
- **Opening an entry switches the pane to that scan's scoped output**, with a
  heading saying which scan and which subject it is scoped to. `Esc` returns to
  the record. The full-screen reader opens whichever of the two the pane is
  showing, so search and paging come to the raw log unchanged.
- **A scan with no `.nmap` file beside its `.xml` still has an entry**, showing
  a report reconstructed from the parsed record and labelled as reconstructed —
  the same fall-back the Scans tab already makes, rather than a feature that
  silently disappears for an engagement handed over as XML only.

Non-goals for this change: raw output for the service *overview* and grouping
records, which describe a service across many hosts and have no single scoped
block to show — those drill down to one host's service, where it is available;
and any parsing of nmap's text back into the model, which stays the XML's job.

## Capabilities

### New Capabilities

None. This extends what the viewer already shows for a record and how that
record is navigated.

### Modified Capabilities

- `nmap-scan-viewer`: a record lists the scans that recorded it and can show
  each one's raw output scoped to that record; the detail pane is navigated by
  a line cursor rather than by scrolling, and that cursor is what selects an
  entry to open.

## Impact

- `src/seek/nmap/rawlog.py` (new): locating a scan's `.nmap` file and cutting
  the block belonging to one host, or one port of one host, out of it; the
  reconstruction fall-back when the file is absent.
- `src/seek/tui/nmap/detail.py`: records gain a scans block, one entry per
  line, and the renderers have to say which of their lines can be opened.
- `src/seek/tui/nmap/app.py`: the line cursor, its key bindings, the pane's two
  modes and the `Esc` that leaves the second one.
- `src/seek/tui/nmap/reader.py`: opens whichever mode the pane is in.
- Key bindings: `J`/`K` change from scrolling the pane to moving its cursor;
  `o` gains a second meaning, and its existing one on the Scans tab has to keep
  working. Both are settled in design.md.
- The specs do not yet describe the terminal progress line, the recursive scan
  discovery or the streaming read added earlier; this change touches the same
  area and its delta is written against the specced behaviour.
- No new dependencies. No configuration change. Nothing is written: the `.nmap`
  file is read, never modified.
