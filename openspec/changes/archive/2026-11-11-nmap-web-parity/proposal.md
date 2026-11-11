## Why

The web interface (`nmap-web-interface`) shows hosts, services and screenshots,
but everything else an engagement needs - statistics, groupings, names, the Scans
tab, nmap's raw output, search, marks, export, running scans and captures - still
lives only in the terminal. It was built so it could grow into an alternative to
the TUI; this change makes it one, so the same work can be done in either, and
adds a way to run it without a terminal at all.

## What Changes

- **A session core shared by both front ends.** The model, the runs, the marks
  and the logic that folds a finished scan or capture back into the model move
  out of the Textual app into one object. The TUI and the web interface both
  drive it; a scan started in either appears in both, and a mark made in either
  is a mark in both. Each client keeps its own tab, filter, sort and cursor.
- **Every overview in the browser**: hosts, services, statistics, the three
  groupings, names and scans - with drill-down that chains exactly as in the
  TUI, the viewer's filter grammar, sorting by any column, the up / open-ports
  toggles, and a back path that restores each level's filter, sort and row.
- **The record for any row**, with the same content the TUI's pane and reader
  show (one renderer for both), links to nmap's own text per scan with stepping
  between the scans of one subject, and in-page search.
- **Marks and export**: mark rows (a bucket marks every record in it), see and
  clear the marks, and export with the same recipes, fields and formats as the
  TUI, downloaded as a file or copied.
- **The Scans tab**: the history of scan files with what each added, live runs
  with their log streamed as it is written, freeze, cancel, and the three report
  modes.
- **Running tools**: a new scan from the shipped or configured presets - scope,
  editable command, the same review before it runs, the same privilege rules
  (`sudo -n`, never a prompt) - and a gowitness capture over the marked or
  filtered URLs. One run per tool at a time, as in the TUI.
- **Keyboard navigation** that mirrors the TUI (`j`/`k`, `h`/`l`, `Enter`,
  `Esc`, `/`, `m`, `x`, digits for sort, `v`/`V` for tabs, `?` for help).
- **`seek nmap serve PATHS…`**: the session and the web interface without the
  TUI, for a headless box or a second screen. `w` in the TUI stays.
- **A light guard on state-changing requests**: they are accepted only from the
  interface's own origin, so a page on another site cannot start a scan through
  the browser. No tokens, no accounts - it binds to loopback only.
- Pages stay server-rendered with plain ES modules and Server-Sent Events for
  live updates: nothing to install, build or vendor. Charts, when statistics
  get visualisations, are drawn as SVG on the server.

## Capabilities

### New Capabilities
- `nmap-session`: the shared session - one model, runs and marks behind every
  front end; what is shared and what stays per client.
- `nmap-web-frontend`: the browser's full feature set - overviews, drill-down,
  records and raw output, search, marks, export, the Scans tab, running scans
  and captures, live updates, keyboard navigation, and the same-origin guard.
- `nmap-serve`: `seek nmap serve` - headless start, what it prints, how it
  stops, and what happens to running work when it does.

### Modified Capabilities
- `nmap-scan-viewer`: marks and runs are the session's, so a mark or a run made
  in the browser appears in the TUI and the other way round.

## Impact

- New `src/seek/nmap/session.py` (no Textual): model, `Runner`s, marks,
  fold-in on completion, change notifications.
- `src/seek/tui/nmap/app.py` delegates model, runs and marks to the session.
- `src/seek/tui/nmap/detail.py` gains an HTML rendering of `Line`s next to the
  Rich one (the record is still built once).
- `src/seek/web/`: new routers for every overview, records, raw output, marks,
  export, scans and runs; an SSE endpoint; `static/` becomes a few ES modules.
- `src/seek/cli.py`: the `serve` form of `seek nmap`.
- No new dependencies.
- Depends on `nmap-web-interface` (should be archived first so its spec exists).
