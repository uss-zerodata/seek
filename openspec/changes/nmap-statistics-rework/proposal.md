## Why

The statistics tab lists six aggregate counts and one line per service name in a
single flat table, and the viewer sorts every list by its first column — so the
totals and the per-service lines interleave alphabetically and the tab reads as
an unordered dump. Distinct open ports are worse off: they are not rows at all
but a comma-separated string in the *detail* cell of one metric, truncated to
the first ten.

The tab is also a dead end in a viewer whose whole navigation model is now
"press `Enter` to keep digging". Every count on it stands for a set of hosts the
user would want to look at — the targets, the ones with evidence of being
reachable, the twelve hosts running `http` — and none of them opens.

## What Changes

- **Sections with headings.** The statistics view is grouped into labelled
  sections — Coverage (host counts), Services (one line per service name),
  Ports (one line per open port) — rendered as visually distinct heading rows,
  in a fixed order that sorting cannot scramble.
- **Ports become rows.** Each open port gets its own line with how many hosts
  expose it and the services seen on it, replacing the truncated comma list in a
  detail cell. `Statistics` grows a `ports` breakdown alongside `services`.
- **Sorting applies within a section.** Choosing a column orders the lines
  inside each section and leaves the headings and the section order alone; the
  view opens on its most useful order (most occurrences first) rather than
  alphabetically by the first column. Views gain a declared default sort.
- **Every statistic opens.** `Enter` (or a click) on any statistics row pushes a
  drill-down for what it counts: a coverage count opens that set of hosts, the
  distinct-services and distinct-ports counts open the matching grouping, a
  service line opens the hosts running it, a port line opens the hosts exposing
  it. `Esc` comes back to the statistics tab as it does from any other
  drill-down.
- **Column headings sort on click**, so the sort is reachable with the mouse in
  every view, not only through the number keys.
- Not in scope: an OS breakdown and a vulnerability/findings section. Both are
  plausible sections later; this change is about the structure that would hold
  them.

## Capabilities

### New Capabilities

None — this reworks behaviour the viewer already claims.

### Modified Capabilities

- `nmap-scan-viewer`: the **Aggregate statistics** requirement gains structure
  (sections, ordering, ports as rows) and drill-down from every row; the
  **Sorting** requirement gains section-aware ordering, a per-view default
  order, and sorting by clicking a column heading. The capability is currently
  specified by the unarchived `nmap-scan-viewer` change, so the delta is written
  against that spec.

## Impact

- `src/seek/nmap/views.py` — `Statistics` gains a `ports` breakdown; `statistics()`
  counts hosts per port and services per port.
- `src/seek/tui/nmap/views.py` — `statistics_view()` rebuilt around sections;
  `Row` gains section/heading/style fields; a host-list view builder for an
  arbitrary subset of hosts; `View` gains a default sort.
- `src/seek/tui/nmap/app.py` — section-aware sorting and filtering in `_narrow`,
  heading rendering in `_fill`, statistics targets in `action_drill`,
  `_reset_sort` reads the view's default, `on_data_table_header_selected`.
- `src/seek/tui/nmap/help.py`, `commands.py`, `README.md` — the statistics tab is
  navigable, so say so.
- Tests: `tests/test_nmap_views.py` (the ports breakdown), `tests/test_nmap_viewer.py`
  (sections, ordering, drill-down from each row kind, filtering a section empty).
- No new dependencies; nothing persisted; the viewer stays stateless.
