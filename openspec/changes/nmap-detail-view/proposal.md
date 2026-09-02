## Why

The record for a selected row is shown in an inline pane that shares the screen
with the list. It is right for a glance, but it caps out: a host with many
services, a vulnerability write-up, and above all a scan's **raw nmap output**
are all taller than the pane and have to be scrolled a few lines at a time with
no way to search. Reading raw output for one open port across a /24 that way is
the opposite of an analysis tool.

`d` currently only collapses that pane — the least useful thing it could do with
the most reachable key.

## What Changes

- **`d` opens the current row's detail full-screen**, as a scrollable reader
  with the whole height to work with. It shows exactly what the inline pane
  shows — host record, service record, grouping, a scan's report in whatever
  mode it is in — so it works from every tab.
- **The full-screen view is searchable.** `/` starts a search; every match is
  highlighted in place and `n` / `N` jump between them, keeping the surrounding
  context, with a match count shown. This is the point of the feature: finding a
  port, a service, a name in a long record or in raw nmap output.
- **A running scan's raw log keeps streaming in the full-screen view**, and an
  active search re-applies to new lines as they arrive — read and search a scan
  while it runs.
- **`D` takes over collapsing the inline pane** (what `d` did before), so the
  pane can still be hidden to give the list more room.
- **BREAKING (keybinding):** `d` no longer toggles the inline pane; it opens the
  full-screen view. `D` toggles the pane.

Not in scope: the file-search session's detail pager (it already opens
full-screen on `Enter`); adding search there is a separate change. Filtering the
detail to only matching lines (the chosen model highlights in place instead).

## Capabilities

### New Capabilities

None — this reshapes how the viewer's existing detail is read.

### Modified Capabilities

- `nmap-scan-viewer`: the **List navigation** requirement (what `d` / `D` do)
  and a new full-screen, searchable reading mode for the detail that the
  **Detail is laid out as a report** requirement already governs. Specified by
  the unarchived `nmap-scan-viewer` change and amended by later ones, so this
  delta archives after them.

## Impact

- New `src/seek/tui/nmap/reader.py` — the full-screen detail reader: a modal
  taking a Rich renderable (or a live source), scrolling, and in-view search
  with match highlighting and next/previous navigation.
- `src/seek/tui/nmap/app.py` — `d` → open the reader on the current row's
  detail; `D` → the old `toggle_detail`; a way to feed the reader live lines
  while a scan runs.
- `src/seek/tui/nmap/help.py`, `commands.py`, `_HINTS`, README, AGENTS.md.
- Tests: a new `tests/test_nmap_reader.py` for the search/scroll logic, and the
  `d` / `D` flows in `tests/test_nmap_viewer.py`.
- No new dependencies.
