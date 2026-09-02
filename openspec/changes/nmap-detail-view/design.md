## Context

See proposal.md — Why. What shapes the approach:

- The inline detail is a `Static` inside a `VerticalScroll` (`#detail`), updated
  by `_refresh_detail`, which builds a Rich renderable per row: `detail_pane.render`
  for host/service/group rows, `scan_views.report`/`scan_report` for the Scans
  tab. The full-screen reader must show *the same* renderable, so it takes what
  `_refresh_detail` already produces rather than re-deriving anything.
- A running scan streams into the inline pane via `_on_scan_line` →
  `_refresh_detail`. The reader, when open on that run, needs the same updates.
- The search session's `DetailScreen` (`tui/detail.py`) is a full-screen pager
  with query highlight but no interactive in-view search, and it is file-shaped
  (takes a `Result`). It is the wrong base to reuse — the nmap reader shows an
  arbitrary renderable and needs live search — so this is a new modal, styled to
  match, not an extension of that one.
- `d` is `toggle_detail` today; `←/→`, `J/K` scroll the inline pane.

## Goals / Non-Goals

**Goals**

- One reader that shows any row's detail full-screen, from any tab.
- Interactive search that keeps context (highlight in place + jump), with a
  match count and an honest empty result.
- A running scan keeps streaming into the reader, search re-applying live.
- `D` preserves the old collapse behaviour.

**Non-Goals**

- The file-search session's detail (already full-screen on `Enter`).
- Filter-to-matching-lines (the chosen model highlights in place).
- Editing or acting on the content from the reader — it reads, it does not act.
- Regex search — a plain case-insensitive substring is what raw output needs.

## Decisions

### The reader takes lines of text, not a live widget

`reader.py` holds a `DetailReader(ModalScreen)` built from a **list of text
lines** plus a title. Rendering the detail to text once, at open, decouples the
reader from how the content was produced (a Rich table, a report, a raw log) and
makes search trivial and correct — search operates on the same lines it shows.

The detail renderables are Rich; the reader needs their text. Rather than a
second text path that could drift from the pane, the reader renders the existing
renderable to lines with a Rich `Console(width=...)`. So the reader shows byte
-for-byte what the pane shows, just taller and searchable.

*Alternative rejected:* moving the Static into a bigger container. That is not
full-screen, keeps the list's width, and gives search nowhere to live.

### Search is highlight-in-place with next/previous

`/` focuses a one-line input; typing filters nothing — it highlights. Every line
containing the term is drawn with the term reverse-styled at each occurrence;
`n`/`N` move a "current match" cursor through occurrences in reading order,
scrolling that line into view. The header shows `<term> — N matches` or
`no matches`. `Esc` in the search box clears the term and returns to scrolling;
`Esc` in the reader dismisses it — the same staged `Esc` the rest of the app
uses.

Case-insensitive substring: raw nmap output is not a place for regex surprises,
and a fold-and-`find` loop is the same cheap primitive the search session's
scorer already relies on.

### A live scan feeds the reader the same lines the pane gets

When `d` is pressed on a running scan, the reader is opened in a **live mode**:
it holds the run and, on each `_on_scan_line`, is handed the run's current lines.
The reader re-renders, re-applies the active search to the new lines, and — if
the user has not scrolled up — follows the tail, exactly as the inline pane does.
`p` (freeze) is respected - but not by bubbling: a `ModalScreen` captures all
input, so `p` never reaches the app's own binding while the reader is on top
(this was checked against the running app, not assumed). The reader takes an
`on_freeze` callback, bound to its own `p`, that calls straight back into
`NmapApp.action_freeze_log`; that method already ends in `_refresh_detail()`,
which is the hook that pushes the now-frozen content back into the reader. One
callback, no duplicated freeze state.

The app already routes `_on_scan_line` to refresh the pane; it will also notify
an open reader. The reader is a modal, so at most one is open; the app holds a
reference while it is up.

### `d` opens, `D` collapses

`d` → `action_open_detail`: render the current row's detail to lines and push the
reader (live mode when the row is a running scan). `D` → the existing
`action_toggle_detail`. Binidng a capital letter is already the app's idiom for a
paired variant (`v`/`V`, `j`/`k` vs `J`/`K`), so `d`/`D` reads naturally. The
hint bar and help say what each does.

### Nothing to read

Opening the reader on a row with no detail (a heading, an empty selection) SHALL
show the same short explanation the pane shows, not an empty modal — the reader
is never a dead end.

## Risks / Trade-offs

- **Rendering a huge record to lines up front** (a /24's worth of one host list,
  or a 20 000-line capped log) → the log is already bounded by `runner.LOG_LIMIT`;
  host records are far smaller. Rendering to lines is O(height), done once per
  open and once per live update, on content the pane already renders.
- **Live update cost** → the same `_on_scan_line` path that already re-renders
  the pane; the reader adds one more render of the same bounded text. The search
  re-scan is a substring pass over the visible set.
- **A second full-screen detail surface** (this and the search session's) → they
  serve different models (arbitrary renderable + live search vs a file pager) and
  the proposal scopes the search session out; the styling matches so they do not
  feel like two apps.
- **Keybinding change** (`d` no longer collapses) → documented as breaking in the
  proposal; `D` keeps the capability, and the help/hint bar name both.
