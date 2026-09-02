## 1. The reader

- [x] 1.1 `src/seek/tui/nmap/reader.py`: `DetailReader(ModalScreen)` built from a title and a list of text lines, full-screen, scrolling like a pager (arrows, `j`/`k`, `g`/`G`, `PgUp`/`PgDn`, `Ctrl`+`U`/`D`), `Esc`/`q` to dismiss — matching the search session's `DetailScreen` chrome.
- [x] 1.2 A helper that renders a Rich renderable to text lines at a given width, so the reader shows byte-for-byte what the inline pane shows.
- [x] 1.3 In-view search: `/` focuses a one-line input; a term highlights every occurrence in place (case-insensitive substring); `n`/`N` move a current-match cursor in reading order and scroll it into view; the header shows the match count or "no matches"; `Esc` in the box clears the term and keeps the reader open.
- [x] 1.4 A row with no detail shows the same short note the inline pane shows, never an empty modal.
- [x] 1.5 Tests in `tests/test_nmap_reader.py`: match counting and next/previous ordering; case-insensitivity; the no-match message; clearing a search; scrolling; the empty-detail note. (Pure-ish logic tested via the screen with `run_test`.)

## 2. Live scans

- [x] 2.1 The reader accepts a live source: opened on a running scan, it re-renders from the run's current lines when handed new output, re-applies the active search, and follows the tail unless the user has scrolled up.
- [x] 2.2 A frozen log (`p`) freezes the reader too; the header says the scan is still running, never contradicting the inline pane.
- [x] 2.3 Tests: opening on a running stub scan updates as lines arrive; an active search keeps matching new lines; freezing stops the tail and says so.

## 3. Wiring d / D

- [x] 3.1 `app.py`: `d` → `action_open_detail` (render the current row's detail to lines and push the reader; live mode when the row is a running scan); `D` → the existing `action_toggle_detail`.
- [x] 3.2 `_on_scan_line` notifies an open reader with the run's current lines.
- [x] 3.3 The reader shows whatever the row shows: host, service, grouping, statistics line, and a scan's report in its current mode (`o` still cycles the mode from the list; reopening reflects it).
- [x] 3.4 Tests: `d` opens the reader on a host record and on a scan's raw report; `D` collapses and restores the inline pane; `d` works while the inline pane is hidden.

## 4. Say so

- [x] 4.1 `help.py`: `d` opens the detail full-screen and is searchable; `D` shows/hides the inline pane.
- [x] 4.2 `commands.py`: palette entries for open-detail and toggle-pane, each naming its key; keep scroll entries.
- [x] 4.3 `_HINTS`: `d` "detail" across the list views; note `D` where the pane hint was.
- [x] 4.4 README and AGENTS.md: the full-screen searchable reader, and that it streams a running scan.

## 5. Finalisation

- [x] 5.1 `uv run ruff check` clean.
- [x] 5.2 `uv run pytest -q` green.
- [x] 5.3 `openspec validate nmap-detail-view --strict` passes.
- [x] 5.4 Check by hand against `test_scans`: open a scan's raw output full-screen, search for a port, jump matches; open a host record and search a service; open on a running scan and watch it stream.

## 6. Testing feedback

- [x] 6.1 Fix `g`/`G` moving the list instead of the reader: the app's `home,g` /
  `end,G` bindings are `priority=True`, which is checked before the screen and so
  pierced every modal (the help and scan dialogs too, not just the reader).
  `NmapApp.check_action` declines `jump` while a modal is on the stack, so the key
  reaches the modal rather than being swallowed.
- [x] 6.2 `←`/`→` (and `h`/`l`) in the reader read the previous/next entry of the
  list: the list moves with it, the entry is read from its top, the ends clamp,
  and an active search is carried over and recounted.
- [x] 6.3 Tests: the reader's own `g`/`G` win over the list; `g`/`G` no longer leak
  through the help screen; the list's own `g`/`G` still work; stepping moves both
  reader and list, clamps at the ends, keeps a search, and leaves on the entry
  last read.
- [x] 6.4 Say so: help, palette, footer hint, README. Correct the AGENTS.md note
  that claimed a modal captures *all* input - `priority=True` bindings pierce it.
