## 1. The port breakdown in the model

- [x] 1.1 `nmap/views.py`: `Statistics` gains `ports: list[tuple[str, int, list[str]]]` — port label, number of hosts exposing it, service names seen on it.
- [x] 1.2 Fill it in the pass that already counts services in `statistics()`: count *hosts* per port (not occurrences — a host cannot expose the same port twice, but say so in the field's name), collect the service names, order by host count descending then port number.
- [x] 1.3 Keep `open_ports` — it is the "distinct open ports" total and has other callers.
- [x] 1.4 Tests in `tests/test_nmap_views.py`: the port breakdown over `basic` and over a merged set; a port exposed by two hosts counts two; the services list names every distinct service seen on that port; the breakdown follows the host subset it is given.

## 2. Sections in the row model

- [x] 2.1 `tui/nmap/views.py`: `Row` gains `section: str`, `section_rank: int`, `heading: bool` and `style: str`, all defaulting to today's behaviour.
- [x] 2.2 `View` gains `default_sort: tuple[int, bool] = (0, False)`.
- [x] 2.3 `app.py` `_reset_sort`: take the column and direction from `self.view.default_sort`.
- [x] 2.4 `app.py` `_narrow`: sort in two stable passes — by the chosen column with `reverse`, then by `(section_rank, 0 if heading else 1)` — so a heading stays at the top of its section and sections never interleave, in either direction.
- [x] 2.5 `app.py` `_narrow`: after filtering, drop a heading whose section has no surviving line.
- [x] 2.6 `app.py` `_fill`: apply `row.style` to the row's cells; leave the filter-match highlighting for rows that have filter text.
- [x] 2.7 `app.py` `_refresh_status`: count only non-heading rows, so "12 rows" means twelve statistics.
- [x] 2.8 Tests: an existing view's order is byte-for-byte unchanged (the section machinery is a no-op with the defaults); reversing a sectioned view keeps the section order and the headings on top.

## 3. The statistics view rebuilt

- [x] 3.1 `tui/nmap/views.py` `statistics_view()`: three sections — Coverage, Services, Ports — each opened by a heading row (`("<name>", "", "")`, bold accent, no filter text, no target).
- [x] 3.2 Coverage lines: targets, asserted up, reachable (evidence), with open ports, distinct services, distinct open ports — keeping today's notes in the detail column (`-Pn: assumed`, the overstatement wording).
- [x] 3.3 Services lines: one per service name, occurrence count as a number, the ports it was seen on in the detail column.
- [x] 3.4 Ports lines: one per open port from `Statistics.ports`, host count as a number, the services seen on it in the detail column. The port's own sort key is its number, not its label.
- [x] 3.5 Columns become `("Statistic", "Count", "Detail")`; `default_sort` is the count column, descending.
- [x] 3.6 Drop the blank spacer row and the `", ".join(st.open_ports[:10])` detail cell — both are replaced by the sections.
- [x] 3.7 Tests in `tests/test_nmap_viewer.py`: the three headings appear in order; the coverage figures still report asserted and evidenced separately; every distinct open port has a line; the tab opens ordered by count, not alphabetically; a filter that leaves no service line removes the Services heading; a filter that leaves nothing leaves an empty table without crashing.

## 4. Every line opens what it counts

- [x] 4.1 `tui/nmap/views.py`: `host_list(title, hosts, subtitle="")` building the host columns for an arbitrary subset; `hosts_view` becomes a caller of it.
- [x] 4.2 `app.py` `action_drill`: a `View` handed over as `drill` is pushed as-is, so a row can name its own destination.
- [x] 4.3 Coverage lines set `drill` to a `host_list` over that subset — all targets, asserted up, evidenced reachable, hosts with open ports — each with a title that names what it is.
- [x] 4.4 The distinct-services and distinct-open-ports lines set `drill` to `grouping_view("service")` / `grouping_view("port")`.
- [x] 4.5 Port lines set `drill` to a `Grouping(key="port", …)`, as service lines already do for `key="service"`.
- [x] 4.6 Heading rows open nothing (no `target`, no `drill`), and the detail pane below shows the section heading rather than going blank.
- [x] 4.7 Tests: each kind of line opens the right thing (a coverage figure → exactly those hosts; a total → the grouping; a service line → its hosts; a port line → the hosts exposing it); `Esc` returns to the statistics view with the same line selected; `Enter` on a heading does nothing.

## 5. Clicking

- [x] 5.1 `app.py`: `on_data_table_header_selected` → `action_sort(column index)`, so a column heading sorts by that column.
- [x] 5.2 Tests: a header click sorts by that column, and the column marker follows; a second click does not reverse (choosing a column always sorts ascending, `r` reverses).

## 6. Say so

- [x] 6.1 `tui/nmap/help.py`: the statistics tab is navigable (`↵` opens the hosts behind a figure) and column headings can be clicked.
- [x] 6.2 `tui/nmap/commands.py`: the Statistics palette entry's description matches what the tab now shows.
- [x] 6.3 `app.py` `_HINTS["stats"]`: sorting and reversing are available in the statistics tab now that it has ordered sections.
- [x] 6.4 README: the statistics tab's sections and that its figures open.

## 8. The tab row follows the drill-down (testing feedback)

- [x] 8.1 `View.tab`: the tab whose subject a view shows. Overviews and the drill-downs that land on another overview's subject claim one; a single host's record claims none, so it keeps the tab it was opened from.
- [x] 8.2 `app.py` `_sync_tab`: mark the topmost view in the stack that claims a tab, after a push and after a pop. `_active_tab` is set before the widget, so `on_tabs_tab_activated` stays a no-op and only a tab the user selects replaces the stack.
- [x] 8.3 Tests: a service opened from a host record marks the services tab and keeps the three-level path; going back restores the tab; a statistics total marks the grouping tab; a host opened from a grouping keeps the grouping's tab; selecting a tab still replaces the drill-down.
- [x] 8.4 Spec: the marked tab follows the list on screen, without a drill-down becoming a tab or the path being discarded.
- [x] 8.5 README, help and AGENTS.md: the tab row follows the drill-down.

## 7. Finalisation

- [x] 7.1 `uv run ruff check` clean.
- [x] 7.2 `uv run pytest -q` green.
- [x] 7.3 `openspec validate nmap-statistics-rework --strict` passes.
- [x] 7.4 Checked against a **250-host synthetic scan** (12 services, ~2.5 open ports per host) rather than the real sample — the gitignored `nmap/` directory is not present in this workspace. 32 rows in three sections, readable at 120x40; `statistics_view().rows` costs 3.8 ms, against 1.3 ms for the host list.
- [x] 7.5 AGENTS.md: note that a heading row is a row, and that the section rank leads the sort key — the next person to touch `_narrow` needs to know.
