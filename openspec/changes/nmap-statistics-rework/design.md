## Context

See proposal.md — Why. What matters for the approach is how the viewer is built:

- One screen, one `DataTable`, one filter, one breadcrumb. A view is data — a
  column spec plus `build(scans) -> list[Row]` — and `NmapApp` knows nothing
  about which view it is showing (`tui/nmap/views.py`, `tui/nmap/app.py`).
- Every rebuild runs `_narrow`: filter the rows, then
  `rows.sort(key=lambda r: _key_at(r, col), reverse=self._sort_desc)`. There is
  exactly one sort, applied to the whole row list, and `_reset_sort` hardcodes
  column 0 ascending. That single global sort is what scrambles the statistics
  tab today: its metric rows and its service lines are sorted together, by their
  first column, alphabetically.
- `Row` already carries what the app needs per row: `cells`, filter `text`,
  `target`, `sort_key`, `host`, `addresses`, and `drill` (what `Enter` opens
  when that is not the row's own record).
- `statistics()` in `nmap/views.py` returns a `Statistics` dataclass; the tab
  turns it into rows. Ports appear only as `open_ports`, rendered as
  `", ".join(st.open_ports[:10])` in one detail cell.
- The scan set is small and re-projected on every rebuild (parsing 1.4 MB takes
  ~11 ms); nothing is cached and nothing is persisted.

## Goals / Non-Goals

**Goals:**

- Sections are a property of the *row list*, so the one sort and the one filter
  keep working unchanged for every other view.
- The statistics tab drills like everything else — `action_drill` gains
  destinations, not a special case for one view.
- A view can say what order it opens in.

**Non-Goals:**

- Collapsible sections, or a tree widget. The table stays flat; a heading is a
  row.
- Multi-column sorting.
- Sections in any other view. The mechanism is general, but only the statistics
  view uses it here.
- Per-section column widths. Columns are budgeted once for the whole table, as
  now, so a section's cells live in the same three columns as every other.

## Decisions

### Sections are rows, ranked by a key the existing sort respects

`Row` gains `section: str` (the heading it belongs to), `section_rank: int`
(fixed order between sections) and `heading: bool`. `_key_at` is left alone;
`_narrow` sorts by `(row.section_rank, 0 if row.heading else 1, _key_at(row, col))`
with `reverse` applied only to the last element.

- A heading sorts to the top of its own section, whatever the column and
  whichever direction — the spec forbids a heading drifting into the middle of
  its lines or a section interleaving with another.
- Rows of every other view carry the defaults (`rank 0`, not a heading), so
  their key is unchanged and no other view can regress.

*Alternative rejected:* build the section order in `statistics_view` and have
`_narrow` skip sorting for `kind == "stats"`. That special-cases the app on a
view kind — the thing the view-as-data design exists to avoid — and it would
make the statistics tab the one list the user cannot sort at all.

*Alternative rejected:* one `DataTable` per section. Three tables mean three
cursors, three filters and a scroll container; the whole screen is built around
there being exactly one list.

Reversing needs care: `reverse=True` on the whole tuple would also reverse the
section order. `_narrow` therefore sorts on a key whose leading elements are
already direction-independent — negating the rank, or sorting in two passes
(stable sort by the column first, then by `(rank, heading)`), whichever reads
more clearly at implementation time. The two-pass form is the safer default:
Python's sort is stable, so a stable sort by the column key followed by a stable
sort by `(rank, heading)` gives exactly the required order with no negation
tricks and no dependence on the column key's type.

### Empty sections are dropped after filtering, not before

Headings carry no filter `text`, so a filter would drop every heading and leave
bare lines. After filtering, `_narrow` removes a heading whose section has no
surviving line. This is one pass over the row list, in the same place the filter
already runs.

### A view declares the order it opens in

`View` gains `default_sort: tuple[int, bool] = (0, False)`; `_reset_sort` reads
it instead of hardcoding `(0, False)`. The statistics view declares the count
column, descending — "how often does this occur" is the question the tab
answers. Every other view keeps today's behaviour by taking the default.

### The statistics view's shape

Three sections, in this order, over the same (filtered) host set as today:

| Section | Lines | Detail column |
| --- | --- | --- |
| Coverage | targets, asserted up, reachable (evidence), with open ports, distinct services, distinct open ports | the existing notes (`-Pn: assumed`, the overstatement warning) |
| Services | one per service name, with its occurrence count | the ports it was seen on |
| Ports | one per open port, with the number of hosts exposing it | the services seen on it |

Columns become `("Statistic", "Count", "Detail")`; the count column holds a
number so it sorts numerically (`_key_at` already buckets ints away from
strings). The per-port breakdown is new data, so `Statistics` gains
`ports: list[tuple[str, int, list[str]]]` — label, host count, service names —
built in the same pass that already counts services. `open_ports` stays: it is
the cheap "distinct open ports" total and is used elsewhere.

*Alternative rejected:* keeping "distinct open ports" as a comma list in a
detail cell and adding no port lines. It is exactly what the feedback calls
unstructured, and it truncates at ten.

### Headings are styled, not spelled

`Row` gains `style: str = ""`; `_fill` applies it to the row's cells when set.
A heading is `("Coverage", "", "")` in bold accent, not `"── COVERAGE ──"`
padding characters, because the table clips cells to a budgeted width and any
drawn rule would be clipped with them. The existing filter-match highlighting
still applies on top for non-heading rows.

### Drill destinations come from the row, through the machinery that exists

`action_drill` already opens whatever `row.drill or row.target` is, dispatching
on type. The statistics rows set `drill` to an object that dispatch already
understands, so `action_drill` gains one branch, not six:

| Line | `drill` |
| --- | --- |
| a coverage count | a host-list view over that subset |
| distinct services / distinct open ports | the grouping view for that key |
| a service line | a `Grouping(key="service", …)` (already how it works) |
| a port line | a `Grouping(key="port", …)` |
| a heading | `None` — opens nothing |

Two new things are needed: `views.host_list(title, hosts, subtitle)` for an
arbitrary subset of hosts (factored out of `hosts_view`, which becomes a caller
of it), and permission for a `View` to be a drill target so the aggregate lines
can push a grouping overview. A `View` is already what `action_drill` builds, so
"the row hands over a ready-made view" is the smallest addition: if `drill` is a
`View`, push it.

*Alternative rejected:* aggregate lines switching to the matching tab. It is
what the tab bar suggests, but it discards the stack, so `Esc` would not come
back to the statistics view — and the spec asks for a drill-down that returns
with the line still selected. Pushing keeps `Enter` digging and `Esc` unwinding,
which is the model the rest of the viewer just settled on.

### Clicking a column heading sorts by it

`DataTable` posts `HeaderSelected` on a header click; the app does not handle it
today, so headers look interactive (they are numbered and marked with the sort
arrow) and are not. `on_data_table_header_selected` maps the column key — the
column index, already stored as the key — to `action_sort(index)`. Clicking a
row is already wired: the first click moves the cursor, a click on the selected
row posts `RowSelected`, which drills.

## Risks / Trade-offs

- **The sort key grows a two-pass form** → every other view sorts with
  `section_rank == 0` and `heading == False`, so the second pass is a stable
  no-op for them; a test asserts an existing view's order is unchanged.
- **A section heading is a row, so counts in the status line include it** →
  the status line reports "rows"; headings are rows on screen. Exclude headings
  from the count so "12 rows" means twelve statistics.
- **Filter highlighting on a styled heading** → headings never match the
  filter (no `text`), so the two never apply to the same row.
- **`Enter` on a coverage line can open a very large host list** (a /24 scan's
  "targets" line) → it is the same list the Hosts tab already renders for the
  same set; no new cost.
- **This change's spec deltas modify requirements that live in the unarchived
  `nmap-scan-viewer` change**, not in `openspec/specs/` → archive
  `nmap-scan-viewer` first, or archive this one after it; archiving this change
  against a capability that does not exist yet would strand the deltas.
- **Scope drift into an OS or findings section** → the proposal excludes both;
  the section mechanism is what makes them cheap to add later.
