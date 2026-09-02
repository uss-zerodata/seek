## Context

See proposal.md — Why. What shapes the approach:

- `nmap/views.py` holds `EXPORTS: {name: (label, f(list[Host]) -> str)}`. Every
  recipe takes hosts, so the service a row stood for is lost before the writer
  ever sees it. `NmapApp._visible_hosts` reconstructs a host list from the rows
  on screen by looking at `Row.target` and unwrapping groups.
- A `Row` already knows what it stands for: `target` (a `Host`, a `Service` with
  `Row.host` beside it, a `ServiceGroup`, a `Grouping`, or nothing) and `drill`.
  The statistics view's lines carry a `Grouping` as their target.
- The export flow is a chain of `push_screen_wait` modals from `tui/menu.py`
  (`ChoiceScreen`, `PromptScreen`) in a `@work(exclusive=True, group="modal")`
  worker.
- The search session already has marks (`ResultsList.marked`, a set of
  `identity()` tuples, `Tab` / `Shift+Tab`, "N marked" in the status line). The
  viewer has none, and its bindings are all bare keys — `Tab` is focus traversal
  and the viewer's README says nothing uses it.
- The viewer is stateless between runs and its views are rebuilt from the model
  on every filter keystroke, sort, resize and tab switch.

## Goals / Non-Goals

**Goals:**

- One place that knows how to turn records into text, importable without
  Textual, so a later "run the next tool" feature reuses it whole.
- Marks that cannot go stale: a rebuild happens on every keystroke, so a mark
  must not be a row index or a row object.
- The export source is never ambiguous.

**Non-Goals:**

- Running any external tool. The boundary is built for it; the feature is not.
- Persisting marks between runs — the viewer stays stateless.
- Marking in the search session, or unifying the two marked-set implementations.
- A general query language for fields. The catalogue is a fixed list.

## Decisions

### A record is `(host, service | None)`

Everything downstream — presets, field accessors, dedup — takes a list of these.
`Host` alone cannot express "443/tcp on 10.0.0.5", which is the half of the
feature the current exporter cannot do at all; `Service` alone cannot express
its host, and services carry no back-reference.

This is also the shape the rows already have (`Row.target` + `Row.host`), so the
UI side is a mapping, not a translation. `Row` gains one method's worth of
meaning — *the records this row stands for* — implemented as a field
`records: tuple[Record, ...]` filled at build time, because the row builders
already have both halves in hand and the alternative is `isinstance` unwrapping
at every use site.

*Alternative rejected:* keep exports host-based and add a parallel
service-export path. Two code paths that must agree on filtering, dedup and
destinations, to avoid one dataclass.

### Marks are keyed by identity, held by the app

`NmapApp._marked: dict[key, Record]`, keyed by `(address, None)` for a host and
`(address, protocol, port)` for a service — the same identity a merge uses, so
the key survives every rebuild and is stable across views showing the same
underlying record from different angles. A `dict` rather than a `set` keeps the
`Record` itself for export without re-finding it in the model, and keeps
insertion order, which becomes the export order.

Two rules follow from marking *records* rather than rows:

- A row marks all of its records; if all of them are already marked, it unmarks
  them. Anything else makes a bucket row's mark state unrepresentable.
- A host is a different record from that host's service. Marking `10.0.0.5` and
  marking `443/tcp on 10.0.0.5` are different intentions — the first exports one
  host, the second exports a service — so both may be marked at once, and a
  preset that names hosts collapses them (see below).

*Alternative rejected:* storing marks per view. The whole point is that the
interesting set spans views.

### Marks are shown in a leading column

`_fill` prepends a two-cell column carrying `●` for a marked row, outside
`View.columns` so the numbered, sortable columns keep their indices and their
`1…9` keys. `_column_widths` budgets it first.

*Alternative rejected:* colouring the whole row instead. The cursor is already
`reverse` and the filter highlight is already a colour; a third colour on the
same text is not reliably distinguishable, and the spec requires the cursor and
a mark to be tellable apart.

A row is marked when *all* of its records are marked; a partially marked bucket
shows a different glyph (`◐`), because "this row is marked" would be a lie and
showing nothing would hide the marks entirely.

### The export flow

`x` opens: source line → recipe → (fields, when `custom…`) → format → destination
→ path. Concretely:

1. Records = the marked records if any, else the records of the rows on screen.
   The first modal's prompt states which and how many, which is where the
   "Both" selection model earns its keep.
2. Recipe: the existing five presets, plus `custom…`.
3. `custom…` opens a multi-select of the field catalogue — a new
   `MultiChoiceScreen` in `tui/menu.py` over Textual's `SelectionList`, which is
   the only new widget the change needs.
4. Format: JSON / CSV / text. Presets that are inherently one-per-line (the
   comma-separated port list) ignore the choice and say so rather than
   pretending; the field-picked export honours it.
5. Destination and path as today, with the extension suggested by the format.

### The field catalogue is a list of named accessors

`FIELDS: list[tuple[str, Callable[[Record], str]]]` in `export.py` — order in
that list *is* column order, so two exports of the same fields line up. Every
accessor returns a string (empty when absent) so the three writers need no type
handling and CSV/JSON/text cannot disagree about `None`.

Dedup is by the rendered row, applied in all three formats: with fields
`address` alone, five marked services on one host are one line — and one JSON
object. A duplicate row carries no information in any of the three.

### `export.py` is pure

No Textual import, no `ScanSet`: it takes records and returns a string. The
viewer supplies records; a future runner supplies the same records and reads
back argv instead of text. This is the modularity the feature asks for, and it
is worth stating that it is only that: no tool is invoked here.

## Risks / Trade-offs

- **Marks and the current view disagree** (marks exist but the user is looking
  elsewhere and expects the screen to be exported) → the status line shows
  "N marked" whenever any exist and the export's first modal names the source
  and its size; `M` clears in one keystroke.
- **A leading column shifts every view's layout by two cells** → budgeted in
  `_column_widths` before the trim loop, so the widest column absorbs it; the
  column is empty when nothing is marked in that view... but it is always
  present, which keeps the layout from jumping as marks come and go.
- **`m` and `M` are two more bare keys** in a viewer that has nearly run out —
  they are free today, and `Tab`/`Shift+Tab` (the search session's choice) are
  unavailable here. Documented in the help overlay and the palette.
- **Marking a large bucket marks hundreds of records** → the count in the status
  line makes it obvious, and `M` undoes it.
- **`EXPORTS` changes shape** → it is internal to the viewer; a test asserts the
  five presets still produce byte-identical output for the same hosts.
- **This change's deltas modify requirements amended by `nmap-statistics-rework`**
  → archive order is `nmap-scan-viewer`, then `nmap-statistics-rework`, then
  this one.
