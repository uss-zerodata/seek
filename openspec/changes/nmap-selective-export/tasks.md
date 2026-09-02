## 1. The pure exporter

- [x] 1.1 New `src/seek/nmap/export.py` with `Record` — a `(host, service | None)` pair with an `identity()` of `(address,)` or `(address, protocol, port)` — and no Textual import.
- [x] 1.2 `FIELDS`: an ordered catalogue of `(name, accessor)` over a record, covering address, hostname, os, state, reachable, sources, port, protocol, port label, service, product, version, extrainfo, tunnel, vulnerability count and url. Every accessor returns a string, empty when the fact is absent.
- [x] 1.3 Writers `to_text`, `to_csv`, `to_json` over `(records, field names)`: text is one space-separated line per record; CSV has a header row and quotes what needs it (`csv` module); JSON is a list of objects keyed by field name. All three drop a row identical to one already written, preserving order.
- [x] 1.4 Move the five presets into `export.py` over records: hosts with open ports, all hosts, the comma-separated port list, `host:port`, HTTP/HTTPS URLs. A preset that names hosts names each host once.
- [x] 1.5 `nmap/views.py`: drop `EXPORTS` and the `export_*` functions, re-exporting from `export.py` only if something outside the viewer still imports them (check first — nothing should).
- [x] 1.6 Tests in a new `tests/test_nmap_export.py`: the five presets produce byte-identical output to today's for the same hosts; field selection writes the catalogue's order regardless of pick order; CSV header and quoting; JSON parses to a list of objects; duplicate rows collapse in all three formats; a record with no service exports empty service fields rather than failing.

## 2. Rows say what they stand for

- [x] 2.1 `tui/nmap/views.py`: `Row.records: tuple[Record, ...]`, filled by each builder — a host row its host; a service row (host, service); a service-group, grouping or statistics line every pair in it; a heading none.
- [x] 2.2 Check every builder: hosts, host_list, services, host_detail, service_detail, grouping, grouping_detail, statistics. A row with a `target` that stands for records must not be left empty.
- [x] 2.3 Tests: every row of every view either carries records or is a heading; a bucket row's records match its members.

## 3. Marks

- [x] 3.1 `app.py`: `_marked: dict[key, Record]`, insertion-ordered, keyed by record identity so it survives every rebuild.
- [x] 3.2 `action_mark` (`m`): mark all of the current row's records, or unmark them when all are already marked. `action_clear_marks` (`M`): drop every mark. Both refresh the list and the status line.
- [x] 3.3 `_fill` / `_column_widths`: a leading two-cell column showing `●` when every record of the row is marked, `◐` when only some are, empty otherwise — outside `View.columns`, so the numbered sort columns keep their indices.
- [x] 3.4 `_refresh_status`: "N marked" while any mark exists, in the search session's style.
- [x] 3.5 Tests: a mark survives filtering, sorting, drilling down, coming back and switching tabs; marking a service-group row marks every pair in it; marking a fully marked row unmarks it; a heading marks nothing; `M` clears; the marker column does not shift which column `1`…`9` sort.

## 4. The export flow

- [x] 4.1 `MultiChoiceScreen` in `tui/menu.py` over `SelectionList`: a titled multi-select returning the chosen ids in catalogue order, `Esc` cancelling.
- [x] 4.2 `app.py` `_do_export`: records are the marked ones when any exist, else the records of the rows on screen; the first modal's prompt names the source and its size.
- [x] 4.3 Offer the five presets plus `custom…`; `custom…` opens the field picker.
- [x] 4.4 Offer JSON / CSV / text, and suggest the matching extension in the file prompt. A preset whose shape is fixed (the comma-separated port list) says that the format does not apply rather than silently ignoring it.
- [x] 4.5 Keep the existing destinations (clipboard, file) and their messages.
- [x] 4.6 Tests: an export with marks uses them and ignores the filter; with no marks it uses the filtered rows; the source is stated in the prompt; a custom field export reaches the clipboard as CSV with a header; cancelling any step writes nothing.

## 5. Say so

- [x] 5.1 `tui/nmap/help.py`: `m` marks, `M` clears, and what an export acts on.
- [x] 5.2 `tui/nmap/commands.py`: palette entries for mark, clear marks and export, each naming its key.
- [x] 5.3 `_HINTS`: `m` in every list-shaped view.
- [x] 5.4 README: marking across views, the field picker, the three formats, and the two worked examples from the feedback (an up-host list for `nmap -iL`, a URL list for gowitness).
- [x] 5.5 AGENTS.md: marks are keyed by record identity because every view is rebuilt on every keystroke; `export.py` is pure so a later runner can reuse it.

## 6. Finalisation

- [x] 6.1 `uv run ruff check` clean.
- [x] 6.2 `uv run pytest -q` green.
- [x] 6.3 `openspec validate nmap-selective-export --strict` passes.
- [x] 6.4 Walked both examples end to end against a 250-host synthetic scan (the gitignored real `nmap/` sample is not in this workspace): `u` → export all hosts → 206 lines for `nmap -iL`; marking the four web service buckets → 200 marked → URLs file; and a custom six-field CSV of one port bucket, 50 rows plus a header.
