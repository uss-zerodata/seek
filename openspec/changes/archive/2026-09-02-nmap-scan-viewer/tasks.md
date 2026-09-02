## 1. Fixtures

- [x] 1.1 Hand-write synthetic fixtures under `tests/fixtures/nmap/`: a basic TCP scan; a host with no hostname and no OS; mixed open/closed/filtered ports; host-level `<hostscript>`; scripts with structured `<table>/<elem>` trees and scripts with free text only; a down host; an empty run; a truncated file; a well-formed XML file that is not nmap output. No real addresses or hostnames.
- [x] 1.2 Derive vulnerability fixtures from the captured `nmap/scans/04-vuln.xml` shape (synthetic content, real structure): a `vuln-*` table keyed by CVE with `title`/`state`/`ids`/`description`/`dates`/`refs`; scripts that ran but found nothing (no tables); the same script reported against two ports of one host; plus a `vulners` cpe table with CVSS, and a script carrying a CVE only in free-text `output`.
- [x] 1.3 Add a dev-only check (not a committed test) that the parser handles the real workspace sample: 256 hosts, 40 ports, 90 scripts, 55 with tables, 255 asserted up vs 9 with evidence.
- [x] 1.4 Add a `-Pn` fixture (targets asserted `up` with reason `user-set`, most with no ports) and a discovery fixture modelled on `01-discovery.xml` (reasons `syn-ack` / `conn-refused`, zero ports).
- [x] 1.5 Add an overlapping pair modelled on `02-ports-a.xml` / `03-services-b.xml`: the same host and port with no product in one file and a product and version in the other, plus ports unique to each file.

## 2. Models and parser

- [x] 2.1 `src/seek/nmap/models.py`: `Vulnerability(id, title, state, severity, ids, refs, disclosed, source_script)` — `severity` only from scripts that actually score, never derived from `state`; `ScriptResult(id, output, data)`, `Service(protocol, port, state, name, product, version, extrainfo, ostype, tunnel, method, conf, scripts, vulnerabilities)`, `Host(address, addrtype, hostnames, state, os, osclass, services, scripts)`, `ScanSet(hosts, sources, failures)`.
- [x] 2.2 `src/seek/nmap/parse.py`: `iterparse`-based reader clearing each finished `<host>`; every attribute optional; validity decided by a `<nmaprun>` root.
- [x] 2.3 Parse `<script>` into `ScriptResult`, converting nested `<table key=…>` / `<elem key=…>` into nested dicts and lists; keep `output` even when tables are present.
- [x] 2.4 Attach `<hostscript>` results to the host and port-level scripts to the service.
- [x] 2.5 Tests: every fixture parses to the expected model; missing hostname/OS yield `None` not errors; truncated and non-nmap files raise a typed parse error; the `<table>` tree round-trips.

## 3. Merging several files

- [x] 3.1 `src/seek/nmap/merge.py`: reconcile hosts on address, union services on `(protocol, port)`, take the first non-empty value for single-valued facts, in the order the files were given.
- [x] 3.1a Record per-host and per-service provenance (which source files it was seen in) and surface it in the detail views.
- [x] 3.1b Accept a directory argument, expanding it to the nmap XML files directly inside it; always route through the merge path even for a single file.
- [x] 3.2 Collect per-file failures into `ScanSet.failures` rather than raising.
- [x] 3.3 Tests: statelessness — no file is created by a run, and two runs over the same inputs are identical; omitting a file removes its contribution; a directory expands to the scans inside it; provenance names the right source files; two files merge to one host with both services; a missing OS is filled from the second file; the same host and port is not duplicated; merging is deterministic in file order; one bad file among three still yields a usable set.

## 4. Vulnerability recogniser

- [x] 4.1 `src/seek/nmap/vulns.py`: recognise the NSE `vuln` library shape — identifier from the **table key**, `title` and `state` from `elem`s, `ids` (prefixed, repeated), `refs`, and `dates > disclosure`.
- [x] 4.2 Lift `vulners` cpe tables into records with id and CVSS severity; de-duplicate records reported against several ports of one host.
- [x] 4.3 Last resort: extract CVE identifiers from free-text `output`, id only, severity left unset.
- [x] 4.4 Never infer a severity the script did not provide; attach records to the service (or host) that carried the script.
- [x] 4.5 Tests: the captured `vuln` shape yields id `CVE-2011-3192`, its title, state `VULNERABLE`, both ids and four refs; a `state` is never surfaced as a severity; scripts that found nothing yield no records; the same finding on two ports is counted once; a scan with no vulnerability scripts yields zero without error.
- [x] 4.6 Dev check against the real `nmap/scans/04-vuln.xml`: 12 scripts, 2 structured, 1 distinct vulnerability.

## 5. Viewer: overviews

- [x] 5.1 `src/seek/tui/nmap/app.py`: a Textual app reusing the existing chrome — status line, hint bar, help overlay, action menu, `keyhints`.
- [x] 5.2 Host view on `DataTable`: address, hostname, OS, service count; absent facts rendered as absent; up and down hosts distinguishable.
- [x] 5.3 Service view on `DataTable`: port, protocol, name, product, version, extra info, vulnerability count, host count; grouped across hosts on `(protocol, port, name, product, version)` as a projection over the model.
- [x] 5.4 A key switches between the two overviews; the active view is shown in the status line.
- [x] 5.5 Tests: both views list the fixture's rows with the right columns; a host with no hostname or OS still appears; down hosts are distinguishable; identical services on many hosts group into one row.

## 6. Filtering and sorting

- [x] 6.1 A filter input per view, building one searchable string per row and matching it with `engine.score.match_spans` so the query grammar is identical to the search session.
- [x] 6.2 Clearing the filter restores every row.
- [x] 6.3 Per-column sort, ascending and descending, toggling on repeat, applied to the filtered set, with the sorted column and direction indicated.
- [x] 6.4 Tests: typing narrows; `'exact` / `^prefix` / `!negate` / AND terms behave as in the search session; clearing restores; sorting reverses on repeat and respects an active filter.

## 7. Drill-down

- [x] 7.1 Host detail: every service on that host with its details, its scripts and its vulnerabilities.
- [x] 7.2 Service detail: every host running that service, each with its own version, extra info and vulnerabilities.
- [x] 7.3 A breadcrumb stack of views; `Esc` unwinds one level per press (clear filter → pop view → quit), matching the search session.
- [x] 7.4 Returning to a view restores its filter and sort.
- [x] 7.5 Tests: host detail lists its services; service detail lists its hosts with per-host specifics; two hosts at different versions each show their own; going back restores filter and sort.

## 8. Entry point and discoverability

- [x] 8.1 `seek nmap [FILES...]` subcommand; add `nmap` to `_KNOWN_SUBCOMMANDS` so the bare-args default still routes to `search`.
- [x] 8.2 Report unparseable files on stderr; exit without opening the viewer when nothing parsed; explain expected usage when no paths are given.
- [x] 8.3 `is_nmap_xml(path)`: extension check first, then read ~4 KB looking for `<nmaprun` with `scanner="nmap"`; memoise per path.
- [x] 8.4 In the search session, when the highlighted result is recognised, show it in the hint bar and add an action that opens the viewer on it.
- [x] 8.5 Tests: the subcommand opens on merged files; a bad file is reported and skipped; no paths prints usage; `is_nmap_xml` accepts the fixtures and rejects ordinary XML; the hint appears only for recognised files.

## 9. `-Pn` and evidence-based reachability

- [x] 9.1 Detect an asserted host state: `-Pn` in `nmaprun@args`, or a host status `reason` of `user-set`. Record it on `ScanSet`.
- [x] 9.2 Compute `Host.evidence` from what the scan found — any port element, any service, any OS match, any script result — and `Host.reachable` from that rather than from the recorded state; keep `state` and `reason` for the detail view.
- [x] 9.3 Default the host overview to the evidence classification; report both counts in the status line whenever they differ.
- [x] 9.4 Filtering by reachability uses the evidence classification.
- [x] 9.5 Tests: a `-Pn` fixture with 10 asserted-up hosts and 2 with ports reports 2 reachable; both counts are surfaced; a fixture scanned *with* discovery (reasons `echo-reply`/`syn-ack`) classifies identically to its recorded state; a host reached by discovery but with no open port still counts as reachable.

## 10. Statistics, grouping and export

- [x] 10.1 Statistics projection over the filtered set: targets, asserted up, evidenced reachable, hosts with open ports; per service name its occurrence count and ports; distinct service count and the distinct open-port set.
- [x] 10.2 Grouping views by service, product and port, ordered by size; services with no detected product are omitted from the product grouping.
- [x] 10.3 Derived-list export from the current filtered view: addresses one per line, distinct open ports comma-separated, `host:port` pairs, HTTP/HTTPS URLs (scheme from `tunnel="ssl"` and known TLS service names; port included when not the scheme default).
- [x] 10.4 Reuse the search session's export destinations — stdout, clipboard, file.
- [x] 10.5 Tests: statistics figures match a hand-computed fixture and follow the filter; each grouping lists the expected members; each export format is byte-exact for a fixture; exports respect an active filter; a non-standard-port HTTP service yields a URL with the port.

## 12. Purpose-built viewer: detail pane and navigation (follow-up)

- [x] 12.1 Remove the search-session integration: the `open_nmap` action, its keybinding, the `results_nmap` hint context, the help and action-menu entries, and the `nmap` `ExitRequest` kind. The search session stays a file search.
- [x] 12.2 `tui/nmap/detail.py`: render the full record for a host, a service and a service group — including script output and complete vulnerability records (id, title, state, severity, cross-reference ids, disclosure date, reference URLs), none of which the table columns can show.
- [x] 12.3 Add a `#detail` pane below the table, separated by a rule; update it on `DataTable.RowHighlighted` and whenever the rows change.
- [x] 12.4 Label an asserted (`-Pn`) host state in the detail rather than only in the table column.
- [x] 12.5 `Ctrl+D` dismisses the pane; drop it automatically on a short terminal. `App.on_resize` is never dispatched (Resize goes to the Screen), so poll instead.
- [x] 12.6 List navigation for long scans: arrows, `PageUp`/`PageDown`, `Ctrl+Home`/`Ctrl+End`. `Home`/`End` stay with the filter text.
- [x] 12.7 Reset the selection to the first row when a filter changes the row set, so the detail always matches.
- [x] 12.8 Tests: the detail follows the cursor; vulnerability and script detail are visible without navigating away; an asserted state is labelled; the pane dismisses and auto-drops; paging and jumping work; filtering resets the selection.

## 13. Testing feedback (follow-up)

- [x] 13.1 The table holds focus so the row cursor renders; `/` opens the filter and `Enter`/`Esc` leaves it. Style `datatable--cursor` as reverse video so selection reads regardless of theme.
- [x] 13.2 Move every action to a bare key: terminals claim `Ctrl+S` (XOFF), `Alt`+digit (tab switching) and `Tab` (focus traversal). `v` swap, `r` reverse, `s` stats, `b` group, `u` reachable, `d` detail, `x` export, `/` filter, `?` help, `q` quit.
- [x] 13.3 Fix `_key_at`: it stringified structured sort keys, so `10.10.10.11` sorted before `10.10.10.2`. Compare numbers, tuples and strings in separate buckets.
- [x] 13.4 Separate choosing a sort column from reversing: `1`–`9` always sort ascending, `r` alone reverses. Name the sorted column and direction in the status line as well as the header.
- [x] 13.5 Highlight the characters the filter matched, per cell, so the user can see why a row survived.
- [x] 13.6 Re-lay the detail pane as a report: labelled values for scalars, bulleted lists for services, scripts and vulnerabilities; pair related scalars onto shared lines so the lists have room.
- [x] 13.7 Add a help overlay (`?`) covering the keys and the filter syntax.
- [x] 13.8 Tests: focus and cursor; numeric IP ordering; column choice vs reverse; sorted column named in the status; matched characters highlighted; no binding uses a terminal-claimed key; report uses labels and bullets.

## 14. Style, layout and range filtering (follow-up)

- [x] 14.1 Match the search session's conventions: thin `border-bottom` rules instead of a `border-top`/`$warning` mix, no filled backgrounds, and the theme's `match` style for filter highlighting.
- [x] 14.2 Budget column widths to the terminal and clip cells with an ellipsis; never overflow horizontally. Re-budget on resize, preserving the selection.
- [x] 14.3 Make the detail pane a scrollable region; `J`/`K` scroll it, and moving to another row returns it to the top.
- [x] 14.4 `nmap/filtering.py`: treat a CIDR token as an address range, compose it with the fuzzy query, support negation, and leave a bare address as a fuzzy term. Show the resolved range in the status line.
- [x] 14.5 Give every row the addresses a range term tests against, so CIDR filtering works in the service, grouping and detail views too.
- [x] 14.6 Fix the startup race: build the view immediately and re-budget after first layout, so a keypress in the first frames is not swallowed by a rebuild that resets the cursor.
- [x] 14.7 Tests: rules not fills; no overflow at 56/80/120/160 columns; cells clipped to their column; the report scrolls and resets per row; CIDR membership, composition, negation, IPv6, and a bare address staying fuzzy.

## 15. Titles and arrow-key roles (follow-up)

- [x] 15.1 Add a `#title` line above each table naming the view and carrying the breadcrumb, which previously only appeared in the status line at the bottom. The status line now carries the corpus size, row count and sort.
- [x] 15.2 Subclass `DataTable` as `ScanTable` and rebind ←/→ to scroll the detail; `DataTable` uses them for a column cursor, which does nothing in row mode. Binding on the widget rather than the app keeps ←/→ editing text inside the filter.
- [x] 15.3 Keep ↑/↓ (and `j`/`k`) on the selection; `J`/`K` remain as an alias for scrolling the detail.
- [x] 15.4 Update the help overlay and README; mention CIDR filtering in the help.
- [x] 15.5 Tests: every view is titled; the title carries the breadcrumb; columns are headed and the sorted one marked; ←/→ scroll the detail; ↑/↓ move the selection; ←  still edits text in the filter.

## 16. Exact addresses and tabbed overviews (follow-up)

- [x] 16.1 Treat a complete address as its own single-host network (`10.10.10.5` = `10.10.10.5/32`), IPv4 and IPv6. An incomplete or invalid address stays a fuzzy term, so typing towards an address still matches while unfinished.
- [x] 16.2 Flip the two tests that encoded the previous "a bare address stays fuzzy" rule, and cover the partial/invalid/negated/composed cases.
- [x] 16.3 Present the overviews as a `Tabs` row — Hosts, Services, Statistics, By service, By product, By port — clickable and keyboard-driven; `v`/`V` cycle, `s`/`b`/`u` jump.
- [x] 16.4 A tab replaces the view stack, since a drill-down belongs to the overview it came from. `Esc` unwinds to the first tab before quitting.
- [x] 16.5 Spend the title row only when there is a path to show; hide the warning row when there is nothing to warn about.
- [x] 16.6 Tests: tab labels and active marking; `v`/`V` cycling; direct keys; activation returns focus to the list; a tab drops a drill-down; `Esc` returns to the first tab; the title row appears only when drilled in.

## 17. Table chrome colouring (follow-up)

- [x] 17.1 Remove the filled background from `datatable--header`: Textual fills it with `$primary`, which is raw ANSI bright blue behind default-coloured text. Carry the colour in the text (bold cyan) instead.
- [x] 17.2 Fix `datatable--cursor`: its own grey-on-black plus `reverse` cancelled to something arbitrary. Transparent background and default colour, so `reverse` inverts predictably.
- [x] 17.3 Mark the active tab with the accent colour rather than a fill, and keep it distinct from the header colour.
- [x] 17.4 Tests: no component of the table chrome is drawn on a fill; the header carries its own colour and the selection inverts; the active tab differs from an inactive one without a fill.
- [x] 17.5 Note the trap in AGENTS.md — this is the second widget whose default fill had to be undone.

## 18. Command palette (follow-up)

- [x] 18.1 `tui/nmap/commands.py`: a `Provider` exposing every action — overviews, tab cycling, reachable-only, drill in, back, first/last/page, detail scroll and toggle, reverse, filter, export, help, quit — each with a description naming its key.
- [x] 18.2 Build the sort entries from the active view's columns, so the palette offers the columns actually on screen.
- [x] 18.3 Register it via `COMMANDS = App.COMMANDS | {ScanCommands}`, keeping the system provider. `Ctrl+P` is free in the viewer.
- [x] 18.4 Mention the palette in the help overlay, the hint bar and the README.
- [x] 18.5 Tests: the provider is registered; `Ctrl+P` opens it; every bound action has an entry; sort entries follow the overview; every entry has help text; running overview, sort and navigation commands has the right effect; entries are listed before anything is typed.

## 19. Digging down without going back (testing feedback)

- [x] 19.1 Sort port columns on the number: the `by port` grouping keyed its rows on the label, so `443/tcp` came before `80/tcp`. The label still shows, the key is the integer.
- [x] 19.2 `Row.drill` — what `Enter` opens, when that is not the record the detail pane is reporting on. Lets a row describe a service and open the host behind it.
- [x] 19.3 The hosts behind a grouping row open into that host's full record (its own view kind, so the hint bar says so), instead of `Enter` doing nothing at the second level.
- [x] 19.4 A service inside a host record opens as that service across the whole set (`views.group_for`), closing the loop host → service → hosts → host. A port open nowhere is in no overview row, so it falls back to every host reporting the port.
- [x] 19.5 The per-service lines of the statistics view open the hosts behind the count.
- [x] 19.6 `_Mark`: `Esc` restores the row a drill-down was opened from and the sort the list was left in — by row identity, falling back to position. Clearing the filter with `Esc` keeps the selected row too.
- [x] 19.7 Fix `preserve`: `DataTable.clear()` resets the cursor to (0, 0), so the resize path read back the zero it had just written and dropped the selection to the top.
- [x] 19.8 Tests: numeric port order and its reverse; grouping → host; host service → the service everywhere; the closed-port fallback; a statistics line; `Esc` restoring row and sort; `Esc` clearing a filter.
- [x] 19.9 Spec: drilling continues from wherever the user is; ports sort numerically; the selection survives going back.

## 11. Finalisation

- [x] 11.1 `uv run ruff check` clean.
- [x] 11.2 `uv run pytest -q` green.
- [x] 11.3 Verify against the real workspace sample (dev check from 1.3); confirm parse time and memory are acceptable for a 1.4 MB file.
- [x] 11.4 Update README (the `nmap` subcommand, the two views, keys) and AGENTS.md (the `nmap/` package layout, the parse/merge invariants, why the recogniser is separate from the generic script model).
- [x] 11.5 Confirm the `nmap/` sample stays gitignored (it is, via `.gitignore:12`) from the repo or confirm with the user whether it should stay; ensure no real scan data is committed.
- [x] 11.6 `openspec validate nmap-scan-viewer --strict` passes.
