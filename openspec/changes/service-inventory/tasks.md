## 1. Model and parsing

- [x] 1.1 Add `Service.cpes` and `Host.os_matches` (`OsMatch(name, accuracy, cpes)`) to `nmap/models.py`; copy them in `Service.copy`/`Host.copy`
- [x] 1.2 Read `<service><cpe>` and every `<osmatch>` (with its `<osclass><cpe>`) in `nmap/parse.py`; keep `Host.os`/`osclass` unchanged
- [x] 1.3 In `merge._merge_service`, let `cpes` override together with a `probed` identification and union them otherwise; take `os_matches` from the same scan as `os` (never unioned: interleaved guesses lose "best first")
- [x] 1.4 Add synthetic fixtures in `tests/fixtures/nmap/`: a probed service with CPE, a CPE without a version, OS matches across kernel lines, `http-server-header` with two tokens, `fingerprint-strings` with SSH/FTP/SMTP banners and HTTP headers, `smb-os-discovery`, `vulners`, and an `http-vuln-*` advisory naming a product (no real addresses)
- [x] 1.5 Tests: parsing and the merge override for CPEs; `benchmarks/check_nmap_real.py` still passes

## 2. CPE and alias table

- [x] 2.1 Create `nmap/cpe.py`: parse a CPE 2.2 URI, format 2.2 and 2.3 (with 2.3 escaping), and fill in a version
- [x] 2.2 Add `ALIASES` (`Product(key, display, kind, vendor, product)`), keyed by casefolded spellings and by nmap `vendor:product`; cover every product in `test_scans/` plus common web/SSH/mail/SMB/database/proxy software (63 entries; vendor:product names from NVD naming conventions, NOT yet verified live against the NVD dictionary - do that before the lookup change relies on them)
- [x] 2.3 Add `lookup(name_or_cpe) -> Product | None` and the fallback key for unmapped names
- [x] 2.4 Tests: round-trips 2.2↔2.3, escaping, version fill, alias unification (`Nginx`/`nginx`/`igor_sysoev:nginx` → one key), table shape (unique keys, valid parts)

## 3. Recognisers and reconciliation

- [x] 3.1 Create `nmap/inventory.py` with `Observation`, `Component`, `Inventory` (`by_service`, `by_host`, `unplaced`) and the source ranks
- [x] 3.2 `from_nmap_service`: probed services only; product/version/CPEs; `method="table"` yields nothing
- [x] 3.3 `from_os`: best OS match with its CPEs, and no single version when its CPEs disagree; `smb-os-discovery` OS and LAN manager at rank 1
- [x] 3.4 `parse_product_tokens` (RFC 7231 product tokens, comments dropped) and the script recognisers: `http-server-header`, `http-generator`, anchored header lines in `fingerprint-strings`, SSH/FTP/SMTP greetings (`fingerprint-strings`, `banner`), `vulners` CPE keys
- [x] 3.5 Reconciliation: group by scope and product key, version from the best rank, refinement rule, the `conflicting` flag, the CPE from nmap or else the alias table (`cpe_origin`)
- [x] 3.6 `build(hosts, captures_by_service, report=None)` over open services only, reporting progress with `progress.counted`
- [x] 3.7 Tests for every scenario in the spec's recogniser and reconciliation requirements, including "advisory text is not software", "a refinement is not a conflict" and "different products on one port stay apart"

## 4. Captures

- [x] 4.1 `gowitness/results.py`: read `<meta name="generator">` from the first 64 KiB of `html` into `Capture.generator`, only if the column exists
- [x] 4.2 `from_capture`: technologies (split `Name:version` on the last colon when a version follows), `Server`/`X-Powered-By`/`X-AspNet-Version`/`X-Generator` case-insensitively, generator; nothing from failed captures and nothing from the page title
- [x] 4.3 Make `Session.captures_by_service` also count unplaced captures; add `Session.inventory(report=None)`, cached on `(id(scans), shots.generation)`
- [x] 4.4 Add a synthetic gowitness database fixture with versioned and unversioned technologies, a `X-Powered-By` header, a generator meta tag, a capture by host name, a failed capture and an unplaceable URL; tests for the join, the count and caching

## 5. Terminal viewer

- [x] 5.1 `tui/nmap/views.py`: `inventory_view` (`reports=True`, one row per product+version, columns product/version/kind/CPE/hosts/services/confidence/conflict, row text including sources, `Row.records` = the running services/hosts); drill-down to the services list
- [x] 5.2 Add `("inventory", "Inventory")` to `tabs.TABS` after `group-port` (the grouping tabs stay together) and route it in `tab_view`
- [x] 5.3 `tui/nmap/detail.py`: a `_software_block` in `service_detail` and `host_detail` (components, CPE or "no CPE", conflict marker, dim observation lines); pass `session.inventory()` through `record.record_lines`
- [x] 5.4 Update the help overlay and hint bar with the Inventory tab and the `U` action
- [x] 5.5 TUI tests: the tab lists rows, the drill-down and going back, filter by source, sort by conflict, the Software block in the pane and in the reader

## 6. Export and web

- [x] 6.1 `nmap/export.py`: `inventory_entries(records, inventory)` and `render_inventory(entries, fmt)` for CSV and JSON (`schema`, `version: 1`, `generated_from`, `unplaced_captures`, `entries`); `produce` takes an optional `inventory`; add the `"inventory"` recipe to `EXPORTS`
- [x] 6.2 Offer the inventory recipe in the export dialog with CSV/JSON, acting on marks or on the view like other recipes
- [x] 6.3 `web/schemas.py` + `web/api/v1/inventory.py` (plain `def`, registered in `ROUTERS`): `GET /api/v1/inventory` returns the same document as the JSON export
- [x] 6.4 Web: the Inventory tab, its drill-down, the Software block (through `web/record.py`, by style), and the export recipe; add the tab key and `U` to `keys.js`
- [x] 6.5 Tests: pin the version 1 JSON field set; API equals the export; `test_every_terminal_key_has_a_browser_key` and `test_every_overview_lists_what_the_terminal_lists` cover the new tab; `test_no_route_on_the_loop_reads_the_model` still passes

## 7. Scan unversioned

- [x] 7.1 `presets.py`: the version-gaps argument constant (`-vv -T4 -n -Pn -sV --version-all --script banner,http-server-header,http-generator -p{ports}`) and its output-name stem
- [x] 7.2 `Session.draft_version_gaps(records)`: targets with unversioned open ports, union of ports (`T:`/`U:` groups, adding `-sU` when UDP is involved), note with the extra pair count, and a `ScanError` when nothing is unversioned or nmap is unavailable
- [x] 7.3 Terminal: bind `U` (plus a command palette entry) to open the draft in the existing scope/command/review flow; show it as unavailable with the reason when nmap is missing
- [x] 7.4 Web: the matching endpoint (async, calls the session) and the `U` key
- [x] 7.5 Tests with a stub nmap: the spec's "scan only what is missing" and "nothing to do" scenarios, the extra-pair note, UDP handling, and a finished run showing its versions in the inventory

## 8. Performance and finish

- [x] 8.1 Build the inventory in the projection worker under `bulk()`; add the inventory to `benchmarks/bench_nmap.py`'s pipeline split and record the 24 200-host figure in its docstring (target < 1 s)
- [x] 8.2 Add the inventory to `AGENTS.md` (a Layout entry and an invariant: session projection, alias-table-only CPEs, observations never discarded)
- [x] 8.3 Update `README.md` with the Inventory tab, the export and the `U` action
- [x] 8.4 `uv run ruff check`, `uv run pytest -q`, `openspec validate service-inventory --strict`

## 9. Captures that went missing (after real use)

- [x] 9.1 Place a capture by host and port when its URL is not one the record builds (nmap named the port something other than http) - any address or name the host is known by, its open TCP port
- [x] 9.2 Name the captures that still match nothing, in the Inventory tab's subtitle (`Session.unplaced_captures`)
- [x] 9.3 Versions only captures detected are separate components per version (`inventory.split_detected`); refinements stay together; nmap against a capture is still a conflict
- [x] 9.4 Tests: jQuery 3.4.1 on an `smtp`-named port, by host name, closed/unknown stays unplaced, 2.1.3 + 3.4.1 on one port, the subtitle
