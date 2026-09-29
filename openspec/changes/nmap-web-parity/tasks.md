## 0. Prerequisite

- [x] 0.1 Archive `nmap-web-interface` (`/opsx:archive`) so its spec is in `openspec/specs/`

## 1. The session core

- [x] 1.1 `src/seek/nmap/session.py`: `Session` with `scans`, `shots`, both `Runner`s, `Marks`, `scan_dir`/naming, the `Scanned` and history caches; no Textual import
- [x] 1.2 Move `_publish`, `_reread`, `_load_captures`, `_register_disk_capture`, `_scan_history`, `_resolve_marks` into it; `NmapApp` delegates, keeping names where tests reach them
- [x] 1.3 `Session.start_scan(request)`, `start_capture(urls)`, `cancel(tool)`, refusing a second run per tool with what is running
- [x] 1.4 `Session.mark / unmark / clear_marks`; `NmapApp._marked` reads the session
- [x] 1.5 `Session.subscribe()`: bounded queues; events `model`, `run`, `line`, `marks`; `line` dropped for a full queue
- [x] 1.6 `NmapApp` subscribes and refreshes status, marks, Scans tab and the model through its existing paths
- [x] 1.7 Full test suite green with no behaviour change; add session unit tests (fold-in, one run per tool, marks, events)

## 2. The server on the session's loop

- [x] 2.1 `WebServer` runs `uvicorn.Server.serve()` as a task on the running loop; subclass with null `capture_signals`; stop by `should_exit` and awaiting the task
- [x] 2.2 `ModelSource` becomes the `Session`; `CachedSource` keyed as today
- [x] 2.3 Same-origin middleware for non-GET requests; tests for foreign, missing and own origin
- [x] 2.4 Test: no `async def` route touches the model (inspect the routes)
- [x] 2.5 Existing web tests green

## 3. Overviews, drill-down and back

- [x] 3.1 `/api/v1/views/{tab}` and `/v/{tab}` for hosts, services, stats, three groupings, names, scans - columns, rows, default sort from `views.py`
- [x] 3.2 Drill steps serialised by row identity; `path=` resolves a chain; the marked tab follows `View.tab`
- [x] 3.3 `q`, `sort`, `desc`, `up`, `ports`, `open` parameters; the same rows as the TUI for a corpus of filters (reuse `test_nmap_query` cases)
- [x] 3.4 Pages: tab bar, list fragment, back via history; each level's URL carries its filter, sort and `sel`
- [x] 3.5 Tests: statistics and groupings match the TUI row for row; back restores a level

## 4. Records, raw output, search

- [x] 4.1 `detail_html(lines)`: Rich spans to CSS classes, `Line.opens` to links; the style map covers every style `detail.py` uses (test fails on an unmapped style)
- [x] 4.2 `/api/v1/records/{step}` and the record panel; full-page record (`d`)
- [x] 4.3 `/api/v1/raw?...` from `rawlog` with the same cache; previous/next scan of the subject
- [x] 4.4 In-page search with count and next/previous
- [x] 4.5 Tests: record text equals the reader's plain text for hosts, services, buckets, captures; raw stepping

## 5. Marks and export

- [x] 5.1 `POST/DELETE /api/v1/marks` by row identity; `GET` lists them in order
- [x] 5.2 Mark column and count in lists; `m`/`M`
- [x] 5.3 `/api/v1/export` over `export.EXPORTS`, fields and formats; download or text
- [x] 5.4 Export dialog (`<dialog>`), from marks else the filtered rows
- [x] 5.5 Tests: exports byte-identical to the TUI's for the same selection; marks shared both ways

## 6. Scans tab and live runs

- [x] 6.1 History and live-run rows from `timeline` and the session's runners
- [x] 6.2 `/api/v1/events` SSE; `events.js` subscribes, reconnects, and says when the server is gone
- [x] 6.3 Run log view: stream, follow unless scrolled away, freeze (view only), cancel, report modes
- [x] 6.4 Tests: SSE delivers lines of a stub run; cancel from the API is recorded as cancelled in both front ends

## 7. Starting scans and captures

- [x] 7.1 `/api/v1/scans/presets`, `/api/v1/scans/review`, `POST /api/v1/scans` over `presets` and `Session.start_scan`
- [x] 7.2 Scan dialog: preset, scope (marks else filtered), editable command, review with root marker
- [x] 7.3 `POST /api/v1/captures/runs` and the capture dialog; gowitness absence shown as a disabled choice with its reason
- [x] 7.4 Tests with the stub nmap: same argv as the TUI; refused metacharacter; `sudo -n` refusal text; second run refused

## 8. Keyboard

- [x] 8.1 `keys.js`: j/k/↑↓, h/l/←→, Enter, staged Esc, /, digits, v/V, m/M, x, d, ?, g/G; ignored in inputs
- [x] 8.2 Help overlay generated from the same key table
- [x] 8.3 A browser-free test of the key table's coverage against the TUI bindings (every TUI viewer binding has a web entry or is listed as terminal-only)

## 9. `seek nmap serve`

- [x] 9.1 CLI dispatch with the `serve`-is-a-directory ambiguity message
- [x] 9.2 Build the session from paths, run the server on the loop, print the URL, `--open`
- [x] 9.3 SIGINT cancels live runs, says which, stops the server
- [x] 9.4 Tests: serve a fixture directory on an ephemeral port and fetch hosts; ambiguity; interrupt during a stub scan

## 10. TUI integration and docs

- [x] 10.1 Quit guard and status bar count browser-started runs; marks from the browser appear on rows
- [x] 10.2 README: the web front end's features, keys, `seek nmap serve`
- [x] 10.3 AGENTS.md: the session, the loop rule, URL-carried client state, the parity rule (a viewer feature lands with its API)
- [x] 10.4 `uv run ruff check`, `uv run pytest -q`, `openspec validate nmap-web-parity --strict`

## 11. Everything linked, screenshots where they are named

- [x] 11.1 `detail.Line.to`: the record says what a line is about - a host, a `(host, service)`, a capture - without the terminal changing
- [x] 11.2 `web/links.py`: one place for where a host, a port, a service and a capture live; records, lists, gallery and capture pages link through it
- [x] 11.3 Record lines link; a capture's thumbnail follows the lines about it, once
- [x] 11.4 List rows carry up to three thumbnails and `+N` (to the gallery narrowed to the row)
- [x] 11.5 On a host's port list the port selects its record; `everywhere →` keeps the drill to the service on every host
- [x] 11.6 The first version's `/hosts`, `/services` pages redirect to the tabs; `w` opens the same places
- [x] 11.7 The capture page links host, port and every capture of the port; long list cells are cut with the value in a tooltip
- [x] 11.8 Tests: redirects, row thumbnails, the port record's link and single thumbnail, the host record's port links, `w`'s targets
