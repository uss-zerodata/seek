## 1. Dependencies and package skeleton

- [x] 1.1 `uv add fastapi uvicorn jinja2` and `uv add --dev httpx`; `uv lock --check` passes
- [x] 1.2 Create `src/seek/web/` with `__init__.py`, `app.py` (`create_app(source)` and the `ROUTERS` list), empty `api/v1/`, `pages/`, `templates/`, `static/`
- [x] 1.3 Build the wheel (`uv build`) and confirm `templates/` and `static/` are inside it

## 2. Capture model: provenance and every capture

- [x] 2.1 Add `Capture.database: Path | None`, set by `results.read_database`
- [x] 2.2 Keep every capture in `Captures` in insertion order (`all()`), guarded by a lock with `add`; the newest-wins URL index and everything the TUI reads stay unchanged
- [x] 2.3 Move `detail._service_urls` to `seek.nmap.export.service_urls`; the TUI detail pane calls the moved function
- [x] 2.4 Tests: two databases with the same URL both appear in `all()` with their database; `get(url)` still returns the newest; pane output unchanged

## 3. Model source and indexes

- [x] 3.1 `web/source.py`: `ModelSource` protocol and `WebModel` - hosts by address, captures by web id (sha1 of database, URL, time), captures by `(address, protocol, port)` via `service_urls`
- [x] 3.2 Cache `WebModel` on the identity of the `ScanSet` plus a capture generation counter; rebuild only when either changes
- [x] 3.3 `NmapApp` implements `ModelSource` (bumps the generation when captures are read)
- [x] 3.4 Tests: ids are stable across snapshots of the same model; a new `ScanSet` or a new capture rebuilds; a host with web servers on two ports maps each port to its own capture

## 4. Query layer and schemas

- [x] 4.1 `web/schemas.py`: pydantic models for host (summary and full), service, service-across-hosts, capture (summary and full), error body
- [x] 4.2 `web/query.py`: list hosts / services / captures from the TUI projections (`hosts_view`, `services_view`, `service_detail`), filtered with `filtering.parse_filter`/`matches`, sorted by `Row.sort_key`, paginated (`limit`, `offset`, `total`)
- [x] 4.3 Tests: a query string gives the same rows as the TUI tab with the same filter; services come out in port order; pagination totals are right

## 5. JSON API v1

- [x] 5.1 `api/v1/hosts.py`: `GET /api/v1/hosts`, `GET /api/v1/hosts/{address}` (ports, services, names, vulnerabilities, captures per port)
- [x] 5.2 `api/v1/services.py`: `GET /api/v1/services`, `GET /api/v1/services/{protocol}/{port}` with filters for name/product/version - the hosts running it, each with its capture
- [x] 5.3 `api/v1/captures.py`: `GET /api/v1/captures` (filterable, with database), `GET /api/v1/captures/{id}` (every recorded field)
- [x] 5.4 Unknown address, service or id answers 404 with a JSON body naming what was not found
- [x] 5.5 Tests with `TestClient` over the fixtures and a fake capture database

## 6. Screenshots

- [x] 6.1 `web/media.py`: `GET /media/shot/{capture_id}` returns the capture's file with the right content type; 404 for an unknown id or a missing file; no route takes a path
- [x] 6.2 Tests: served by id; `../../etc/passwd` and encoded variants are 404 and read nothing; a deleted file is 404 and the gallery page still renders

## 7. Pages

- [x] 7.1 `templates/base.html` (navigation: Gallery, Hosts, Services; filter box), `static/app.css` (light/dark via `prefers-color-scheme`, system fonts), `static/app.js` (debounced filter that swaps the list fragment)
- [x] 7.2 Gallery `/`: thumbnails (`loading="lazy"`) with URL, status, title, database; failed captures shown with their reason and no image; links to capture, host and port
- [x] 7.3 Hosts `/hosts` and host page `/hosts/{address}`: ports and services with each port's screenshots beside it; "nothing captured" when none
- [x] 7.4 Services `/services` and `/services/{protocol}/{port}`: hosts running it with each one's screenshot
- [x] 7.5 Capture page `/captures/{id}`: full-size screenshot and every recorded field
- [x] 7.6 List pages accept `q`, `limit`, `offset`, and `fragment=1` for the filtered list alone
- [x] 7.7 Tests: each page renders from the fixtures; no page references a host other than the server itself (scan the HTML for `http(s)://` in `src`/`href` of assets)

## 8. Server supervision

- [x] 8.1 `web/server.py` `WebServer`: refuse non-loopback hosts; probe the port and report "in use" with the setting name; run `uvicorn.Server` on a daemon thread; `stop()` sets `should_exit` and joins with a timeout; `running`, `url`
- [x] 8.2 `url_for(row)`: host → host page, service group → service page, exactly one capture → capture page, anything else → gallery
- [x] 8.3 Import FastAPI/uvicorn lazily on first start only
- [x] 8.4 Tests: start on an ephemeral port, fetch `/api/v1/hosts`, stop, port free again; `0.0.0.0` refused; occupied port reported

## 9. Viewer integration

- [x] 9.1 `Config.web_host` (`127.0.0.1`) and `Config.web_port` (`7272`) with validation and range; regenerate only those lines of `config.example.toml` (it carries hand edits)
- [x] 9.2 `w` binding and `action_open_web`: start or reuse, open the browser at `url_for(current row)`; errors as notifications
- [x] 9.3 Status bar `◉ web http://…` while running; palette entry "Open the web interface"; help overlay line; hint bars where space allows
- [x] 9.4 `on_unmount` stops the web server; the quit guard does not ask about it
- [x] 9.5 Tests: `w` starts once and reuses; URL follows the selected row; quitting stops it and frees the port; `W` still starts gowitness's server independently

## 10. Documentation and checks

- [x] 10.1 README: the web interface, its key, pages, API, loopback-only binding, the new dependencies
- [x] 10.2 AGENTS.md: the `seek/web` layout, the `ModelSource` seam, the reuse of TUI projections and filter grammar, id-not-path media, lazy import
- [x] 10.3 Measure one gallery and one host-list request against the 24 200-host benchmark corpus with the TUI open; record the numbers in the design
- [x] 10.4 `uv run ruff check`, `uv run pytest -q`, `openspec validate nmap-web-interface --strict`

## 11. Several captures, and a sortable gallery

- [x] 11.1 `query.SORTS`: address, host name, port, HTTP status, URL, title, time taken, database; unknown values last in both directions; `desc`
- [x] 11.2 Gallery and `/api/v1/captures` narrow by `address`, `protocol`, `port`; the API refuses an unknown sort with 422, the page falls back to the default
- [x] 11.3 `CaptureSummary.siblings`; a card whose service has several captures links to all of them; the "next" link keeps sort and scope
- [x] 11.4 Gallery controls: sort select and direction, submitted as a plain GET and swapped in place by `app.js`; a line saying what the list is narrowed to, with a way back to everything
- [x] 11.5 `i` with several captures offers "all N side by side in the web interface" first; `gallery_path_for(row)` narrows to the row's host and/or port
- [x] 11.6 Tests for every sort, failures last, numeric order, narrowing, sibling links, paging, the 422, and the `i` choice; help and README
