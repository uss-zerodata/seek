## Context

The nmap viewer (`seek.tui.nmap.app.NmapApp`) already holds everything the web
interface needs: `self.scans`, an immutable `ScanSet` snapshot that is only ever
*replaced* (`_publish`), and `self.shots`, a `Captures` read from every gowitness
database found by `gowitness/locate.py`. The views the TUI shows are pure
projections in `seek.tui.nmap.views` (`hosts_view`, `services_view`, ...) with no
Textual import; `seek.nmap.filtering` is the filter grammar; `detail._service_urls`
is how a service is matched to its captures. So the web interface is a second
*consumer* of an existing model, not a second loader.

Two gaps in the capture model matter here: a `Capture` does not record which
database it came from, and `Captures` keeps only the newest capture per URL
(`_by_url`), so the same URL captured from two databases is one entry.

## Goals / Non-Goals

**Goals:**
- One process, one model: the web interface sees exactly what the TUI sees, live.
- A layered package where a new page or API resource is a new module registered
  in one place, not an edit through the stack.
- The same projections and the same filter grammar as the TUI, so a list in the
  browser and the same tab in the terminal cannot disagree.

**Non-Goals:**
- Any write path: starting scans or captures, marking, exporting from the web.
  The layering leaves room for them; this change adds none.
- A standalone `seek web` command without the TUI. The model source is an
  interface precisely so that can be added later, but it is not added now.
- Authentication. The interface binds to loopback only (see spec); multi-user or
  remote access is a later change with its own threat model.
- Thumbnail generation. Browsers scale the originals; no imaging dependency.

## Decisions

### 1. In-process server on a thread, not a subprocess
`uvicorn.Server` runs in a daemon thread started by the viewer; stopping sets
`server.should_exit` and joins with a timeout.

*Why:* a subprocess would have to re-read every scan and database - the very
work, and the very divergence, this change exists to avoid - and could not see a
capture that finishes in the TUI. *Alternative considered:* subprocess fed a
pickled snapshot on each change; rejected as copying an engagement-sized model
on every batch.

*Thread safety:* the web thread only ever reads. `self.scans` is replaced
atomically, never mutated after publication (the accumulator's `_private` rule),
so reading the reference and walking it is safe. `Captures` is appended to on
the event loop, so the source hands out a snapshot built under a lock (below).

### 2. A `ModelSource` protocol between the TUI and the web package
```
class ModelSource(Protocol):
    def snapshot(self) -> WebModel: ...
```
`NmapApp` implements it; `seek.web` never imports Textual or the app.
`WebModel` is built from `(scans, captures)` and cached by the identity of the
`ScanSet` plus a capture generation counter, so it is rebuilt only when the TUI
publishes a new model or reads a new database - not per request. It holds the
indexes every route needs: hosts by address, captures by id, and captures by
`(address, protocol, port)` computed once through the shared URL-matching
function.

*Why:* the seam that makes a future standalone server (or tests) possible
without a TUI, and the one place concurrency is handled.

### 3. Package layout - routers registered in one list
```
src/seek/web/
  __init__.py
  source.py        ModelSource, WebModel (indexes, capture ids)
  schemas.py       pydantic response models: HostOut, ServiceOut, CaptureOut ...
  query.py         list + filter + sort + paginate over TUI view projections
  api/v1/          hosts.py, services.py, captures.py   (JSON routers)
  pages/           gallery.py, hosts.py, services.py, captures.py (HTML routers)
  media.py         screenshot route
  templates/       base.html + one per page + _fragments for filtered lists
  static/          app.css, app.js (vanilla, no CDN, no framework)
  app.py           create_app(source) -> FastAPI; ROUTERS list
  server.py        WebServer: loopback check, port probe, start/stop, url_for(row)
```
Pages and API call the same `query.py` functions and render the same schemas -
the API returns them as JSON, the pages hand them to templates. Adding a
resource is a schema, a query function and a router appended to `ROUTERS`.

### 4. Reuse the TUI's projections and filter grammar
Lists are built from `vdefs.hosts_view().rows(scans)`, `services_view()`,
`service_detail(...)` and filtered with `filtering.parse_filter` /
`filtering.matches` over `Row.text`, `Row.addresses` and `Row.records` - the
exact path `NmapApp._narrow` takes. Sorting uses `Row.sort_key` (so ports sort
numerically, as fixed in the TUI). *Alternative:* re-deriving lists from the
model in the web package; rejected because two derivations drift - the
invariant AGENTS.md already enforces between the pane and the reader.

`detail._service_urls` moves to a pure module (`seek.nmap.export`, next to
`service_url` / `url_for`) so both consumers match services to captures the same
way.

### 5. Capture identity and provenance
`Capture` gains `database: Path | None`, set by `read_database`. `Captures`
keeps every capture in insertion order (`all()`) in addition to the newest-wins
URL index the TUI uses, so the TUI's behaviour is unchanged and the gallery can
show both captures of a URL taken from two databases. A capture's web id is
`sha1(f"{database}\0{url}\0{probed_at}")[:12]` - stable while the model is,
independent of gowitness's per-database `row_id`, and not a path.

### 6. Server-rendered pages, server-side filtering
Jinja2 templates; `app.js` debounces the filter box and fetches the list
fragment (`GET /hosts?q=...&fragment=1`), replacing the list in place. Filtering
therefore uses the TUI grammar on the server and scales to 24 000 hosts with
pagination (`limit`/`offset`, default 200 rows, "more" link), which a
client-side filter over a fully rendered list would not. Images use
`loading="lazy"`. *Alternative:* htmx - it would do the fragment swap
declaratively, but the whole need is ~40 lines of `fetch`, and vendoring a
library for it is the dependency cost AGENTS.md asks to justify.

Styling: one stylesheet with `prefers-color-scheme` light/dark, system fonts.

### 7. Screenshots are addressed by capture id
`GET /media/shot/{capture_id}` looks the capture up in `WebModel` and returns
`FileResponse(capture.shot)` only if that path is a file. There is no route
taking a path, so traversal has nothing to act on. Content type from the suffix
(`.jpeg`/`.png`).

### 8. Launch from the viewer
`w` (bare, like every viewer action; `W` stays gowitness's report server) and a
palette entry. `WebServer.url_for(row)` maps the selected row: host →
`/hosts/{address}`, service group → `/services/{proto}/{port}?...`, a record
with exactly one capture → `/captures/{id}`, else `/`. The browser is opened
with the existing `actions.opener_argv`. The status bar shows `◉ web
http://127.0.0.1:PORT` while running; `on_unmount` stops it next to
`_stop_report_server`, and the quit guard does not ask (nothing is lost).

Binding: `Config.web_host` (default `127.0.0.1`) and `Config.web_port` (default
`7272`, beside gowitness's `7171`). Non-loopback hosts are refused by checking
`ipaddress.ip_address(host).is_loopback` (or `localhost`). The port is probed
with a bind before the thread starts, so "in use" is reported synchronously
instead of from a dying thread.

### 9. Dependencies
Runtime: `fastapi`, `uvicorn` (plain, not `[standard]` - no uvloop/httptools
needed for a local single-user server), `jinja2`. Dev: `httpx` for
`fastapi.testclient.TestClient`. Hatchling already ships everything under
`src/seek`, templates and static files included - verified in the wheel by a
task.

## Risks / Trade-offs

- [The collector pause] Web requests allocate on another thread while the TUI
  may be inside `bulk()` with collection suspended → requests are small and
  short; the frozen model is not re-scanned. Measure one gallery render at the
  24 200-host benchmark corpus.
- [GIL contention with the TUI] A large page render competes with the event loop
  → pagination caps a response; `WebModel` indexes are built once per model, not
  per request.
- [Captures mutated during snapshot] `Captures` is appended on the event loop
  while the web thread snapshots → a lock around `add` and the snapshot copy of
  its list; the rest of `WebModel` is derived from immutable data.
- [Import cost at startup] FastAPI/pydantic import is ~150 ms → imported lazily
  on first `w`, never on `seek` or `seek nmap` startup.
- [Port collision with a second viewer] Two viewers want the same port → the
  second is told the port is in use and which setting to change.
- [Wheel size / dependency weight] Three runtime deps added to a project that
  keeps them minimal → the user asked for one unified application; recorded in
  README's dependency note.

## Migration Plan

Additive. No stored state, no format changes. `W` is untouched. Rollback is
removing the `w` binding and the package.

## Measured

On the 24 200-host benchmark corpus (`benchmarks/gen_nmap_corpus.py`, 120 files)
with one capture per web service - 95 015 captures:

| request                        | time   | size   |
|--------------------------------|--------|--------|
| `WebModel` build (once per model change) | 2.9 s | - |
| `/` gallery, first 200         | 137 ms | 105 KB |
| `/hosts`                       | 36 ms  | 57 KB  |
| `/services`                    | 158 ms | 8 KB   |
| `/api/v1/hosts?limit=200`      | 28 ms  | 49 KB  |
| `/?q=8443` over every capture  | 563 ms | 106 KB |
| `/hosts?q=open:443`            | 72 ms  | 57 KB  |
| `/hosts/{address}`             | 3 ms   | 5 KB   |

The build was 3.9 s before `canonical_url` gained a regex fast path for the plain
`scheme://host[:port]` shape every service URL has (411 501 calls through
`urlsplit`); it runs under `bulk.responsive()` so the viewer keeps its turns.
Two findings from implementation, both fixed with tests: an exact filter term
(`'8080`) fell back to a subsequence match in the scorer - so the TUI filter had
the same bug - and the fast path had to lowercase the scheme, as `urlsplit` does.
