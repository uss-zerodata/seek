## Context

`NmapApp` (3 200 lines) owns everything today: the model and its publication
(`_publish`, the accumulator), both `Runner`s (asyncio, one run per tool), the
marks (`_marked`), the fold-in of a finished scan (`_on_scan_done` →
`_reread`) and capture (`_on_capture_done` → `_load_captures`), the Scans
history, and the export and scan-flow dialogs. The web interface
(`nmap-web-interface`) reads the model through `ModelSource` and runs uvicorn on
its own thread. The projections (`tui/nmap/views.py`), the filter grammar, the
record builder (`detail.render` → `list[Line]`), `rawlog`, `timeline`, `export`
and `presets` are already Textual-free and pure.

Decisions taken with the user: the browser may start and cancel runs; only a
light same-origin guard, no tokens; launch from `w` and from
`seek nmap serve`; the session shares model, runs and marks, each client keeps
its own position; the frontend must need no installation or build and must
leave room for charts later.

## Goals / Non-Goals

**Goals:**
- One session object with no Textual import, driven by both front ends.
- The browser reaches every TUI feature through the JSON API; every page is a
  template over the same schemas the API returns.
- Nothing is derived twice: lists from `views.py`, records from `detail.render`,
  commands from `presets`, exports from `export`, the history from `timeline`.

**Non-Goals:**
- Live synchronisation of cursor, tab or filter between clients.
- Authentication or remote access. Loopback only, same-origin guard only.
- Charts. The statistics are laid out so an SVG renderer can be added beside
  the table later; none is drawn now.
- Freezing or editing the TUI's `.tcss`/Textual widgets for the web - the web
  has its own templates.

## Decisions

### 1. `nmap/session.py` - the session, extracted from `NmapApp`
```
class Session:
    scans: ScanSet            # replaced, never mutated (as today)
    shots: Captures
    runner: Runner            # nmap
    captures: Runner          # gowitness
    marks: Marks              # insertion-ordered dict[identity, Record]
    def publish(scans) / fold_scan(run) / fold_capture(run)
    def start_scan(request) / start_capture(urls) / cancel(tool)
    def mark(records) / unmark(records) / clear_marks()
    def subscribe() -> Subscription   # events: model, run, line, marks
```
Moved, not rewritten: `_publish`, `_reread`, `_load_captures`,
`_register_disk_capture`, `_scan_history`, the `Scanned` cache and the
`scan_dir` / naming state go with it. `NmapApp` keeps its screens, its
projection worker and its per-client state (stack, marks-of-rows display,
filter, sort, cursor) and subscribes to the session to refresh. The accumulator's
batch cadence and `bulk()` policy stay where they are - the reading worker - and
publish into the session.

*Alternative:* let the web call into `NmapApp`. Rejected: `seek nmap serve` has
no `NmapApp`, and the web would depend on Textual.

### 2. One event loop owns the session; the server runs on it
The web server moves from a thread (the `nmap-web-interface` decision) onto the
session's asyncio loop as a task: `uvicorn.Server.serve()` in the TUI's loop, or
`asyncio.run` of it in `serve`. `Runner` is asyncio and must run on one loop;
running the server there too means a mutating endpoint is an `async def` that
calls the session directly - no `run_coroutine_threadsafe`, no locks around
marks. Rendering stays off the loop: page and list endpoints are plain `def`,
which FastAPI runs in its threadpool, and they read the immutable model as now.

uvicorn's `capture_signals` would take SIGINT from Textual on the main thread, so
the server is a small `uvicorn.Server` subclass with `capture_signals` as a null
context; `serve` handles SIGINT itself.

*Trade-off:* a slow `WebModel` rebuild in the threadpool still competes for the
interpreter - `bulk.responsive()` stays around it.

### 3. Events: an in-process broadcast, Server-Sent Events to the browser
`Session.subscribe()` returns an `asyncio.Queue`-backed subscription; the
session puts small events (`{"type": "line", "run": id, "text": ...}`,
`model`, `run`, `marks`). The TUI subscribes and calls its existing refresh
paths; `/api/v1/events` streams them as SSE. A slow subscriber's queue is
bounded and drops `line` events rather than blocking a run - the browser then
refetches the log tail. SSE over WebSocket: one direction is all that is needed,
it reconnects by itself, and Starlette's `StreamingResponse` serves it with no
dependency.

### 4. Per-client state lives in the URL
Tab, drill-down path, filter, sort, toggles and selected row are query
parameters (`/v/hosts?q=…&sort=2&desc=1&sel=10.0.0.5` and a `path=` of
drill steps). Back is the browser's history; the TUI's "restore filter, sort and
row" rule is simply that each level's URL carries them. No server-side client
state, so two windows are independent by construction.

A drill step is serialised by what the row *is* (`host:10.0.0.5`,
`service:tcp/443/https/nginx/1.25`, `bucket:port/443/tcp`, `stat:<key>`), the
same identity `_Mark.key` uses, so a URL still resolves after the model grows.

### 5. One record renderer, two outputs
`detail.render` keeps producing `list[Line]` of Rich `Text`. A new
`detail_html(lines)` converts each `Text` to HTML by its spans (style → CSS
class from a fixed map of the styles the renderer uses) and each `Line.opens`
to a link. The reader's and pane's content therefore cannot drift from the
browser's - the invariant the TUI already enforces between pane and reader.

### 6. Frontend: server-rendered pages + plain ES modules
No framework, nothing vendored, no build: `static/js/{keys,list,record,events,
dialogs,runs}.js` as ES modules, loaded with `<script type="module">`. Lists
and records are HTML fragments fetched by URL (as the gallery already does);
dialogs (export, scan flow) are `<dialog>` elements posting to the JSON API.
Keyboard handling is one module mapping the TUI's keys to the same actions,
ignoring keys while an input has focus.

For future charts: statistics render as a table plus a `<figure>` slot; an SVG
renderer (server-side, pure Python) can fill it without a JS dependency.

*Alternatives:* Preact + htm vendored - smoother, but a second rendering path
beside Jinja; Vite/TypeScript - rejected, adds a Node toolchain to a uv-only
project.

### 7. The same-origin guard
One middleware: for `POST`/`PUT`/`DELETE`, require `Origin` (or, absent that,
`Referer`) to equal the server's own `http://host:port`; otherwise 403. All
state changes are non-GET. This is the whole protection, as agreed; it stops a
page on another site from driving the API through the user's browser.

### 8. Scan flow in the browser
`/api/v1/scans/presets` lists presets (with `needs_root` derived from flags as
today); `/api/v1/scans/review` takes preset, scope and edited command and
returns what `presets.parse_command` accepts or the reason it refuses;
`POST /api/v1/scans` starts it through `Session.start_scan`, which is exactly
what the TUI's review screen calls. Scope defaults to marks, else the filtered
rows' addresses - the TUI's rule. Privilege: `sudo -n` only; a refusal is the
run's outcome with `elevation_help()`, as in the terminal.

### 9. `seek nmap serve`
Dispatched in `cli.py` before path parsing: `serve` as the first argument
selects it unless a file of that name exists, in which case the CLI explains the
ambiguity. It builds the `Session` from the same `merge.Pending` path as the TUI,
runs the server on the loop, prints the URL, `--open` launches the browser, and
SIGINT cancels live runs and stops the server.

## Risks / Trade-offs

- [Large refactor of `NmapApp`] → Move code, keep names; the existing ~600 viewer
  tests are the regression net; do it first, behind no feature, and land it
  green before any web work.
- [Server on the TUI loop] A blocking call in an `async def` endpoint would
  freeze the TUI → every endpoint that touches the model is sync `def`; only
  mutations (quick) and the SSE stream are `async`. A test asserts no async
  route reads the model.
- [SSE backpressure] → bounded queues, drop `line` events for slow clients, the
  page refetches the tail.
- [Two clients editing marks] → the session is the single writer on one loop;
  last action wins, as with one user pressing `m` twice.
- [Same-origin guard only] A local process can still call the API → accepted by
  the user; the server is loopback-only and runs as the user.
- [Parity drift] New TUI features will not appear in the web by themselves →
  AGENTS.md gains a rule: a viewer feature lands with its API endpoint.

## Migration Plan

1. Extract `Session`; TUI green. 2. Move the server onto the loop. 3. API and
pages per feature. 4. `serve`. `w` and the existing pages keep working at every
step. Archive `nmap-web-interface` before this change so its spec exists.
