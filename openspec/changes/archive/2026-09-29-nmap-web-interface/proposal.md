## Why

Screenshots of an engagement's web servers come from more than one gowitness
database - the capture this viewer runs, captures run by hand, captures from
other directories passed on the command line - and gowitness's own report server
can serve only one database at a time. The viewer already reads all of them
into one model, merged with the nmap scans, but a terminal cannot show an image,
so the only way to look at the pictures together with the hosts and ports they
belong to is to open them one by one. A browser can; this change gives the
viewer a web interface of its own that shows exactly what the viewer knows.

It is also the first step towards a browser front end that could eventually do
everything the nmap TUI does, so it is built as an application with a stable
data interface and room to grow, not as a one-off gallery page.

## What Changes

- A web interface, built on FastAPI and shipped in the `seek` package itself
  (no extra install step), serving the viewer's model on a loopback address:
  - a **screenshot gallery** of every capture from every database found,
    filterable, each linked to the host and port it shows;
  - a **host list** and a **host page** with the host's ports, services and the
    screenshots of each;
  - a **service/port view** listing services across hosts, each with its
    screenshots;
  - a **capture page** with the full-size screenshot and everything the capture
    recorded (status, title, redirects, headers, cookies, console log,
    technologies, TLS names).
- A versioned JSON API (`/api/v1/...`) that every page is built from, so a later
  richer front end - or another tool - uses the same data without scraping HTML.
- Pages are rendered on the server with templates and a small vendored script
  for in-page filtering; nothing is loaded from the internet, so it works
  offline on an engagement network.
- Launched from inside `seek nmap` with a new key (`w`) and from the command
  palette: starts the server on first use, opens the browser at the page for
  the selected row, and is stopped when the viewer exits. The status bar says
  when it is running and where.
- The server reads the viewer's live model: scans and captures that finish
  while it is open appear on the next page load.
- Screenshots are served only when the model references them - by capture, not
  by path - so the server exposes no other file on disk.
- New configuration: the address and port the web interface binds to.
- `W` keeps starting gowitness's own report server; the two coexist.
- New runtime dependencies: `fastapi`, `uvicorn`, `jinja2`.

## Capabilities

### New Capabilities
- `nmap-web-interface`: the browser interface over the viewer's model - the
  API, the gallery, host, service and capture pages, how screenshots are served,
  how it is started and stopped, and its loopback-only binding.

### Modified Capabilities
- `nmap-scan-viewer`: a new action opens the web interface at the selected row;
  it is reachable by key and by name, its state is shown in the status bar, and
  quitting stops it.
- `configuration`: the web interface's bind address and port are overridable
  settings.

## Impact

- New package `src/seek/web/` (application factory, API routers, page routers,
  templates, static assets, server supervision).
- `src/seek/tui/nmap/app.py`: the `w` action, status bar indicator, shutdown in
  `on_unmount`; `commands.py`, `help.py` and the hint bars list it.
- `src/seek/config.py` and `config.example.toml`: `web_host`, `web_port`.
- `pyproject.toml` / `uv.lock`: `fastapi`, `uvicorn`, `jinja2` as runtime
  dependencies. Tests use FastAPI's `TestClient` (needs `httpx`, dev only).
- No change to the nmap parsing, merge, or gowitness reading code: the web
  interface is another consumer of the same model and the same `Captures`.
