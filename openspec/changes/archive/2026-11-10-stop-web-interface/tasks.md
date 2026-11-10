## 1. Server

- [x] 1.1 `WebServer`: `on_stop` parameter and `app.state.on_stop`; `app.state.closing` event set by `stop()`; `timeout_graceful_shutdown=2`
- [x] 1.2 `events` stream ends on `closing` with an `event: closing`; keeps the 15 s ping
- [x] 1.3 `GET /api/v1/web` (mode) and `POST /api/v1/web/stop` (answer first, then `on_stop` via `call_later`)
- [x] 1.4 `serve`: `on_stop=stop.set`; tests: stop request ends `serve` like a signal; a stopped server closes an open event stream within 2 s; another origin is refused

## 2. Terminal viewer

- [x] 2.1 `w` while running → `ChoiceScreen` (open / copy / stop); not running → start as today
- [x] 2.2 `action_stop_web` + palette entry; notify, status line, `on_stop` from the browser lands here
- [x] 2.3 Tests: the `w` menu's three choices; stop keeps a running scan; `w` after stop starts again; the browser's stop in the viewer leaves the app running

## 3. Browser

- [x] 3.1 Stop control in the key bar (`data-action="stopWeb"`), confirmation `dialog()` worded by mode
- [x] 3.2 `events.js`: `closing` → stopped state, no reconnect
- [x] 3.3 Layout test: the control is an action button in `HANDLERS`, one primary in its dialog

## 4. Finish

- [x] 4.1 README and help overlay; ruff, full pytest, `openspec validate stop-web-interface --strict`
