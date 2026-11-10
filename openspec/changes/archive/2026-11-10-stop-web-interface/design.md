# Design

## Context

See proposal.md (Why). `WebServer` (`web/server.py`) runs uvicorn as a task on the viewer's loop. It already has `stop()` (sets `should_exit`) and `aclose()` (stop, then wait up to 3 s). `NmapApp._web` holds it; `_open_web` starts it or reuses it, and opens the browser. `seek nmap serve` waits on an `asyncio.Event` that SIGINT/SIGTERM set, then cancels runs and calls `aclose()`.

The event stream (`GET /api/v1/events`, `runs.py:events`) is an endless `StreamingResponse`. uvicorn's graceful shutdown waits for in-flight responses, and with no `timeout_graceful_shutdown` it waits for ever. Today a stop with a page open is ended only by `aclose`'s 3 s `wait_for`, which cancels the task.

## Goals / Non-Goals

**Goals:** one stop path for the three triggers (the `w` menu, the palette, the browser); a prompt stop with pages told why; serve mode ending exactly as on Ctrl+C.

**Non-Goals:**
- A key binding of its own: `w` and the palette cover it.
- Restarting from the browser.
- Stopping gowitness's own report server (`W`), which has its own lifecycle.

## Decisions

**1. One callback says what "stop" means.** `WebServer(…, on_stop=callable)`, kept on `app.state.on_stop`.
- Viewer: `NmapApp._stop_web`, which calls `aclose()`, notifies, and refreshes the status line.
- `serve`: `stop.set`, the same event the signal handlers set, so the browser's stop is Ctrl+C in every respect.

`POST /api/v1/web/stop` answers `{"stopping": true, "ends": "web" | "process"}` first, then schedules `on_stop` with `loop.call_later(0.1, …)` so the response is written before the server begins to close. It is `async def`, because it changes the session's loop. Same-origin is the existing middleware.

**2. Streams are closed, not waited for.**
- `app.state.closing = asyncio.Event()`, set by `WebServer.stop()`.
- The `events` stream waits on its queue *or* that event (`asyncio.wait` with `FIRST_COMPLETED`, keeping the 15 s ping), sends `event: closing`, and returns.
- `uvicorn.Config(timeout_graceful_shutdown=2)` is the backstop for any other long response.

Considered: cancelling the server task outright. Rejected, because pages would see "connection lost", which is the message this change exists to replace.

**3. `w` while running is a `ChoiceScreen`:**
- `open` (today's behaviour, the default and first);
- `copy` (`copy_to_clipboard`, with the URL shown if there is no clipboard, as the scan review does);
- `stop`.

When it isn't running, `w` starts it as today, with no menu. The palette entry calls `action_stop_web` and says "the web interface is not running" when there is nothing to stop.

**4. The browser.**
- **Control:** a `button[data-action="stopWeb"]` in the key bar, dispatched through `HANDLERS` like every action control. Its confirmation is `dialog()` with one primary button. The confirmation text depends on `/api/v1/web` (`{"mode": "viewer" | "serve"}`): in serve mode it says running scans and captures will be cancelled.
- **Events:** `events.js` handles the `closing` event by setting a `stopped` state, saying "the web interface was stopped - start it again with w in seek", and not reconnecting. Today `EventSource` retries every 2 s.
- **Keys:** no new terminal key, so the parity test is unaffected.

## Risks / Trade-offs

- [A stop request from a forwarded page in serve mode ends the process] → that's the point. It is confirmed, and the same-origin rule keeps other sites out.
- [`call_later(0.1)` racing the response write] → 0.1 s is long against a local write. The test asserts the response arrives and the server is then gone.
- [A browser that missed `closing` (a dropped connection)] → it shows "connection lost" as today, so nothing is worse.
