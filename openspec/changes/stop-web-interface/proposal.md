# Proposal

## Why

Once `w` has started the web interface in the viewer, the only way to stop it is to quit seek. A port left listening is something the user should be able to close deliberately: after showing a colleague a page, before handing the machine over, or when it was only needed for a moment. `seek nmap serve` stops only with Ctrl+C in its own terminal, which is out of reach for someone using it through a forwarded port.

## What Changes

- **Terminal viewer:**
  - `w` while the web interface is running asks what to do: open the browser at this row (today's behaviour), copy the URL, or stop the web interface.
  - The command palette gets "Stop the web interface".
  - Stopping says so, and the status line drops its "◉ web …" entry.
  - `w` afterwards starts it again.
- **Browser:**
  - A Stop control in the key bar, confirmed first.
  - In the viewer it stops only the web interface, and the terminal keeps running. For `seek nmap serve` it ends the server exactly as Ctrl+C does, cancelling runs still in progress, and the confirmation says so.
  - It is a change, so the same-origin rule applies.
- **Stopping is prompt:**
  - Open live-update streams are told the interface is closing, so pages say "the web interface was stopped" rather than "connection lost".
  - The server does not wait on them; a short graceful-shutdown limit backs this up.

## Capabilities

### New Capabilities

### Modified Capabilities
- `nmap-web-interface`: the interface can be stopped, from the terminal viewer and from the browser, without stopping the viewer.

## Impact

- `seek.web.server.WebServer`: an `on_stop` callback, closing the open streams on `stop()`, `timeout_graceful_shutdown`.
- `seek.web.api.v1`: `POST /api/v1/web/stop`; the event stream ends on a `closing` event.
- `seek.web.serve.serve`: the browser's stop sets the same event Ctrl+C sets.
- `NmapApp.action_open_web`: the menu when running; `action_stop_web`; a palette entry.
- `actions.js` / `events.js`: the Stop control, its confirmation, and the "stopped" state.
