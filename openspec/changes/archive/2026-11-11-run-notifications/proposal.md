# Proposal

## Why

Scans and captures run for minutes to hours, often while the user is elsewhere. Today the only way to know that one finished is to look at the viewer. The user wants a push notification on a phone or desktop through an ntfy-compatible webhook, and optionally progress updates while the run is still going.

## What Changes

- New settings `notify_url` (default empty: off) and `notify_progress` (default false).
- The scan review and the capture review, in the terminal and in the browser, show the URL and the progress switch with these defaults. The user can change or clear them for this one run.
- When a run ends (finished, failed or cancelled), seek POSTs one ntfy message to the URL. With progress on, it also sends one message each time the run crosses 25, 50 and 75 percent done.
- Messages are **minimal**: tool or preset name, outcome and elapsed time. They never contain an address, a host name, a URL, a path or tool output.
- A failed delivery never affects the run. It is written into the run's log, which both front ends show.

## Capabilities

### New Capabilities
- `run-notifications`: webhook notifications for nmap scans and gowitness captures: settings, per-run choice, content limits, delivery.

### Modified Capabilities

## Impact

New `seek/notify.py` (stdlib `urllib`, no new dependency). `Run` gets the notification fields and a progress fraction. `Session._start` sends. Config fields and `config.example.toml`. The TUI `ReviewScreen` gets an input and a checkbox. Web schemas, `runs.py` and `actions.js`. Tests use a loopback receiver.
