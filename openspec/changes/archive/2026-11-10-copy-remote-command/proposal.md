# Proposal

## Why

Often the machine that runs `seek nmap` cannot reach the targets, or must not scan them: a jump host, an engagement laptop, or a box without nmap or gowitness. Today seek only plans a scan or capture to run it locally, so its presets, the `{ports}` expansion, the version-gap command and the URL list are not available when the scan has to run on a different machine.

## What Changes

- The nmap review and a new capture review get a **copy** action. It offers two forms:
  - **as shown**: the exact argv this machine would run, shell-quoted, with local paths. Offered only when the tool is available here.
  - **for another machine**: a self-contained, paste-ready shell snippet. It uses relative output paths, the native `nmap`/`gowitness` binaries (never the docker wrapper), and plain `sudo` when the flags need root. For a capture, the snippet writes the URL list itself with a quoted heredoc. No path from this machine appears in it.
- The review states where to put the results: copy the `.xml`/`.nmap`/`.gnmap` files, or the `gowitness/` folder, into one of the scan directories. The next read picks them up through the existing discovery. seek has no import step and keeps no record of pending remote runs.
- Planning works **without nmap or gowitness installed**. The scan flow and the capture review open, "Start" is disabled and gives the reason, and copying stays available.
- A capture now goes through a review (command, URL count, start / copy) before it runs. Until now it started immediately. Without the review, the command could not be seen or copied.
- The web interface gets the same actions: the plan responses carry both copy forms, and the review dialogs have a copy button and key.

## Capabilities

### New Capabilities
- `remote-execution`: planning a scan or capture for another machine: the two copy forms, what the remote snippet contains and leaves out, how results come back, and the same actions in the browser. (The browser's scan dialogs are specified in the unarchived `nmap-web-frontend` capability of `nmap-web-parity`, so the browser requirement is added here instead of as a delta to that capability.)

### Modified Capabilities
- `nmap-scan-runner`: "nmap is detected and its absence is visible" now allows planning and copying without nmap. Only starting a scan stays unavailable.
- `gowitness-capture`: the same relaxation for a missing gowitness, and a capture now runs from a reviewed command.

## Impact

- `seek.nmap.session`: `draft_command`, `draft_version_gaps`, `plan_scan` and `plan_capture` gain a mode that skips the availability, busy and writability checks and does not write the URL file.
- New pure module `seek/nmap/remote.py`: argv/plan → the two text forms (`shlex`, no Textual).
- `seek.tui.nmap.scope.ReviewScreen`: copy action, disabled Start with reason. New capture review in `app.py`.
- `seek.web.api.v1.runs` + `schemas`: the plan responses carry `copy_local` / `copy_remote`, and a new `POST /captures/review`. `actions.js`, `keys.js` and the help text are updated.
- Reuses `seek.actions.copy_to_clipboard` (pyperclip + fallbacks). No new dependency.
