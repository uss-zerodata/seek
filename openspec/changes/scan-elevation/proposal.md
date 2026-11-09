# Proposal

## Why

A scan that needs root could not start from the viewer on a machine where sudo asks for a password, even after the user ran `sudo -v`. Reproduced: seek starts every tool in a new session, which has no controlling terminal. sudo keeps its credential cache per terminal, so `sudo -n` never sees a warm timestamp. The advice in the error ("warm the timestamp with `sudo -v` in another terminal") can never work with sudo's default per-terminal cache. The setcap advice did not work either: seek put `sudo -n` in front of nmap even when nmap had the capabilities, and nmap uses them only with `--privileged`.

## What Changes

- A tool is started in its own process group but in the viewer's session, with stdin closed, so sudo sees the viewer's terminal. Cancelling still reaches the whole group.
- Before an elevated scan starts from the terminal viewer, seek asks sudo whether it would run the command without a password. If not, the viewer steps aside and lets **sudo** ask on the terminal, then runs the scan with `sudo -n`. seek never reads, stores or forwards the password.
- When the nmap binary has the raw-socket file capabilities, a privileged scan runs **without sudo**, with `--privileged` added. The review says which route a scan takes.
- The browser refuses to start an elevated scan that sudo would not run without a password, before anything runs, and explains why. The refusal explanation is corrected everywhere.

## Capabilities

### New Capabilities

### Modified Capabilities
- `nmap-scan-runner`: "Privileged scans use non-interactive elevation" is replaced by elevation that sudo may confirm interactively in the terminal viewer, with a capability route.

## Impact

`seek.runner` (process group, stdin), `seek.nmap.presets` (capability detection on `Probe`), `seek.nmap.runner` (`sudo_ready`, help text), `seek.nmap.session.plan_scan` (route), the TUI review and start path, `web/api/v1/runs.py`, `actions.js` review text, the README and AGENTS.md.
