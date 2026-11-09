## 1. Core

- [x] 1.1 `seek/notify.py`: `normalise(url)`, message builders (end, milestone), `send()` via urllib in ntfy format; ASCII-safe headers
- [x] 1.2 `Run`: `notify_url`, `notify_progress`, `fraction()` (nmap percent, capture finished/total), the milestone reached, and `notify_name` (preset, or "gowitness capture")
- [x] 1.3 Config: `notify_url` (validated, normalised), `notify_progress`; regenerate `config.example.toml`
- [x] 1.4 Session: plans carry the defaults; `_start` sends milestones on progress lines and the final message on done, in a thread; a failure goes to the run log
- [x] 1.5 Tests: content has no target/path/output, milestones once each, loopback receiver gets ntfy headers, an unreachable URL leaves the run DONE with a log line, config validation

## 2. Front ends

- [x] 2.1 TUI `ReviewScreen`: URL input and progress checkbox with defaults; an invalid URL keeps the review open; applied to the run
- [x] 2.2 Web: plan responses carry the defaults; `ScanPlanIn`/`CaptureIn` accept the per-run values; the review dialogs show them
- [x] 2.3 Tests: TUI per-run override and clearing; web start with override

## 3. Dialogs that fit

- [x] 3.0 Scope, preset, command and review dialogs: frame never wider or taller than the screen, the long part's max-height set from the room left (`_Fits`), `[x]` / `[ ]` checkbox; test at 60x18, 80x24, 120x40 with 300 targets

## 3. Finish

- [ ] 3.1 README, AGENTS.md; ruff, full pytest, `openspec validate run-notifications --strict`
