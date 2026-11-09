## 1. Pure text forms

- [x] 1.1 Add `src/seek/nmap/remote.py`: `local_text(argv)`, `nmap_snippet(scan_args, targets, out_name, needs_root)`, `capture_snippet(urls, settings)`, reusing `presets.build_argv` and `gw_capture.scan_argv` with a native probe and a relative root
- [x] 1.2 `tests/test_nmap_remote.py`: `shlex.split` round-trip equals the argv; `sudo` without `-n` when `needs_root`; no `docker`, no absolute path, no scan-dir path in either snippet; the heredoc holds exactly the URLs; the settle script survives quoting

## 2. Session: plan without running

- [x] 2.1 Move the nmap-available and writable refusals out of `draft_command`, `draft_version_gaps` and `plan_scan` into `ScanPlan.blocked`; keep the `{ports}`, no-target and parse refusals
- [x] 2.2 `plan_capture`: availability and busy go to `CaptureRun.blocked`; stop writing `urls.txt` at plan time and write it in `start_capture`
- [x] 2.3 Add `copy_local` (None when the tool is unavailable) and `copy_remote` to `ScanPlan` and `CaptureRun`
- [x] 2.4 `start_scan` / `start_capture` refuse a plan with `blocked` set; tests for the moved refusals and for "a cancelled capture review writes nothing"

## 3. Terminal UI

- [x] 3.1 `_start_scan_flow` no longer returns early when nmap is missing; the ScopeScreen → preset → command → review path runs without nmap
- [x] 3.2 `ReviewScreen`: choices as one-line options (start / copy for another machine `y` / copy as shown `Y`), start disabled with the `blocked` reason, a note on where to copy the results
- [x] 3.3 New capture review modal (URL count, first URLs, destination, backend, the same choices); `_start_capture` pushes it before it starts
- [x] 3.4 Copy through `actions.copy_to_clipboard`; on `ActionError`, show a modal with the text in a read-only `TextArea`
- [x] 3.5 Help overlay and hint text for `y` / `Y`; `test_tui`/nmap tests: plan without nmap, copy with a fake clipboard, the clipboard-failure modal, capture review cancel

## 4. Web

- [x] 4.1 Schemas: `ScanPlanOut` gets `copy_local`, `copy_remote` and `blocked`; new `CapturePlanOut`
- [x] 4.2 `POST /captures/review`; `POST /scans` and `POST /captures/runs` return 409 when `blocked`
- [x] 4.3 `actions.js`: a copy choice in the scan review dialog, a new capture review dialog before start, `navigator.clipboard` with the readonly-textarea fallback
- [x] 4.4 `keys.js`: `y` / `Y`; web tests: review without nmap, identical snippet to `remote.nmap_snippet`, 409 on a blocked start

## 5. Docs and specs

- [x] 5.1 README: section "Scanning from another machine"; AGENTS.md: an nmap-viewer invariant line (copied text is `shlex`-quoted for a person, executed text is never joined)
- [x] 5.2 `uv run ruff check`, `uv run pytest -q`, `openspec validate copy-remote-command --strict`
