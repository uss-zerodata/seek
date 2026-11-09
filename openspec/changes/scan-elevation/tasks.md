## 1. Process and detection

- [x] 1.1 `seek.runner`: start tools with `process_group=0` and `stdin=DEVNULL` instead of `start_new_session=True`
- [x] 1.2 `presets.raw_capable(path)` from the `security.capability` xattr; `Probe.capable`; tests on real `setcap` bytes
- [x] 1.3 `plan_scan`: route root / capabilities (`--privileged`, no sudo) / sudo; `ScanPlan.via`; the remote snippet stays built from the user's arguments

## 2. Asking sudo first

- [x] 2.1 `nmap.runner.sudo_ready(argv)`: `sudo -n <program> --version` in the viewer's session (`-l` misreports a password rule beside an unrelated NOPASSWD rule), the reason when it would ask
- [x] 2.2 TUI: after the review, `sudo_ready`; if it would ask, suspend and run `sudo -v`, check again, otherwise say why
- [x] 2.3 Web `POST /scans`: refuse with 409 and the help text when `sudo_ready` fails
- [x] 2.4 Correct `elevation_help`; add the requiretty wording to the refusal list; review text in TUI and `actions.js`

## 3. Verify

- [x] 3.1 Unit tests (capabilities, route, help text, sudo_ready with a stub sudo, TUI prompt path with a fake suspend, web 409)
- [x] 3.2 Container check against password sudo: prompt, then `sudo -n` scan from the same session
- [x] 3.3 README, AGENTS.md; ruff, pytest, `openspec validate scan-elevation --strict`
