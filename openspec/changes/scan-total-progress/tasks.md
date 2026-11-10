## 1. Counting

- [x] 1.1 The target-selecting part of a command (targets, `-iL`, `--exclude`, `--excludefile`, whether `-iR`) via `options.split`
- [x] 1.2 `Session.start_scan` counts with `nmap -sL -n` in the background (drain to the last line, 60 s timeout, `None` on failure, skipped for `-iR`) into `run.total` (D1)
- [x] 1.3 Tests: a stub nmap answering `-sL` with a count; a failing count; `-iR` not counted

## 2. Reading progress

- [x] 2.1 `ScanRun`: `verbose`, `phase`, `phase_pct`, `group`, `finished`, `reported_up`, `total`; parse per D2; remove `_STATS_ALT`/`hosts_up`
- [x] 2.2 `fraction()` per D3 (monotonic, < 1, `None` without `-v` or total); `progress()` per D4; time left
- [x] 2.3 Tests over nmap's real line shapes (captured from 7.94): several groups, down hosts, a phase change does not go back, no `-v`, no total, milestones not sent by a group's phase

## 3. Front ends and catalogue

- [x] 3.1 Scans tab row and record show the new progress and time left (the web reads the record)
- [x] 3.2 `--stats-every` catalogue note
- [x] 3.3 README, help, AGENTS.md

## 4. Finish

- [x] 4.1 Real nmap on loopback and a namespace with down hosts: the figure rises across groups and reaches the end (counts lag nmap's stdout flushes - recorded in the design)
- [ ] 4.2 ruff, full pytest, `openspec validate --strict`, version bump (minor)
