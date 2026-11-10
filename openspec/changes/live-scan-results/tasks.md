## 1. Runner: several runs

- [x] 1.1 `seek/runner.py`: replace `_process` / `_current` / `_cancelling` with per-run state (`_processes`, `Run.cancelling`); add `active()`; keep `busy()`, `claim()`; add `cancel(run=None)`; update the docstring (D5)
- [x] 1.2 Tests in `test_nmap_runner.py`: two runs supervised together, cancelling one leaves the other running, `cancel()` with several and no run named returns False

## 2. Session: concurrent scans with a warning

- [x] 2.1 `scan_blocked` drops the busy branch; add `scan_warning()`; `ScanPlan.warning`; `start_scan` refuses only an `out_base` a running scan uses (D6)
- [x] 2.2 `presets.output_base` adds `-2`, `-3`, … when the base's XML exists
- [x] 2.3 `Session.cancel(tool, run=None)`, `cancel_all` over every active run; `running()` callers checked
- [x] 2.4 Update the double-start test from scan-robustness for captures; tests for a second scan starting with a warning and for the output-base refusal

## 3. Live results

- [x] 3.1 Session: a `Nmap scan report for` line starts a per-run timer that calls `Owner.scan_grew(run)` after the burst, paced (D1, D2)
- [x] 3.2 Diff baseline taken as the run starts (in a thread); every read diffs the run's own hosts against it (D3)
- [x] 3.3 `Session.running_paths()`; `_say_unread` and `tabs.py` treat a running run's file as the run (D4)
- [x] 3.4 `NmapApp.scan_grew` → quiet `_absorb(run, live=True)`: no busy overlay, skipped while a read or absorb runs, size check, status line "+N hosts so far"
- [x] 3.5 `NmapApp._on_scan_done` and `HeadlessOwner.scan_done` fold in a cancelled or failed scan's XML when it exists
- [x] 3.6 `HeadlessOwner.scan_grew`
- [x] 3.7 Tests: a stub nmap that writes one host group to a partial XML, prints a report line and waits → the host is in `session.scans` while the run runs; nothing is read without a report line or growth; the final summary counts all hosts; no incomplete warning for a running file; a cancelled run's hosts stay

## 4. Front ends

- [x] 4.1 TUI review shows `plan.warning`; start stays enabled
- [x] 4.2 TUI `c`: the selected running run in the Scans tab, the only one, or a `ChoiceScreen` of the running scans (D7)
- [x] 4.3 Quit question names every running scan and says the finished hosts are kept
- [x] 4.4 Web: `warning` in the review schema and dialog; `POST /runs/{rid}/cancel`; `/runs/{tool}/cancel` 409s with several running; the browser cancels the selected run
- [x] 4.5 TUI and web tests for the warning and for cancelling one of two

## 5. Finish

- [x] 5.1 README, help text and AGENTS.md (the "One `Runner` slot per tool" and "A finished scan is folded in" notes)
- [x] 5.2 ruff, full pytest, `openspec validate --strict`, version bump (minor)
- [x] 5.3 Manual check with a real nmap (7.94, loopback): the XML grows per host group in step with the report lines (D1 risk); live reads, cancel, sudo, two at once, same second, no -v, one group, header-only file, default pacing and the TUI end to end
