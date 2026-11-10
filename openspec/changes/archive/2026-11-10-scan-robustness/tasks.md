## 1. Fixes

- [x] 1.1 `options.split`; `recent.strip` and `Session.plan_scan` use it; no fallback to the scope; refuse a command without targets; the command runs in its own order; `plan_scan` loses `targets`
- [x] 1.2 `Runner.claim` in `Session._start`; test of two starts in one turn
- [x] 1.3 Elevated scans run `self.nmap.path`; tests
- [x] 1.4 `parse_file` keeps the finished hosts of a cut-off file (`ScanFile.complete`); `_say_unread`; cancel message; parser and viewer tests
- [x] 1.5 ruff, full pytest, `openspec validate scan-robustness --strict`
