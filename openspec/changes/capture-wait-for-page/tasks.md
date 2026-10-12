## 1. Capture

- [x] 1.1 `capture.settle_script(quiet_ms, cap_ms)`: one-line function returning a promise - loaded, images in, still for the quiet time, or the cap
- [x] 1.2 `scan_argv`: `--driver gorod --delay 0 --javascript <script>` by default; `settle_ms=0` restores `--delay 3` and no driver flag; timeout never below cap + 10 s
- [x] 1.3 `Config.gowitness_settle_ms` / `gowitness_settle_cap_ms` with ranges and descriptions; `Session.plan_capture` passes them; `config.example.toml` regenerated

## 2. Verify

- [x] 2.1 Tests: default argv, the script's shape, timeout, the off switch, the session passing configuration
- [x] 2.2 Measured against gowitness 3.2.2 on local slow pages: chromedp does not await, gorod does, `--javascript-file` does not; failure and result log lines unchanged; database read back by `results.read_database`
- [x] 2.3 `AGENTS.md`: the rule and its three measured traps
- [ ] 2.4 A capture of a real engagement's slow targets, compared with the old screenshots
