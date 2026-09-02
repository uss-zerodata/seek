## 1. Generalise the runner

- [ ] 1.1 Split `nmap/runner.py` along the seam design.md names: a neutral `Run` (argv, state, timing, bounded log, `command()`, `append()`) and `Runner` supervising it. No behaviour change.
- [ ] 1.2 `ScanRun(Run)` keeps everything nmap-shaped: `xml_path`, `preset`, the `About x% done` / `hosts up` progress regexes, and the "IP addresses"/"hosts up" summary.
- [ ] 1.3 Confirm the existing nmap tests still pass unchanged - this step must be invisible from outside.

## 2. Detecting gowitness

- [ ] 2.1 `gowitness/detect.py`: a `Probe` mirroring `nmap/presets.py:probe()` - runs once, never raises, absence is an answer. Docker counts as usable only when the daemon answers (`docker info`), not merely when the client is on `PATH`. Do not pull the image here.
- [ ] 2.2 `label()` for the status bar: `◉ gowitness docker` / `◉ gowitness native` / `◉ gowitness not found`, symbol and words so colour is never the only signal.
- [ ] 2.3 Config: `gowitness_mode` (`auto` | `docker` | `native`, default `auto`), `gowitness_path`, `gowitness_image`, `gowitness_report_host`, `gowitness_report_port`, `gowitness_chrome_path`. Add each to `config.example.toml` with a comment and its default.
- [ ] 2.4 Tests: each mode against present/absent/daemon-dead backends; a pinned-but-missing backend disables the feature and says which was pinned rather than falling back.

## 3. Building and running a capture

- [ ] 3.1 `gowitness/capture.py`: the capture directory layout (`gowitness/` under the scan output dir, holding `urls.txt`, `gowitness.sqlite3`, `gowitness.jsonl`, `screenshots/`).
- [ ] 3.2 One argv builder taking "where the capture directory is, from the runner's point of view", so docker and native differ only in that prefix and the `docker run -v … -w …` preamble. Pass `--write-db --write-jsonl --screenshot-path … --skip-html --skip-network-logs`.
- [ ] 3.3 `CaptureRun(Run)`: screenshot dir, db and jsonl paths, `N/M captured` progress parsed from gowitness's `INFO result … target=… status-code=…` lines, and a `N captured, M failed` summary.
- [ ] 3.4 Write the URL list from the current selection, honouring marks and filter exactly as the export recipes do. Refuse with a clear message when the selection holds no HTTP/HTTPS URL.
- [ ] 3.5 A second `Runner` slot on the app for captures, so one capture runs at a time while a scan may run concurrently. Extend the quit guard to ask both.
- [ ] 3.6 Tests: argv for both backends; the URL file contains fully qualified URLs only; progress and summary parsing; refusal on an empty selection; a capture and a scan run concurrently; a second capture is refused; the quit guard covers a running capture.

## 4. Reading results back

- [ ] 4.1 `gowitness/results.py`: parse JSONL into a `Capture` record carrying url, final url, status code and reason, title, protocol, technologies, the `Server` header, a TLS summary, screenshot path, and failure reason. Skip and report a malformed line rather than failing the file.
- [ ] 4.2 Index captures by URL and expose the lookup a service and a host need. Read the capture directory on startup so an externally produced capture is picked up, on the same principle as the scan history.
- [ ] 4.3 Build fixtures from the real sample at `scratchpad/gw/gowitness.jsonl` - including a failed result and one with several technologies - rather than hand-written JSON that may not match the tool.
- [ ] 4.4 Tests: a successful result, a failed result kept with its reason, a malformed line skipped, an external capture directory read at startup, and results attributed to the right service by URL.

## 5. Showing them

- [ ] 5.1 `tui/nmap/detail.py`: annotate the existing `URLs` section of a service with a dim continuation line per captured URL (`200 OK · title · server · technologies`). A URL with no capture gets no line - silence, not "not captured".
- [ ] 5.2 A `Captures` section on a host, aligned status-first for triage, built with the `Text`-padding idiom the `Names` section already uses. Failed results marked `✗` with their reason.
- [ ] 5.3 Status-code colour as reinforcement only, from the ANSI-adaptive palette: 2xx success, 3xx info, 4xx warning, 5xx and failures error. Never colour as the only signal.
- [ ] 5.4 Status bar: the gowitness token beside nmap's, and `◉ report :7171` while the report server runs.
- [ ] 5.5 Tests: a service's captures render; a host's summarise; a record with no captures gains no section; several names on one port are shown separately rather than merged; a failed result is visible with its reason.

## 6. Acting on them

- [ ] 6.1 Export dialog: a `Capture screenshots` entry, last and under a rule, showing the URL count before committing. Disabled with the reason as its subtitle when gowitness is unavailable - visible, not hidden.
- [ ] 6.2 `i` opens a capture's image: directly when the record has one, through the existing `ChoiceScreen` when it has several. A failed result is listed but disabled, with its reason.
- [ ] 6.3 `W` starts `gowitness report server` against the capture's own database and opens the browser; if already running, just reopen. Stop it when the app exits so no server is left behind.
- [ ] 6.4 Captures in the Scans tab: no column change, `● capture / 233 urls / running / 84/233 captured`. The three `o` report modes - overview, diff against the previous capture, raw log.
- [ ] 6.5 Tests: the export entry is disabled with a reason when unavailable; `i` with one and with several captures; `i` on a failed result says there is no screenshot; the server is stopped on exit; a capture appears in the run list with its progress.

## 7. Say so

- [ ] 7.1 Help screen: `i`, `W`, and the capture entry under `x`, in the existing sections.
- [ ] 7.2 Command palette: entries for capture, open image, and report server, each naming its key.
- [ ] 7.3 `_HINTS` for the views where the new keys apply.
- [ ] 7.4 README: the capture workflow end to end, the backend order and how to pin it, and where the artefacts are written.
- [ ] 7.5 AGENTS.md: the two invariants this change establishes - results are annotated onto the URL list that already exists rather than given a parallel section, and one `Runner` slot per tool is what makes "concurrent across tools, serial within one" free.

## 8. Finalisation

- [ ] 8.1 `uv run ruff check` clean.
- [ ] 8.2 `uv run pytest -q` green.
- [ ] 8.3 `openspec validate gowitness-integration --strict` passes.
- [ ] 8.4 Check by hand against `test_scans` and the authorised targets: run a capture from the export dialog, watch it stream in the Scans tab, cancel one, read the results on a host and a service, open an image, start the report server.
