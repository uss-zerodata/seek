## 1. Detecting nmap

- [x] 1.1 `src/seek/nmap/presets.py`: `probe(program)` → available flag, resolved path, version string, or the reason it is unavailable. Uses `shutil.which` and one `--version` call; never raises.
- [x] 1.2 The probe runs once at startup and its result is carried on the app, not re-run per action.
- [x] 1.3 Tests: found (version parsed), not on the path, present but not executable, and a program that answers `--version` with nonsense.

## 2. Presets and the command

- [x] 2.1 `Config.nmap_presets: dict[str, str]`, `Config.nmap_path: str = "nmap"`, `Config.scan_output_dir: str = ""` (empty means the launch directory), validated like `editors`; a user's table replaces the default rather than merging.
- [x] 2.2 `needs_root(args)` derived from the flags that actually require it: the raw scan types (`-sS -sA -sW -sM -sN -sF -sX -sU -sY -sZ -sO`), `-O -A --traceroute --privileged`, **and the raw host-discovery probes `-PE -PP -PM -PO -PU`** (found while deriving the presets — the documented discovery scans use them and were being classified as unprivileged). `-PS`/`-PA` are excluded: unprivileged nmap sends those with connect().
- [x] 2.3 `parse_command(text)`: `shlex.split`, refuse shell metacharacters naming the offending token, refuse a program that is not nmap, refuse user-supplied `-oA/-oX/-oN/-oG`.
- [x] 2.4 `build_argv(args, targets, out_base, elevate)` and `output_base(dir, preset, when)` → `seek-<slug>-<UTC>Z`; `-oA` is always appended by the app.
- [x] 2.5 The shipped preset table, **derived from `nmap.md`**: the reference's phases (01 discovery, 02 services, 03 service-specific) in workflow order, arguments only (no `sudo`, `-iL` or `-oA`), plus `{ports}` expanding to the open ports already in the model — the grep step the reference does between the top-1000 and version scans. Example file regenerated.
- [x] 2.6 Tests: privilege derivation per flag; every refusal path of `parse_command`; argv construction with and without elevation; the output base name; a malformed preset is reported and the rest of the config still loads.

## 3. Targets

- [x] 3.1 `parse_target(line)` accepting an address, a CIDR range, a hostname or a URL; blank lines and `#` comments ignored; a URL contributes its host and, when given, its port.
- [x] 3.2 A scope reports per-line validity, the count of valid targets and the total addresses covered.
- [x] 3.3 Tests: each accepted form, IPv6, an out-of-range address, a bare port, a URL with a path, a line that is nothing at all.

## 4. Running

- [x] 4.1 `src/seek/nmap/runner.py`: `ScanRun` (id, preset, targets, argv, state, times, exit code, bounded log deque with a dropped-line counter, output base) and a supervisor with `start`/`cancel`. No Textual import.
- [x] 4.2 Launch with `asyncio.create_subprocess_exec` — never a shell — streaming stdout and stderr line by line to a callback.
- [x] 4.3 Elevation: `sudo -n` prepended when the command needs root and the process is not root; classify a refusal distinctly from a scan failure.
- [x] 4.4 Cancel: `SIGTERM` to the process group, `SIGKILL` after a grace period; the run is recorded as cancelled with the output it produced and a note that no file was written.
- [x] 4.5 Exit classification: finished, failed (with nmap's own message), cancelled, elevation refused, executable missing.
- [x] 4.6 Progress: parse nmap's `Stats:`/`Timing:` lines when present; fall back to elapsed time. Never inject flags the user did not see.
- [x] 4.7 Tests, all against a **stub executable** that prints canned output — never a real scan: streaming, cancellation, non-zero exit, elevation refusal, a log longer than the bound.

## 5. The Scans tab

- [x] 5.1 `src/seek/tui/nmap/scans.py`: the run list as a `View` (Scan, Scope, State, Elapsed, Result) so sorting, filtering and the rest apply unchanged.
- [x] 5.2 The tab is always present, last in the row; without nmap it explains what is missing rather than being merely greyed out.
- [x] 5.3 The report pane renders the selected run in three modes cycled by `o`, with the current one named in its first line: condensed, diff, raw.
- [x] 5.4 Live output while running, following the newest line unless the user has scrolled away.
- [x] 5.5 `p` freezes the display only; the header says the scan is still running; nothing is lost when it is unfrozen. `c` cancels the run.
- [x] 5.6 `n` starts a new scan from any tab; a second scan while one runs is refused, naming the running one.
- [x] 5.7 `⌁ nmap <version>` / `⌁ nmap not found` in the status line — symbol and text, never colour alone.
- [x] 5.8 Empty state: no runs yet says how to start one; without nmap it says what is missing and how to fix it.
- [x] 5.9 Tests: the run list; the three report modes; freezing does not signal the process and says so; cancelling; the second-scan refusal; the indicator in both states.

## 6. The scope editor

- [x] 6.1 `src/seek/tui/nmap/scope.py`: a multi-line editor in the list region, one target per line, annotated per line as it is typed, with the count and the address total below.
- [x] 6.2 `seek nmap` on paths with no readable scan opens it when nmap is available, and reports as it does today when not; the launch directory becomes the scan output directory.
- [x] 6.3 Scanning is refused while no valid target exists, saying so.
- [x] 6.4 Opened on scans that can be read, nothing changes — no editor, no new prompt.
- [x] 6.5 Tests: the empty-directory entry point with and without nmap; per-line validation; the existing entry points are untouched.

## 7. Choosing, reviewing, confirming

- [x] 7.1 Preset chooser over the configured presets, in config order, one line each, with the privilege requirement shown.
- [x] 7.2 The chosen preset becomes an editable command line, complete with targets and the output path.
- [x] 7.3 The review step: exact argv, target count and first targets, output path, privilege level, and the authorisation reminder. Nothing runs without confirmation here.
- [x] 7.4 The output directory is checked for writability before the review, not after the scan.
- [x] 7.5 Cancelling at any step runs nothing and writes nothing.
- [x] 7.6 Tests: preset → command → review → start; a refusal from `parse_command` surfaces at the command step; cancelling at each step; an unwritable directory.

## 8. Folding the result back in

- [x] 8.1 On success, re-read every source plus the new file (`prepare(load(...))`) rather than merging incrementally.
- [x] 8.2 Re-resolve marks by identity against the new model, dropping any that no longer exist.
- [x] 8.3 `src/seek/nmap/diff.py`: new hosts, newly open ports, changed service identifications; a run that added nothing says so.
- [x] 8.4 The condensed report: hosts and open ports found, duration, and what the diff summarises.
- [x] 8.5 Tests: a finished scan appears in the overviews with its provenance; the diff over a fixture pair; a scan that adds nothing; marks survive a rebuild.

## 9. Export → scan

- [x] 9.1 The export dialog offers scanning the selected records when nmap is available, and does not when it is not.
- [x] 9.2 The selected records' addresses become the scope, entering the same preset → command → review flow.
- [x] 9.3 Tests: the destination appears only when available; the scope carries the marked addresses; the flow reaches the review step.

## 10. Say so

- [x] 10.1 Help overlay: `n`, `o`, `p`, `c`, what freezing does and does not do, and where output is written.
- [x] 10.2 Command palette entries for every new action, each naming its key.
- [x] 10.3 `_HINTS` for the Scans tab and the scope editor.
- [x] 10.4 README: the scan workflow end to end, the preset config, `sudo -n` and what to do when it is refused.
- [x] 10.5 AGENTS.md: the command field is parsed and never shelled; privilege is derived from flags; freezing is a view state; merging is a re-read; tests never run a real nmap.

## 12. Not by accident (follow-up)

- [x] 12.1 Every route out - `q`, the staged `Esc`, `ctrl+c` and the system palette's Quit (`action_quit` overridden: a guard one keypress can walk around is not a guard) - goes through one `_request_quit`.
- [x] 12.2 With a scan running it names the scan, its elapsed time and what leaving costs (a scan that does not finish writes no file); `Esc` on the question keeps scanning.
- [x] 12.3 The `Esc` hint says "quit (asks while a scan runs)" while one is running.
- [x] 12.4 Tests: each route asks; dismissing stays; choosing to quit ends the scan and leaves; with nothing running it exits immediately.

## 13. Names, everywhere they matter (follow-up)

- [x] 13.1 `03 · DNS names (reverse lookup, sends nothing)` preset: `-sL -R`, the one preset without `-n` — resolving is the point, and a list scan sends the targets nothing.
- [x] 13.2 `nmap/names.py`: the recogniser, run once by `views.prepare`, attaching `Service.cert_names` — the `ssl-cert` subject *and* its SAN table, wildcards and addresses dropped.
- [x] 13.3 The URL export covers the address and every name; a `names` field carries them into CSV/JSON; `host_search_text` includes them so the filter finds a host by a certificate name.
- [x] 13.4 The host record lists every name with its source; the service record shows its certificate names and every URL it answers on.
- [x] 13.5 The hostname column reads `name +N`, in every list that shows one.
- [x] 13.6 A **Names** tab: each name, its source, its hosts and ports; `Enter` opens the hosts that answer to it; an empty state that says how names are found.
- [x] 13.8 The vhost question: an address cannot be asked which names point at it, so the recogniser reads what the server gives away — certificate subjects and SANs, redirect targets, Windows identity FQDNs, certificate transparency — each with its own narrow pattern, and every name keeps all of its evidence. Three further presets find them (service-revealed, crt.sh, `http-vhosts`), with the external one labelled as querying a third party.
- [x] 13.9 A `vhosts` fixture covering all five sources; a regression test that a `http-vuln-*` advisory link is not harvested as a name.
- [x] 13.7 Tests: extraction from output and tables; wildcards and addresses refused; the column, both panes, the filter, the tab, the drill-down and the empty state.

## 14. Scans as a history over time (testing feedback)

- [x] 14.1 `ScanFile.start` parsed from `<nmaprun start>`; `ScanSet.files` retains the per-file parses; `merge` keeps them.
- [x] 14.2 `nmap/timeline.py` (pure): order scan files by start epoch, re-parse each pristinely (merge mutates the earliest file's hosts), and diff each against a deep-copied cumulative-before snapshot. Baseline for the first.
- [x] 14.3 Raw view: the sibling `.nmap` when present, else a report synthesized from the XML.
- [x] 14.4 The Scans tab lists the history (imported + in-app) uniformly, labelled by filename, ordered by time; a finished in-app run is deduped against its own file; running/failed runs show live. Cached (`_scan_history`) and rebuilt only when the model changes; live rows recompute each refresh. Starting a scan focuses its live row.
- [x] 14.5 Tests: ordering by start; baseline; incremental diff; pristine per-scan hosts; raw sibling-vs-synthesized; the tab lists imported scans and is empty only with none.

## 11. Finalisation

- [x] 11.1 `uv run ruff check` clean.
- [x] 11.2 `uv run pytest -q` green.
- [x] 11.3 `openspec validate nmap-scan-runner --strict` passes.
- [x] 11.4 Regenerate `config.example.toml`.
- [x] 11.5 **Run by the user.** Walk both entry points against a lab target you are authorised to scan: an empty directory through the editor, and an existing scan through export → scan. Every automated test here runs a stub, never nmap, so this is the only step that exercises the real binary, real `sudo -n` and real `-oA` output.
