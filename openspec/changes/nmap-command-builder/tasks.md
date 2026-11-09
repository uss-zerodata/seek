## 1. Data

- [x] 1.1 `models.Host.times` (srtt, rttvar, to in microseconds) and `parse.py` reads `<times>`; fixture XML with `<times>` for some hosts; parser test
- [x] 1.2 `merge` keeps the slower `times` for a host seen in several files (file order is not time order, and a timeout must cover the slowest); test

## 2. Option catalogue

- [x] 2.1 `nmap/options.py`: `Option`, `Value` (form, attach, optional), the eleven groups in the summary's order, every option of the design's inventory with names/aliases, default, root, `about`, source page
- [x] 2.2 Value forms with validators and messages: number, real, time, ports (the full `-p` grammar), portlist, protocols, list, hosts, choice, hex, text, script expression, script-args
- [x] 2.3 Conflict rules (exclusive / ignored / advice) with their sources; `owner` reasons for the options seek controls
- [x] 2.4 `presets.needs_root` learns the raw-packet evasion options; tests: every summary option is catalogued, every `root=True` option is classified by `needs_root`, every shipped preset parses with no unknown token, every validator accepts its documented examples and refuses its counter-examples

## 3. Recent and frequent commands

- [x] 3.1 `nmap/recent.py`: `strip(argv)` using the catalogue's arity and `owner`; `--exclude`/`--excludefile` dropped
- [x] 3.2 `History` JSON file in the state directory (`seek.paths`), capped at 200; `record(args)`; `recent()` / `frequent()` merged with the session's `ScanFile.args`; `{ports}` restored
- [x] 3.3 Tests: every shipped preset survives `strip` whole; no address, CIDR, octet range, IPv6, host name, path or `-iL`/`--exclude` value survives; the file never holds a target; tests use the private state dir
- [x] 3.4 `Session.start_scan` records the stripped arguments on success

## 4. Timing

- [x] 4.1 `nmap/timing.py`: `Rtt`, `derive(observations, profile)` with the clamped 2× / 3× / 4× rule and the sentence naming the source and the slowest host
- [x] 4.2 `measure_connect` (≤ 8 hosts × 3 connects, 2 s each, 8 s total, cancellable) and `measure_ping` (bounded `nmap -sn -n -oX -`, run directly with a timeout - it is not a scan to list - `<times>` read)
- [x] 4.3 Tests: LAN, Internet and mixed RTTs; clamping; partial data; a measurement against a loopback listener; refused/filtered counts as no data; cancel stops it

## 5. Builder model

- [x] 5.1 `nmap/builder.py`: `Facts`, `Answers`, `Overrides`, immutable `State` with JSON round trip; the seven steps with status (done/current/ahead/skipped) and `applies`
- [x] 5.2 `resolve(state, facts, profile)`: precedence user > goal > profile > measured > earlier scans > default, losers kept for help; conflicts applied with the user's latest winning an exclusive rule
- [x] 5.3 `render(resolved)`: group and catalogue order, attach rules; the profile table of the design, with `misses`; privilege fallback to `-sT` with its note
- [x] 5.4 Tests: each goal's step sequence; back keeps answers; user values survive both profiles; exclusive conflicts clear the older and say so; render is byte-stable; documented figures pinned; every rendered command passes `presets.parse_command`

## 6. Terminal

- [x] 6.1 `ChooserScreen`: build / recent / frequent / presets with headings, source lines, type-to-filter; replaces `PresetScreen` as the entry
- [x] 6.2 `BuilderScreen` layout: step list (or one-line stepper below 120 columns), content, help pane (or `?` overlay), live command with folded targets, key line; `_Fits` frame
- [x] 6.3 Guided steps: choices with `+`/`−` lines, inline flags, `recommended` in words, preview on highlight; measurement confirmation, progress, cancel, failure states
- [x] 6.4 Fine-tune: grouped rows with set counts, `[x]` flags, value editing in place with `✗` validation, provenance badge, `r` reset, `/` filter, `s` set-first, owned options dimmed with reasons
- [x] 6.5 Choose: fast and reliable side by side with differences and misses; finish → `CommandScreen` → review; Esc asks before discarding answers
- [x] 6.6 Help overlay and README key list; TUI tests: chooser order and filter, reusing a recent command, a full path to the review, back/jump, fine-tune validation and reset, declining the measurement sends nothing, discard confirmation, fits at 60x18 / 80x24 / 160x48

## 7. Browser

- [x] 7.1 `api/v1/builder.py`: `GET /builder` (state in, steps and command out), `POST /builder/measure` (requires `confirmed`), `GET /scans/recent`; schemas
- [x] 7.2 `actions.js`: chooser section, builder dialog with stepper, radio-group choices, fine-tune `<details>` with filter and inline errors, measurement confirmation; `keys.js` dialog scope
- [x] 7.3 Web tests: the same state gives the same command as the terminal; measure refuses without confirmation; stepper and errors carry their ARIA attributes

## 8. Finish

- [x] 8.1 README (the builder, fine-tune, the trade-offs, the history file and what it holds); AGENTS.md (the stateless exception, the catalogue as the one option source, the rule sources, the precedence)
- [ ] 8.2 ruff, full pytest, `openspec validate nmap-command-builder --strict`
