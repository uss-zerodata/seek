# Design

## Context

See proposal.md (Why). What exists today:

- `Session.draft_command` / `draft_version_gaps` / `plan_scan` produce the nmap argv. Each one refuses up front when `self.nmap.available` is false or `scan_dir` is not writable. `plan_scan` sets `elevate` from `needs_root(args) and geteuid() != 0`, and `build_argv` then prefixes `sudo -n`.
- `Session.plan_capture` refuses when gowitness is unavailable or busy, **writes `urls.txt`**, and builds the argv with `gw_capture.scan_argv(probe, paths, ...)`. When the backend is docker, that argv carries `docker run -v <root>:/data`.
- A capture has no review: `_start_capture` (TUI) and `POST /captures/runs` (web) plan and start in one step.
- `seek.actions.copy_to_clipboard(text)` exists (pyperclip, then the xclip, wl-copy, pbcopy and clip fallbacks) and raises `ActionError` when nothing works.
- The rule "the command box is not a shell" applies to *execution*. Copied text is for a person to paste into a shell, so here `shlex.join` is the correct tool.

## Goals / Non-Goals

**Goals:** one pure function per form, used by both front ends. Plans can be made with the tool absent or busy. A capture gets a review.

**Non-Goals:** tracking remote runs, an import command, watching for returned files, a docker form of the snippet, an editable capture command, and any setting for the remote binary name (the snippet uses bare `nmap`/`gowitness`; the user edits the pasted text when the remote machine differs).

## Decisions

**1. A pure module `seek/nmap/remote.py`, with no Textual and no FastAPI.**
- `local_text(argv) -> str`: `shlex.join(argv)`.
- `nmap_snippet(scan_args, targets, out_name, needs_root) -> str`: `[sudo] nmap <args> -oA <out_name> <targets>`, built through the same `presets.build_argv`. The program is `"nmap"`, the out base is the bare `out_base.name`, and elevation is off. Then the `sudo -n` from `build_argv` is replaced by a plain `sudo` prefix, so the output flags stay in one place.
- `capture_snippet(urls, settings) -> str`: `mkdir -p gowitness && cd gowitness`, a `cat > urls.txt <<'SEEK_URLS'` heredoc, then `shlex.join(scan_argv(native_probe, Paths(root=Path(".")), ...))`. Passing a native `Probe` (program `gowitness`) and a relative root to the existing `scan_argv` reuses the flag logic (settle script, `--driver gorod`, skip-html), and `"."` paths come out relative. A URL that contains the delimiter line cannot occur, because `export_urls` emits URLs and never a bare `SEEK_URLS`. An assert covers this in tests.
- Alternative considered: a second argv builder for the remote case. Rejected, because the two builders would drift on flags.

**2. Planning separates "can this command exist" from "can it run here".**
`draft_command`, `draft_version_gaps` and `plan_scan` drop the availability and writability refusals. These move into `Session.start_scan`, and onto the plan as `ScanPlan.blocked: str | None` (the reason that "start" is unavailable). `plan_capture(records, write=True)` does the same: the `CaptureRun` gets `blocked`, `urls.txt` is written only at start time (`start_capture` writes it), so a review that is cancelled or only copied writes nothing, and a busy capture's file is never overwritten. The `{ports}`, empty-target and parse refusals stay where they are.
- Alternative considered: a `remote=True` flag on every planner. Rejected, because two modes per function means twice the tests for the same output.

**3. Copy forms ride on the plan, computed once.** `ScanPlan` and `CaptureRun` get `copy_local: str | None` (None when the tool is missing) and `copy_remote: str`. The TUI review and the web schemas read the same strings, so the two front ends cannot differ.

**4. Terminal UI.** `ReviewScreen` gets `y` (copy for another machine) and `Y` (copy as shown), each shown as an `OptionList`-style line (house rule: no stacks of Buttons). It also gets a dim note: "results: copy the output files into <scan dir>". When `blocked` is set, the start choice is disabled and its label is the reason (house rule: absence is a state that is rendered). A new `CaptureReviewScreen` shows the URL count, the first URLs, where the capture is written, the backend and the same choices; `_start_capture` pushes it before it starts. When `copy_to_clipboard` raises, a modal shows the text in a read-only `TextArea` so that it can be selected.

**5. Web.** `ScanPlanOut` gets `copy_local`, `copy_remote` and `blocked`. A new `POST /captures/review` returns `CapturePlanOut` (urls, where, backend, copy forms, blocked), and the capture button now opens a review dialog before `POST /captures/runs`. `actions.js` copies with `navigator.clipboard.writeText` (loopback http is a secure context). On rejection, it shows the text in a `<textarea readonly>` inside the same `dialog()`. `keys.js` gets `y` / `Y` for parity.

## Risks / Trade-offs

- [The remote machine has a different nmap or gowitness version, so a flag is unknown there] → the snippet is plain text that the user can edit. The review note says which version the plan assumed when it is known locally.
- [The capture settle script is a long single-line JavaScript argument] → `shlex.quote` handles it, and a test round-trips the snippet through `shlex.split` and compares it with the argv.
- [`gorod` + `--javascript` requires gowitness 3.x on the remote machine] → this is the documented requirement already. The note in the review mentions it.
- [The capture now needs one more confirmation, which changes muscle memory] → this is accepted. The spec now requires the review, and it is the only place where the command can be seen.
- [Moving the availability checks into `start_*` could let a start slip through] → the session's `start_scan` / `start_capture` refuse when `blocked` is set. The web `POST /scans` and `POST /captures/runs` return a 409 with the reason, tested.
