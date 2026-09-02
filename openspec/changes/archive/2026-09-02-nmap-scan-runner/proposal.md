## Why

The viewer reads scans someone else ran. In practice the loop is: read the
scans, export a host or URL list, leave the app, run the next nmap command in
another terminal, come back, re-open the viewer on the new file. The export work
we just shipped made the leaving-and-coming-back half of that loop fast; this
change removes it.

Everything needed is already here: the model merges several scans with
provenance, the export knows how to turn a selection into a target list, and the
parser reads whatever nmap writes. What is missing is the step in between —
choosing a command, running it, watching it, and folding the result back in.

It also removes the one case where the viewer has nothing to offer: pointed at a
directory with no scans in it, it exits with an error. That is exactly the
moment a scan should be started.

## What Changes

- **nmap is detected at startup** and the interface says so: its version when
  found, a muted indicator and a stated reason when not. Every scan action is
  unavailable, visibly, rather than failing when invoked.
- **A scope editor** when the viewer is opened with no scans to read — a
  multi-line field for addresses, CIDR ranges, hostnames and URLs, one per line,
  validated as they are typed. Opened on a directory that already has scans, the
  viewer behaves exactly as it does today.
- **Presets in the config file**, as a name → nmap arguments mapping, shipped
  with a small default set to be replaced by the user's own documented commands.
  Whether a preset needs root is **derived from its flags**, not declared.
- **A command is reviewed before it runs.** The chosen preset becomes an
  editable command line, then a confirmation shows the exact argv, the target
  count, the output path, and a reminder that the targets must be ones the user
  is authorised to scan. Nothing runs without that second step.
- **Privileged presets run through `sudo -n`** when the app is not already root:
  never a password prompt inside the TUI. When `sudo -n` is refused, the app
  says how to make it work rather than failing silently.
- **A Scans tab** — one scan at a time, every run of the session kept: the run
  list is the table, the selected run's report is the pane below, which is the
  same one-list-one-report shape as every other tab.
- **The live log streams while the scan runs.** `p` freezes the *log view* for
  reading; **the scan itself is never suspended** and the interface says so
  while frozen. `c` cancels the run for real.
- **Output is always `-oA`** into the directory the viewer was launched on (the
  working directory when it was launched on individual files), so a scan started
  here leaves exactly what an externally run scan leaves.
- **The result is merged and summarised**: the run's report toggles between a
  condensed overview, a diff against what was known before it, and the raw
  output.
- **The export dialog gains a destination**: scan the selected records, carrying
  their addresses into the same preset → command → confirm flow.
- **BREAKING (behaviour):** `seek nmap` with no readable scans no longer exits
  with an error when nmap is available; it opens the scope editor.

## Capabilities

### New Capabilities

- `nmap-scan-runner`: detecting nmap, defining a scope, choosing and editing a
  command, running it under supervision, streaming its output, and folding the
  result back into the model.

### Modified Capabilities

- `nmap-scan-viewer`: the **Entry point** requirement (no scans is no longer an
  error), and the **Derived lists can be exported** requirement (a scan is a
  destination). Specified by the unarchived `nmap-scan-viewer` change and
  amended by three later ones, so this delta archives after them.
- `configuration`: a new requirement for the preset table and the scan settings.

## Impact

- New `src/seek/nmap/presets.py` — the preset table, privilege derivation from
  flags, argv construction, output naming.
- New `src/seek/nmap/runner.py` — process supervision: launch, stream, cancel,
  exit classification. No Textual import.
- New `src/seek/nmap/diff.py` — what one scan added to what was known.
- New `src/seek/tui/nmap/scans.py` — the Scans tab: run list, live log, the
  three report modes.
- New `src/seek/tui/nmap/scope.py` — the scope editor and the command review.
- `src/seek/cli.py` — `seek nmap` with no readable scans opens the editor;
  `--no-scan` to opt out.
- `src/seek/config.py` — `nmap_presets`, `nmap_path`, `scan_output_dir`;
  regenerate `config.example.toml`.
- `src/seek/tui/nmap/app.py` — the Scans tab, the availability indicator, the
  export destination, merging a finished run into the model.
- Tests: `tests/test_nmap_presets.py`, `tests/test_nmap_runner.py` (against a
  stub executable, never a real scan), `tests/test_nmap_diff.py`, and the TUI
  flows in `tests/test_nmap_viewer.py`.
- No new dependencies: `asyncio`, `shlex`, `shutil.which`, `signal`.
- **Not in scope:** other tools (gowitness, masscan), scheduling or queueing
  runs, editing a preset from inside the app, and resuming a cancelled scan.
