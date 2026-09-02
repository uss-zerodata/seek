## Context

See proposal.md — Why. What shapes the approach:

- The viewer is **stateless**: the files named on the command line are the whole
  truth for a run, and every view is recomputed from the model. A scan that
  writes a file and re-reads it fits that rule; an incremental in-memory merge
  would break it.
- The screen is **one list, one report pane, one filter, one breadcrumb**, and a
  view is data (`View`: columns + `build(scans) -> [Row]`). A new tab that
  invents its own layout would be the first thing in the app to do so.
- Every action is a **bare key** — the filter is entered deliberately with `/`.
  Free letters left: `a c e f i l n o p t w y z`.
- Textual's event loop must never block; long work runs in a worker.
- `merge.load()` + `views.prepare()` parse 1.4 MB in ~11 ms, so re-reading every
  source file is cheap enough to be the merge strategy.
- The user's answers fix four things: **`sudo -n`** for privileged presets,
  **pause freezes the log and never the scan**, **`-oA` into the launch
  directory**, **one run at a time with a session history**.

## Goals / Non-Goals

**Goals**

- Running a scan is the same shape as reading one: same tab row, same list, same
  report pane, same keys.
- Nothing runs that the user has not read in full, twice.
- The editable command is not a shell prompt in disguise.
- A finished scan leaves exactly what an external run leaves.

**Non-Goals**

- Queueing, scheduling or resuming scans; editing presets in the app; other
  tools. Each is its own change.
- Persisting run history between sessions — the viewer stays stateless.
- Progress bars derived from anything but what nmap itself prints.
- Suspending a running scan (the user chose against it, see Decisions).

## Decisions

### The Scans tab is the same shape as every other tab

The run list is the table; the selected run's report is the pane below. No new
layout, no new focus model, and the existing sort, filter and mark machinery
applies unchanged.

```
 Hosts  Services  Statistics  By service  By product  By port  Scans
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━╺

      1 Scan            2 Scope        3 State     4 Elapsed  5 Result
      quick-tcp         4 targets      running     01:42      43% · 2 up
      discovery         10.0.0.0/24    done        00:31      3 new hosts
      udp-top-100       10.0.0.5       failed      00:02      sudo -n refused
─────────────────────────────────────────────────────────────────────────
 raw output · following                                       ⠋ running
   Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-01 14:22 CEST
   Nmap scan report for 10.0.0.1
   443/tcp open  https   Apache httpd 2.4.57
   Stats: 0:01:42 elapsed; 110 hosts completed (146 up), 146 undergoing
─────────────────────────────────────────────────────────────────────────
 250 host(s) across 2 scan(s)   3 runs  ·  ⌁ nmap 7.94
 ↑↓ select   o report view   p freeze log   c cancel   n new scan   ? help  …
```

*Alternative rejected:* a full-screen log view. It would be the only screen in
the app you cannot leave by pressing a tab, and the run list would have nowhere
to live.

### Availability is a status-line fact, not an icon

`⌁ nmap 7.94` when found, `⌁ nmap not found` muted when not — symbol plus text,
never colour alone, in the status line where the scan counts already are. The
Scans tab is always present; opened without nmap it explains what is missing and
how to fix it, which is more useful than a greyed-out tab the user cannot
interrogate.

### The scope editor is a view, not a modal

Opened with nothing to read, the app shows the scope editor in the list region —
same chrome, same status line, `Esc` still quits. Each line is validated as it
is typed and annotated in place, because a scope that is rejected wholesale
tells you nothing about which line was wrong.

```
  Scope — one target per line

  10.0.0.0/24                                        ✓ 256 addresses
  192.168.1.10                                       ✓
  example.test                                       ✓ hostname
  https://app.example.test:8443                      ✓ host · port 8443
  10.0.0.300                                         ✗ not an address
  # staging is out of scope

─────────────────────────────────────────────────────────────────────────
  4 valid targets · 1 invalid line · 258 addresses in scope
  ⌁ nmap 7.94    ↵ choose a scan    Esc quit
```

### Two steps, and the second one is a review

Preset → editable command → review. The review is deliberately not a yes/no on a
one-line question: it is the argv, the scope size, the output path, the
privilege level, and the authorisation reminder.

```
╭─ Start this scan? ──────────────────────────────────────────────────╮
│ nmap -sV --version-light -T4 --stats-every 10s                      │
│      -oA engagement/seek-quick-tcp-20260901T142233Z                 │
│      10.0.0.0/24 192.168.1.10 example.test app.example.test         │
│                                                                     │
│ scope      4 targets · 258 addresses                                │
│ writes     engagement/seek-quick-tcp-…-{xml,nmap,gnmap}             │
│ privilege  direct — no elevation needed                             │
│                                                                     │
│ ⚠ scan only what you are authorised to scan                         │
│ ↵ start · Esc back                                                  │
╰─────────────────────────────────────────────────────────────────────╯
```

### The command field is parsed, not interpreted

`shlex.split`, then refuse anything that is only meaningful to a shell (`| & ; <
> $ ` ( ) * ?` outside a quoted word), refuse a program that is not nmap, and
refuse user-supplied output flags. Executed with `create_subprocess_exec` — no
`shell=True`, ever.

*Why refuse rather than sanitise:* a field that silently drops half of what was
typed is worse than one that says why it will not run. The refusal names the
offending token.

### Privilege is derived from the flags, and elevation is `sudo -n`

`needs_root(args)` looks for the flags that actually require it (`-sS -sA -sW
-sM -sN -sF -sX -sU -sY -sZ -sO -O -A --traceroute --privileged`). Derived beats
declared: a command the user pastes is classified as correctly as a shipped one,
and a preset table cannot drift out of date.

When `os.geteuid() != 0` and the command needs root, argv becomes `sudo -n nmap
…`. `sudo -n` never prompts. When it is refused the run fails with the reason,
the exact command to run elsewhere, and one further affordance: **retry without
elevation** — because `setcap cap_net_raw+eip` on the nmap binary is a real and
common setup in which no elevation is needed at all.

*Alternative rejected:* `sudo -S` with a password field. A tool that also writes
files should not be handling a password.

### `p` freezes the display, never the process

The user's call, and the right one: nmap's timers run against the wall clock, so
`SIGSTOP` on a long pause can make hosts time out on resume and silently corrupt
the result. Freezing is a view state — the reader stops moving, the writer keeps
appending — and the pane header says so in words:

```
 raw output · frozen — the scan is still running               ⠋ running
```

`c` cancels for real: `SIGTERM` to the process group, `SIGKILL` after a grace
period, and the run is recorded as cancelled with the output it produced.

### Output is `-oA` into the launch directory, and merging is a re-read

The app appends `-oA <dir>/seek-<preset-slug>-<UTC>Z`; `<dir>` is the directory
the viewer was opened on, or the working directory when it was opened on files.
On success the app re-runs `prepare(load(sources + [new.xml]))` over **all**
sources rather than merging incrementally: the merge rules (probed beats table
guess, observed beats asserted, provenance) then apply identically to a scan
started here and one run outside, and there is no second merge path to keep
correct.

The rebuild has one consequence worth naming: marks hold `Record`s that point at
`Host` objects from the old model. After a rebuild, marks are **re-resolved by
identity** against the new model and any that no longer exist are dropped.

### Presets are `name -> arguments`, and the order is the config's

`nmap_presets: dict[str, str]` in the config file, validated exactly like
`editors` — no new config machinery, insertion order preserved, and a user's
table replaces the default rather than merging (a curated list should be exactly
what is offered).

```toml
[nmap_presets]
"Discovery (ping sweep)"        = "-sn -PE -PP -PS21,22,80,443 --stats-every 10s"
"Quick TCP (top 1000, -sV)"     = "-sV --version-light -T4 --stats-every 10s"
"Full TCP (-p-)"                = "-p- -sV -T4 --stats-every 30s"
"SYN stealth (top 1000)"        = "-sS -T4 --stats-every 10s"
"UDP top 100"                   = "-sU --top-ports 100 --stats-every 30s"
"Service + OS + default NSE"    = "-A --stats-every 30s"
"Vuln scripts"                  = "-sV --script vuln --stats-every 30s"
```

The shipped defaults carry `--stats-every`, which is why progress can be shown
without the app injecting flags behind the user's back: the progress line is
parsed if nmap prints one, and elapsed time is shown when it does not.

### Process supervision is async, the parsing is not

`runner.py` uses `asyncio.create_subprocess_exec` with a pipe, read line by line
in a Textual worker and posted as messages — the framework's own idiom for a
streaming child, and no thread to marshal back from. The log is a bounded
`deque` (20 000 lines) with a counter of what was dropped, because `-p- -v` on a
/24 produces far more than a screen's worth and unbounded growth in a
long-running TUI is a leak with a nice name.

`presets.py`, `runner.ScanRun` and `diff.py` import no Textual, so they can be
tested without a screen and reused by whatever runs the next tool.

### The diff is computed between two models, not two files

`diff(before_hosts, after_hosts)` → new hosts, newly open ports, changed service
identifications. Computed from the model, so it is the same comparison whether
the new data came from a scan started here or a file that appeared on disk.

## Risks / Trade-offs

- **An editable command is an execution surface** → parsed with `shlex`, no
  shell, program pinned to nmap, output flags refused, and the argv is shown in
  full before it runs. The refusal path is tested as carefully as the happy one.
- **`sudo -n` fails on a normal sudo setup** (no NOPASSWD, cold timestamp) →
  the failure names the cause and offers both ways out: `sudo -v` in another
  terminal, or retry unelevated for a capabilities-based install.
- **A frozen log reads like a paused scan** → the header says otherwise in
  words, and cancelling is a different key.
- **Re-reading every source on completion** costs a full re-parse → ~11 ms per
  1.4 MB, once per finished scan, against a merge path that cannot disagree
  with the file-loading one.
- **A scan started in a directory the user cannot write to** → checked before
  the review step, not after the scan.
- **Killing nmap loses the output file** — nmap writes `-oA` at the end → a
  cancelled run keeps its captured stdout, and says the file was not written.
- **Tests must never run a real scan** → the runner takes the program to execute
  from config (`nmap_path`), and every test points it at a stub script that
  prints canned output and exits.

## Open Questions

- The default preset table above is a placeholder. The user will supply their own
  documented commands; replacing the table is task 2.5 and changes no spec, no
  interface and no test beyond the fixture that reads it.
