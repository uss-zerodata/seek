# Design

## Context

What nmap 7.94 printed when run as seek runs it (stdin from `/dev/null`, its own
process group), checked on loopback and on down hosts in a network namespace:

- `--stats-every` prints **nothing**. The stats lines come from nmap's keypress
  handler, which needs an interactive terminal on stdin that nmap controls. A
  pty on stdin alone is not enough. A session of nmap's own would be, but it
  breaks sudo's per-terminal authorisation (the scan-elevation fix).
- With `-v`, each phase starts with `Initiating <Phase> at …` and
  `Scanning N hosts [P ports/host]`, or `Scanning <host> [P ports]` for one host.
  Host discovery (`Ping Scan`) runs ahead in larger batches than the port scan.
- With `-v`, each finished host gets a report line, down hosts included
  (`Nmap scan report for 10.99.0.2 [host down]`, right after discovery). Without
  `-v`, only up hosts are reported.
- nmap prints `<Phase> Timing: About X% done; ETC: …` by itself during long
  phases.
- `nmap -sL -n <targets> [--exclude …] [-iL f]` ends with
  `Nmap done: N IP addresses`, and sends no packet.

- nmap's stdout is block-buffered into a pipe and flushed at points of its own:
  a phase start, its timing lines, the end of a host group. Phase and group
  lines arrive promptly. Down-host reports made just after discovery can wait
  for the next flush: 13 s, measured, when the up host's port scan printed no
  timing line.

## Goals / Non-Goals

**Goals:** one figure for the whole scan, honest about what it does not know, the
same in the terminal and the browser, and used by the milestones.

**Non-Goals:** making `--stats-every` work; a per-phase weighting model (`-sV`
vs scripts vs OS).

## Decisions

### D1: The total from `nmap -sL -n`, in the background
- **How:** `Session.start_scan` starts the count as an asyncio subprocess, with
  `config.nmap_path`, no sudo, and stdin `/dev/null`.
- **What it passes:** the command's targets plus its target-selecting options
  (`-iL`, `--exclude`, `--excludefile`), taken with `options.split`.
- **What it reads:** stdout is drained line by line, keeping only the last
  line, because a /8 lists 16 million lines. It sets `run.total` from
  `Nmap done: N IP address(es)`.
- **When it gives up:** a timeout of 60 s, or any error, leaves `total` as `None`.
- **When it isn't run:** a command with `-iR` is not counted.
- **Why nmap, not our own parser:** nmap's target grammar (`10.0-3.1-254`,
  `-iL`, IPv6, exclusions) is nmap's to define. A parser of our own would drift
  from it, and the count would be wrong exactly where it matters.

### D2: What `ScanRun.read_progress` reads
- **`Initiating <Phase> …`:** sets `phase`, and resets `phase_pct` to 0.
- **`Scanning N hosts [` or `Scanning <one host> [`:** sets `group` to N or 1,
  unless the phase is host discovery (`Ping Scan`, `ARP Ping Scan`), which runs
  in larger batches whose hosts are counted when reported.
- **`Nmap scan report for …`:** adds 1 to `finished`. If the line has no
  `[host down]`, it also adds 1 to `reported_up`.
- **`About X% done`:** sets `phase_pct`.
- **`verbose`:** whether the command has `-v`/`-vv`/`-v2`…, known from argv at
  construction (`ScanRun.verbose`).

### D3: The figure
- **Formula:** `overall = min(finished + group × phase_pct, finished + group) / total`.
  The group term is dropped once its hosts are reported: `group` is reset to 0
  on the first report line after a `Scanning` line.
- **Bounds:** clamped to `[last, 0.99]`, so the figure is monotonic and below
  100 % until nmap ends.
- **When there is none:** `fraction()` returns it only when `verbose` and
  `total` are both known. Otherwise it returns `None`, and milestones send
  nothing until the end.
- **Time left:** `elapsed × (1 − f) / f`, only once `f ≥ 0.02`, shown as "≈".

### D4: What is shown
`ScanRun.progress()` gives one line for the run row:
- with a total: `≈ 31% · 128/512 hosts · port scan 50%`;
- without `-v`: `14 up hosts reported · group 45% · -v gives progress`;
- with no total: `128 hosts · port scan 50%`.

The record (`scans.py`) adds the time left. The web reads the same record.

### D5: `--stats-every`
The catalogue entry's text adds "prints nothing when seek runs nmap: nmap prints
stats only for an interactive terminal". `_STATS_ALT` and `hosts_up` go.

## Risks / Trade-offs

- **Phases are unweighted.** A long `-sV` after a fast port scan holds the figure
  for a while. The clamp keeps it from going back, which is honest, just coarse.
- **One `-sL` per scan start.** For a /8 that's tens of seconds of CPU on the
  viewer's machine, in a child process. Until it finishes, there are counts only.
- **Hostnames** count as one target each, as `-sL -n` counts them.
- **Counts lag nmap's flushes.** In a long scan, the lag is at most one timing
  line or one group. `stdbuf -oL` was rejected: it does nothing for an nmap with
  file capabilities, because the loader ignores `LD_PRELOAD` there. A pty for
  stdout was rejected too: it would make `\r\n` line endings and sudo's own pty
  handling seek's problem.
