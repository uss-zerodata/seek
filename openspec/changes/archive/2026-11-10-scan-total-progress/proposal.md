# Proposal

## Why

nmap scans in host groups, and the percentage nmap prints ("SYN Stealth Scan
Timing: About 45% done") covers one phase of the current group only. On a
multi-group scan, the Scans tab's figure resets with every phase and every
group, and says nothing about how much of the scan is left. The 25/50/75 %
notifications read the same figure, so "75 %" can arrive during the first group.
seek also expects nmap's `--stats-every` lines ("N hosts completed"), but nmap
prints those only when its stdin is a terminal it controls, which it never is
under seek. That is deliberate: the sudo fix needs nmap in the viewer's session.

## What Changes

- A running scan shows the progress of the whole scan: an overall percentage, the
  hosts finished out of the total, and the current group's phase and percentage,
  with an estimate of the time left.
- The total is counted as the scan starts, by `nmap -sL -n` over the same target
  options. That lists targets without sending a packet and handles ranges, CIDR,
  `-iL` and `--exclude`. With `-iR`, or when the count fails, there is no total,
  and the run shows counts only.
- Hosts finished are nmap's report lines. With `-v`, these include the hosts
  found down. Without `-v`, only up hosts are reported, so no overall figure is
  claimed: the run says how many hosts were reported and that `-v` gives the
  scan's progress.
- The overall figure never goes back, and stays below 100 % until the scan ends.
- The 25/50/75 % notifications follow the overall figure.
- The fine-tune list says that `--stats-every` prints nothing when seek runs
  nmap. The unused parsing of its "hosts completed" line is removed.

## Capabilities

### New Capabilities
- `nmap-scan-progress`: how far a running nmap scan is, over the whole scan:
  the total, what counts as finished, the group, the estimate, what is shown
  without `-v` or a total, and the figure that milestones read.

### Modified Capabilities
(none - the notification requirement already says "the run's reported progress";
this change defines that figure.)

## Impact

- `seek/nmap/runner.py` (`ScanRun`: parse group, phase, reports; `fraction`,
  `progress`).
- `seek/nmap/session.py` (count the targets as a scan starts).
- `seek/nmap/presets.py` or `options.py` (the target-selecting options of a command).
- `seek/tui/nmap/scans.py` (the run row and record show the new progress; the web
  reads the same record).
- `seek/nmap/options.py` (the `--stats-every` note).
- No new dependency.
