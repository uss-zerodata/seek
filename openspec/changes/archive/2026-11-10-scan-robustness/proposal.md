# Proposal

## Why

An audit of the scan path found four faults:
- an edited command could scan hosts the user had taken out of it;
- two starts in the same moment ran two scans, and the first could not be cancelled;
- elevated scans failed when nmap was outside sudo's `secure_path`;
- a cancelled scan's cut-off XML was thrown away whole, finished hosts included, while the run claimed nothing was written.

## What Changes

- The targets of a scan are read from the edited command. The words that are neither an option nor an option's value, decided by the option catalogue, are the targets. The scope it was drafted from never comes back. A command with no target and no `-iL`/`-iR` is refused. The command runs in the order it was written.
- A runner is busy from the moment a run is accepted, not from its first step.
- An elevated scan runs nmap by the absolute path seek detected.
- A scan file that stops part-way keeps the hosts it finished and is reported as incomplete, not as unreadable. A cancelled run says its output so far is kept.

## Capabilities

### New Capabilities

### Modified Capabilities
- `nmap-scan-runner`: the targets come from the reviewed command; one run at a time holds for simultaneous starts; an elevated scan runs the nmap that seek found.
- `nmap-scan-viewer`: a cut-off scan file keeps its finished hosts.

## Impact

- `seek.nmap.options.split`: shared by `recent.strip` and `Session.plan_scan`, which loses its `targets` parameter.
- `seek.runner.Runner.claim`, called in `Session._start`.
- `seek.nmap.parse.parse_file`, `ScanFile.complete`, `NmapApp._say_unread`.
