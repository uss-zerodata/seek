# nmap-scan-runner Specification

## Purpose
Lets a scan be started, watched and folded back into the model from inside the
viewer, so that reading a scan and running the next one are one workflow rather
than two.

## Requirements

### Requirement: nmap is detected and its absence is visible
The system SHALL determine at startup whether nmap can be run, and SHALL report
what it found: the version when nmap is available, and a stated reason when it
is not. That state SHALL be visible in the interface without opening anything,
and SHALL NOT be conveyed by colour alone.

Every action that would start a scan on this machine SHALL be unavailable while
nmap is unavailable, and SHALL say why rather than failing when invoked.
Planning a scan up to its review, and copying the reviewed command for another
machine, SHALL remain available. The viewer's reading, filtering and exporting
SHALL work exactly as before with nmap absent.

#### Scenario: nmap is present
- **WHEN** the viewer starts and nmap is on the path
- **THEN** the interface shows that scanning is available, with the version found

#### Scenario: nmap is absent
- **WHEN** the viewer starts and nmap is not on the path
- **THEN** the interface shows scanning as unavailable with the reason, and the rest of the viewer is unaffected

#### Scenario: A scan action while unavailable
- **WHEN** the user goes through the scan flow and nmap is unavailable
- **THEN** the review explains why the scan cannot start here, offers to copy the command for another machine, and starts nothing

### Requirement: A scope is defined when there is nothing to read
When the viewer is opened on no readable scans and scanning is available, the
system SHALL offer an editor for defining a scope instead of exiting: a
multi-line field taking one target per line, accepting addresses, CIDR ranges,
hostnames and URLs, and ignoring blank lines and comments.

Targets SHALL be validated as they are entered, with invalid lines identified
individually rather than the whole scope being rejected, and the count of valid
targets SHALL be shown. A URL SHALL contribute its host, and its port where one
is given. Scanning SHALL be refused while no valid target exists.

When the viewer is opened on scans that can be read, it SHALL behave exactly as
it does today and SHALL NOT show the editor.

#### Scenario: An empty directory
- **WHEN** the viewer is opened on a directory containing no readable scans and nmap is available
- **THEN** the scope editor is shown rather than an error

#### Scenario: A line that is not a target
- **WHEN** the user types a line that is neither an address, a range, a hostname nor a URL
- **THEN** that line is marked invalid, the others are still counted, and scanning is refused until it is fixed

#### Scenario: A URL as a target
- **WHEN** the user enters `https://example.test:8443/admin`
- **THEN** the target is the host `example.test`, and the port `8443` is carried into the command

#### Scenario: Existing scans are unaffected
- **WHEN** the viewer is opened on a directory that does contain scans
- **THEN** the viewer opens on them as it does today, with no editor

### Requirement: A scan runs from a reviewed command
A scan SHALL be started only from a command the user has seen in full. The
system SHALL offer the configured presets by name, beside the guided builder
and the recently and frequently used commands; choosing any of them SHALL
produce the complete command as editable text, which the user MAY change
before running.

Before anything runs, the system SHALL present a confirmation showing the exact
arguments to be executed, the number of targets and the first of them, the file
the output will be written to, and whether the command will be run with elevated
privileges. The scan SHALL start only on an explicit confirmation at that step,
and cancelling at any step SHALL run nothing.

The confirmation SHALL state that the targets must be ones the user is
authorised to scan.

#### Scenario: Preset to command
- **WHEN** the user selects a preset
- **THEN** the full command, including the targets and the output path, is shown as editable text

#### Scenario: Builder to command
- **WHEN** the user finishes the builder and picks the fast or the reliable command
- **THEN** that command, with the targets, is shown as editable text, followed by the same review

#### Scenario: The second step
- **WHEN** the user confirms the command
- **THEN** a review of the exact arguments, the scope size, the output path and the privilege level is shown, and nothing runs until that is confirmed too

#### Scenario: Backing out
- **WHEN** the user cancels at the preset, the command or the review step
- **THEN** no process is started and nothing is written

### Requirement: A command is executed, never interpreted by a shell
The system SHALL execute the reviewed command as an argument vector, without a
shell. The edited text SHALL be split with shell-like word rules, and text that
would only be meaningful to a shell — pipes, redirections, command separators,
substitutions, globs — SHALL be refused with an explanation rather than being
passed through or silently ignored.

The command SHALL run nmap: the system SHALL refuse a command whose program is
anything else.

The system SHALL control the output arguments: it SHALL append `-oA` with a base
path of its own choosing, and SHALL refuse a command that carries its own output
arguments rather than trying to reconcile the two.

#### Scenario: A shell metacharacter
- **WHEN** the edited command contains a pipe or a redirection
- **THEN** it is refused with an explanation, and nothing runs

#### Scenario: Another program
- **WHEN** the edited command names a program other than nmap
- **THEN** it is refused

#### Scenario: The output arguments belong to the system
- **WHEN** the edited command carries its own `-oX` or `-oA`
- **THEN** it is refused with an explanation that output is handled for it

### Requirement: Privileged scans are elevated without seek handling a password
A command that needs elevated privileges SHALL be identified from its arguments, so that a command the user writes is classified like a shipped one. When the system is not already privileged, the system SHALL use the first route that works: nmap's own file capabilities (run unelevated, with `--privileged`), then sudo. The review SHALL say which route applies. The system SHALL NOT read, store or forward a password.

#### Scenario: Already privileged
- **WHEN** the application runs as root
- **THEN** the command runs directly, without elevation

#### Scenario: nmap has the capabilities
- **WHEN** the nmap binary has the raw-socket file capabilities and the command needs root
- **THEN** the command runs as the user with `--privileged` added and without sudo

#### Scenario: A scan needing root, unprivileged
- **WHEN** the user runs a preset whose flags require root, the application is not root, nmap has no capabilities, and sudo would run it without asking
- **THEN** it is run through `sudo -n` with no prompt

#### Scenario: Elevation is refused
- **WHEN** sudo refuses an elevated scan after it started
- **THEN** the run fails with that reason and how to make elevation work, and no password is asked for

### Requirement: Scans may run together, every run kept
The system SHALL let a scan start while another scan runs. The review before it
starts SHALL name every running scan and state the cost: the scans share the
network path, each one's timing adapts to the other's traffic, both take
longer, and rate-limited targets drop more probes. Starting SHALL stay possible.
A scan whose output files a running scan already writes SHALL be refused.

Every run of the session SHALL be listed with its preset, its scope, its state —
running, finished, failed or cancelled — its duration, and a one-line result.
Selecting a run SHALL show that run's report. Runs SHALL survive the completion
of the scan and SHALL NOT be persisted beyond the session.

#### Scenario: A second scan while one runs
- **WHEN** the user starts a scan while another is running
- **THEN** the review names the running scan and says what running both costs, and the scan starts when the user confirms

#### Scenario: The same output twice
- **WHEN** a scan would write to the output files of a scan that is running
- **THEN** it is refused, naming the running scan

#### Scenario: The run list
- **WHEN** three scans have been run in a session
- **THEN** all three are listed with their state, duration and result, and any of them can be selected

### Requirement: Output streams while the scan runs
The output of a running scan SHALL be shown as it is produced, and the display
SHALL follow the newest line unless the user has scrolled away from it. The user
SHALL be able to freeze the display; freezing SHALL NOT affect the scan, the
interface SHALL say the scan still runs, and no output SHALL be lost.

The user SHALL be able to cancel a running scan: the process ends and the run is
recorded as cancelled with its output. With several scans running, cancelling
SHALL act on the one the user chose.

Every route out of the application SHALL first name what is running and say
that leaving ends it and keeps only the hosts finished so far, and SHALL leave
only on an explicit answer. Dismissing that question SHALL keep the application
open. No scan SHALL be left running once the application has gone.

#### Scenario: Live output
- **WHEN** a scan is running
- **THEN** its output appears as it is produced and the view follows the newest line

#### Scenario: Freezing the display
- **WHEN** the user freezes the display
- **THEN** the view stops moving, the interface states that the scan is still running, and nothing is lost when it is unfrozen

#### Scenario: Cancelling
- **WHEN** the user cancels a running scan
- **THEN** the process ends, the run is recorded as cancelled, and the output it produced is kept

#### Scenario: Cancelling one of several
- **WHEN** two scans are running and the user cancels the one selected in the run list
- **THEN** that scan ends and the other keeps running

#### Scenario: Leaving while a scan runs
- **WHEN** the user quits, by any of the ways the application can be quit, while a scan is running
- **THEN** the system names the running scans, says that leaving ends them and keeps the hosts finished so far, and quits only on an explicit answer

#### Scenario: The safe answer is the easy one
- **WHEN** the user dismisses that question rather than answering it
- **THEN** the application stays open and the scan keeps running

#### Scenario: Leaving with nothing running
- **WHEN** the user quits and no scan is running
- **THEN** the application exits without asking

### Requirement: A finished scan is written where an external one would be
A scan SHALL leave its output in the directory the viewer was opened on — the
working directory when it was opened on individual files — in nmap's own
formats, under a name that identifies the preset and when it ran. The file
SHALL be indistinguishable in kind from one produced by running nmap outside
the application.

The result SHALL be merged into the model with the same provenance rules as any
other scan file. A scan that fails or is cancelled SHALL keep the hosts it
finished, and the file SHALL be named as incomplete.

#### Scenario: The file that is left behind
- **WHEN** a scan finishes successfully
- **THEN** its output is written to the launch directory in nmap's own formats, named for the preset and the time it ran

#### Scenario: The model catches up
- **WHEN** a scan finishes successfully
- **THEN** its hosts and services appear in the overviews, attributed to that scan

#### Scenario: A failed scan
- **WHEN** a scan fails or is cancelled after nmap finished some hosts
- **THEN** those hosts stay in the model, the file is named as incomplete, and the run says what happened

### Requirement: The scans are a history over time
The Scans tab SHALL present every scan file that is loaded, whether the
application ran it or it was already on disk, not only the runs of the current
session. Each SHALL be placed in the list by the time the scan started, so an
externally-run scan takes its true place in the order, and each SHALL be shown
alike — a scan is a scan.

Each scan SHALL be diffed against the merged state of every scan that started
before it, so the list reads as a history unfolding: the earliest is a baseline,
and each later one shows what it added — a host not seen before, a port not
previously open, a service identification that changed. A per-scan diff SHALL
reflect what that scan alone recorded, not the consolidated model.

A run started in the application that has produced its file SHALL appear once, as
that file; one that has not yet produced a file — still running, or failed before
writing — SHALL appear on its own with its live log.

#### Scenario: An externally-run scan appears
- **WHEN** the viewer is opened on a directory of scans none of which this session ran
- **THEN** each is listed in the Scans tab in the order it was started

#### Scenario: A later scan reads as what it added
- **WHEN** a service scan follows an earlier discovery scan of the same hosts
- **THEN** its entry lists the ports it opened that the discovery scan had not seen

#### Scenario: The baseline
- **WHEN** the earliest scan is viewed
- **THEN** it is shown as a baseline rather than a diff against nothing

#### Scenario: A per-scan view is that scan's own
- **WHEN** a scan is viewed whose hosts a later scan also covered
- **THEN** it shows what that scan alone recorded, not the merged total

#### Scenario: A finished run is listed once
- **WHEN** a scan run in the application finishes and writes its file
- **THEN** it appears once, as that file in the history, not also as a separate run

### Requirement: A run is reported three ways
Each finished run SHALL offer three views of its result, one at a time, with the
current one named: a condensed overview, a difference against what was known
before the run, and the raw output.

The condensed overview SHALL give at least the hosts and open ports the scan
found and how long it took. The difference SHALL list only what the run added or
changed — hosts not previously known, ports not previously open, and service
identifications that changed — and SHALL say plainly when a run added nothing.
The raw view SHALL show the output as nmap produced it.

#### Scenario: Switching views
- **WHEN** the user switches the report view of a finished run
- **THEN** the condensed, difference and raw views are each reachable and the current one is named

#### Scenario: A run that found something new
- **WHEN** a scan finds a host and two ports that were not in the model before
- **THEN** the difference view lists that host and those two ports, and nothing that was already known

#### Scenario: A run that added nothing
- **WHEN** a scan confirms only what was already known
- **THEN** the difference view says so rather than showing an empty list

### Requirement: The targets scanned are the ones in the reviewed command
The targets of a scan SHALL be the words of the reviewed command that are neither an option nor an option's value. The scope the command was drafted from SHALL NOT be added back. A command with no target and no target list (`-iL`, `-iR`) SHALL be refused with the reason. The review SHALL count the targets the command contains.

#### Scenario: Targets replaced by a list
- **WHEN** the user drafts a scan for two addresses and edits the command to `nmap -sT -iL hosts.txt`
- **THEN** the command that runs contains neither address

#### Scenario: A target added in the editor
- **WHEN** the user adds an address to the command in the editor
- **THEN** the address is scanned and the review counts it

#### Scenario: No target left
- **WHEN** the edited command has no target and no target list
- **THEN** it is refused, and the reason says that no target is left

### Requirement: A tool that runs one at a time is busy at once
A tool that runs one at a time, such as gowitness, SHALL be busy from the moment a run of it is accepted. A second start that arrives before the first run has produced anything SHALL be refused, whichever front end sends it.

#### Scenario: Two starts at once
- **WHEN** two captures are started in the same moment, for example a double click in the browser
- **THEN** one runs, the other is refused as busy, and the running one can be cancelled

### Requirement: An elevated scan runs the nmap that seek found
When a scan runs through sudo, the command SHALL name nmap by the absolute path that seek detected, not by a bare name that sudo would look up in its own path.

#### Scenario: nmap outside sudo's path
- **WHEN** nmap is installed in a directory on the user's PATH that is not in sudo's secure_path, and a scan needs root
- **THEN** the scan runs that nmap through sudo

### Requirement: sudo may ask in the terminal viewer, and only there
Before an elevated scan starts from the terminal viewer, the system SHALL find out whether sudo would run it without a password. If sudo would ask, the viewer SHALL give the terminal to sudo so that sudo itself asks, and start the scan when sudo accepted. The scan process SHALL stay in the viewer's terminal session, so that a sudo authorisation made in that terminal applies to it.

#### Scenario: Password sudo in the terminal viewer
- **WHEN** the user starts a scan that needs root, sudo needs a password, and nmap has no capabilities
- **THEN** sudo asks for the password on the terminal, and the scan starts once it is accepted

#### Scenario: The password is refused
- **WHEN** sudo does not accept the password
- **THEN** no scan starts and the viewer says why and how to make elevation work

### Requirement: The browser does not start a scan sudo would refuse
The browser SHALL NOT start an elevated scan that sudo would not run without a password. It SHALL refuse before anything runs and say how to make it work.

#### Scenario: Password sudo from the browser
- **WHEN** a scan that needs root is started from the browser and sudo would ask for a password
- **THEN** the request is refused before anything runs, naming the terminal viewer, root and setcap as the ways to make it work
