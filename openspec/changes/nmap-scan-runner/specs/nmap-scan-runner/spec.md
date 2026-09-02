## Purpose

Lets a scan be started, watched and folded back into the model from inside the
viewer, so that reading a scan and running the next one are one workflow rather
than two.

## ADDED Requirements

### Requirement: nmap is detected and its absence is visible
The system SHALL determine at startup whether nmap can be run, and SHALL report
what it found: the version when nmap is available, and a stated reason when it
is not. That state SHALL be visible in the interface without opening anything,
and SHALL NOT be conveyed by colour alone.

Every action that would run a scan SHALL be unavailable while nmap is
unavailable, and SHALL say why rather than failing when invoked. The viewer's
reading, filtering and exporting SHALL work exactly as before with nmap absent.

#### Scenario: nmap is present
- **WHEN** the viewer starts and nmap is on the path
- **THEN** the interface shows that scanning is available, with the version found

#### Scenario: nmap is absent
- **WHEN** the viewer starts and nmap is not on the path
- **THEN** the interface shows scanning as unavailable with the reason, and the rest of the viewer is unaffected

#### Scenario: A scan action while unavailable
- **WHEN** the user invokes a scan action and nmap is unavailable
- **THEN** the system explains why it cannot run rather than attempting it

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
system SHALL offer the configured presets by name; choosing one SHALL produce
the complete command as editable text, which the user MAY change before running.

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

### Requirement: Privileged scans use non-interactive elevation
A preset that needs elevated privileges SHALL be identified from the arguments
themselves rather than from a declaration, so that a command written by the user
is classified as correctly as a shipped one.

When such a command is run and the system is not already privileged, it SHALL be
run through non-interactive elevation, which never prompts for a password. The
system SHALL NOT read, store or forward a password.

When elevation is refused, the system SHALL report that plainly and say how to
make it work — running the viewer as root, or authorising elevation outside the
application — and SHALL leave the command available to copy.

#### Scenario: A scan needing root, unprivileged
- **WHEN** the user runs a preset whose flags require root and the application is not root
- **THEN** it is run through non-interactive elevation

#### Scenario: Elevation is refused
- **WHEN** non-interactive elevation is refused
- **THEN** the run fails with that reason and how to resolve it, and no password is requested

#### Scenario: Already privileged
- **WHEN** the application is already running as root
- **THEN** the command is run directly, without elevation

### Requirement: One scan at a time, every run kept
The system SHALL run at most one scan at a time and SHALL refuse to start
another while one is running, saying which is running.

Every run of the session SHALL be listed with its preset, its scope, its state —
running, finished, failed or cancelled — its duration, and a one-line result.
Selecting a run SHALL show that run's report. Runs SHALL survive the completion
of the scan and SHALL NOT be persisted beyond the session.

#### Scenario: A second scan while one runs
- **WHEN** the user starts a scan while another is running
- **THEN** it is refused, naming the running scan

#### Scenario: The run list
- **WHEN** three scans have been run in a session
- **THEN** all three are listed with their state, duration and result, and any of them can be selected

### Requirement: Output streams while the scan runs
The output of a running scan SHALL be shown as it is produced, not after it
finishes, and the display SHALL follow the newest line unless the user has
scrolled away from it.

The user SHALL be able to freeze the display for reading. Freezing the display
SHALL NOT suspend, signal or otherwise affect the scan, and while frozen the
interface SHALL say that the scan is still running. Output produced while frozen
SHALL NOT be lost.

The user SHALL be able to cancel a running scan, which SHALL end the process,
and the run SHALL be recorded as cancelled with the output it produced.

A running scan SHALL NOT be ended by accident: because a scan writes its output
only once it finishes, quitting mid-run discards the work, so every route out of
the application SHALL first say what is running and what leaving costs, and
SHALL leave only on an explicit answer. Dismissing that question SHALL keep the
application open. No scan SHALL be left running once the application has gone.

#### Scenario: Live output
- **WHEN** a scan is running
- **THEN** its output appears as it is produced and the view follows the newest line

#### Scenario: Freezing the display
- **WHEN** the user freezes the display
- **THEN** the view stops moving, the interface states that the scan is still running, and nothing is lost when it is unfrozen

#### Scenario: Cancelling
- **WHEN** the user cancels a running scan
- **THEN** the process ends, the run is recorded as cancelled, and the output it produced is kept

#### Scenario: Leaving while a scan runs
- **WHEN** the user quits, by any of the ways the application can be quit, while a scan is running
- **THEN** the system says which scan is running and that leaving ends it, and quits only on an explicit answer

#### Scenario: The safe answer is the easy one
- **WHEN** the user dismisses that question rather than answering it
- **THEN** the application stays open and the scan keeps running

#### Scenario: Leaving with nothing running
- **WHEN** the user quits and no scan is running
- **THEN** the application exits without asking

### Requirement: A finished scan is written where an external one would be
A successful scan SHALL leave its output in the directory the viewer was opened
on — the working directory when it was opened on individual files — in nmap's
own formats, under a name that identifies the preset and when it ran. The
resulting file SHALL be indistinguishable in kind from one produced by running
nmap outside the application.

The result SHALL then be merged into the model with the same provenance rules as
any other scan file, so that the overviews, filters and exports include it
immediately.

#### Scenario: The file that is left behind
- **WHEN** a scan finishes successfully
- **THEN** its output is written to the launch directory in nmap's own formats, named for the preset and the time it ran

#### Scenario: The model catches up
- **WHEN** a scan finishes successfully
- **THEN** its hosts and services appear in the overviews, attributed to that scan

#### Scenario: A failed scan
- **WHEN** a scan fails or is cancelled
- **THEN** the model is unchanged and the run says what happened

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
