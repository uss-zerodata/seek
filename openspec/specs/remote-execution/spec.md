# remote-execution Specification

## Purpose
Plan a scan or a capture in seek and run it on a different machine that does not have seek: copy the command, run it there, then copy the output back so that seek reads it.

## Requirements

### Requirement: A reviewed command can be copied in two forms
The nmap review and the capture review SHALL each offer a copy action with two forms: **as shown**, the exact argument vector this machine would run, joined with shell quoting; and **for another machine**, a self-contained shell snippet. The "as shown" form SHALL be offered only when the tool is available on this machine. Copying SHALL NOT start a process and SHALL NOT write a file.

#### Scenario: Copy as shown
- **WHEN** nmap is available and the user copies the reviewed command in the "as shown" form
- **THEN** the clipboard holds the reviewed argument vector, shell-quoted, with this machine's output path

#### Scenario: Copying runs nothing
- **WHEN** the user copies either form and then backs out of the review
- **THEN** no scan or capture has started and no file has been created or changed

### Requirement: Copying works without a clipboard
The copied text SHALL be put on the system clipboard. When no clipboard mechanism works, the system SHALL say so and SHALL show the full text in a form that the user can select and copy by hand.

#### Scenario: Copy without a clipboard
- **WHEN** the user copies a command and no clipboard mechanism works
- **THEN** the system says that the clipboard is unavailable and shows the full text for manual selection

### Requirement: The remote snippet runs on a machine with only the tool
The "for another machine" snippet SHALL run as pasted on a POSIX shell, in an empty directory, on a machine that has only the tool installed. It SHALL call the native `nmap` or `gowitness` binary by its bare name, never this machine's configured path and never a container wrapper. It SHALL quote every argument, so that a target, a URL or a script argument is never interpreted by the shell.

#### Scenario: Docker backend here, native there
- **WHEN** this machine captures with the gowitness container and the user copies a capture snippet
- **THEN** the snippet runs `gowitness` directly, with no `docker run`

### Requirement: The remote snippet elevates interactively
The snippet SHALL prefix `sudo`, not `sudo -n`, when the flags need root. It SHALL decide this by the same rule that the local review uses, whatever the privilege of this machine's user.

#### Scenario: Privileged preset on an unprivileged local user
- **WHEN** the reviewed nmap command contains `-sS` and the snippet is copied
- **THEN** the snippet runs `sudo nmap ...` and sudo has no `-n` flag

### Requirement: The remote snippet writes relative paths only
The snippet SHALL write every output to a path relative to the current directory. nmap output SHALL use the base name that a local run would use, in all three formats. A capture SHALL write to a `gowitness/` directory with its database and `screenshots/` inside it, and SHALL create its URL list itself with a quoted here-document. No absolute path of this machine, its user name or its scan directory SHALL appear in the snippet.

#### Scenario: Capture snippet
- **WHEN** the user copies a capture of 12 URLs for another machine
- **THEN** the snippet creates `gowitness/`, writes the 12 URLs into its URL file with a here-document, and runs `gowitness` with a relative database and screenshot path

#### Scenario: No local path leaks
- **WHEN** the scan directory is `/home/alice/engagement` and the snippet is copied
- **THEN** the text does not contain `/home/alice`

### Requirement: Results come back as files
The review SHALL state how to bring the results back: copy the nmap output files, or the `gowitness/` directory, into a scan directory of this session. The system SHALL NOT keep a record of copied commands and SHALL NOT wait for their results. Results copied back SHALL be read by the existing discovery, like a scan or capture made outside seek.

#### Scenario: Remote nmap output read back
- **WHEN** the user copies the `.xml` that the snippet produced into a scan directory and the sources are read again
- **THEN** its hosts are part of the model and it is listed in the scan history like any other file

#### Scenario: Remote capture read back
- **WHEN** the user copies the snippet's `gowitness/` directory into a scan directory and the sources are read again
- **THEN** its screenshots are shown under their services like those of a local capture

### Requirement: Planning does not need the tool installed
When nmap or gowitness is unavailable on this machine, the user SHALL still be able to go through the scan flow, or open the capture review, up to the review. The review SHALL show "start" as unavailable with the reason and SHALL offer the "for another machine" copy form.

#### Scenario: Planning a scan without nmap
- **WHEN** nmap is not installed and the user chooses a preset for three marked hosts
- **THEN** the review opens, "start" is unavailable and says that nmap was not found, and the remote snippet can be copied

### Requirement: Only reasons about the command stop a plan
A reason that applies only to running here (the tool is missing, a run of that tool is busy, the scan directory is not writable) SHALL NOT stop planning or copying. A reason that applies to the command itself (no targets, nothing to capture, no known open port for `{ports}`, a refused command) SHALL stop the plan as before.

#### Scenario: Copying a capture while a capture runs
- **WHEN** a capture is running and the user opens the capture review for another selection
- **THEN** "start" is unavailable because a capture is busy, the snippet can be copied, and the running capture's URL file is not overwritten

#### Scenario: Nothing to capture stays refused
- **WHEN** gowitness is missing and the selection has no HTTP service
- **THEN** the system says there is nothing to capture and no review opens

### Requirement: The browser offers the same copy actions
The browser's scan review and capture review SHALL offer the same two copy forms with the same text as the terminal, generated by the same code on the server. The copy SHALL use the browser's clipboard and SHALL show the text for manual selection when the clipboard is refused. The copy action SHALL have the same key in the terminal and in the browser.

#### Scenario: Same snippet in both front ends
- **WHEN** the same preset and targets are reviewed in the terminal and in the browser
- **THEN** the copied remote snippets are identical
