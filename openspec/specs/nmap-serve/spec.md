# nmap-serve Specification

## Purpose
`seek nmap serve` runs an engagement session and its web interface without the
terminal viewer, for a machine with no terminal to spare or a browser on a
second screen.

## Requirements

### Requirement: The session runs without the terminal viewer
`seek nmap serve` SHALL accept the same paths and options as `seek nmap`, read
them into a session exactly as the terminal viewer would, and serve the web
interface on the configured loopback address and port, with the same loopback
rule and port-in-use message. It SHALL print the address to open and SHALL keep
running until interrupted.

#### Scenario: Serving a directory
- **WHEN** the user runs `seek nmap serve ./scans`
- **THEN** the address of the web interface is printed and the browser can list the hosts read from `./scans`

#### Scenario: The configuration applies
- **WHEN** the configuration sets the web interface's port to 9000 and the user runs `seek nmap serve ./scans`
- **THEN** the interface listens on port 9000

### Requirement: A directory named `serve` is still a path
When the first argument is `serve` and a file or directory of that name exists in
the working directory, the system SHALL NOT guess: it SHALL say that `serve` is
ambiguous and how to name the directory (`./serve`) or the subcommand explicitly
(`seek nmap --serve`).

#### Scenario: Ambiguous
- **WHEN** a directory `serve` exists and the user runs `seek nmap serve`
- **THEN** the system explains the ambiguity and does nothing else

### Requirement: Stopping ends the runs it started
Interrupting `seek nmap serve` SHALL stop the server and SHALL cancel any scan or
capture still running in the session, as quitting the terminal viewer does, and
SHALL say which runs it cancelled.

#### Scenario: Interrupted during a scan
- **WHEN** the user presses Ctrl+C while a scan is running
- **THEN** the scan is cancelled, the server stops, and the terminal says the scan was cancelled

### Requirement: It can be opened straight away
`seek nmap serve` SHALL accept an option that opens the address in the system's
browser once the server is listening.

#### Scenario: Open on start
- **WHEN** the user runs `seek nmap serve --open ./scans`
- **THEN** the browser opens at the web interface once it is ready
