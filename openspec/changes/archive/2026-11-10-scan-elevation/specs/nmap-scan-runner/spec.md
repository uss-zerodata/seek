## RENAMED Requirements

- FROM: `### Requirement: Privileged scans use non-interactive elevation`
- TO: `### Requirement: Privileged scans are elevated without seek handling a password`

## MODIFIED Requirements

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

## ADDED Requirements

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
