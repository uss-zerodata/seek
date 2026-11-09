## ADDED Requirements

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

### Requirement: One scan at a time holds for simultaneous starts
A tool SHALL be busy from the moment a run of it is accepted. A second start that arrives before the first run has produced anything SHALL be refused, whichever front end sends it.

#### Scenario: Two starts at once
- **WHEN** two scans are started in the same moment, for example a double click in the browser
- **THEN** one runs, the other is refused as busy, and the running one can be cancelled

### Requirement: An elevated scan runs the nmap that seek found
When a scan runs through sudo, the command SHALL name nmap by the absolute path that seek detected, not by a bare name that sudo would look up in its own path.

#### Scenario: nmap outside sudo's path
- **WHEN** nmap is installed in a directory on the user's PATH that is not in sudo's secure_path, and a scan needs root
- **THEN** the scan runs that nmap through sudo
