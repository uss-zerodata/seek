## MODIFIED Requirements

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
