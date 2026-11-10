## ADDED Requirements

### Requirement: A scan file that stops part-way keeps what it finished
A scan file whose XML stops part-way, as a cancelled or crashed scan leaves it, SHALL be read for every host it finished. The viewer SHALL name it as incomplete, with the number of hosts kept, and SHALL NOT report it as unreadable. A file that stops before any host is finished SHALL be reported as unreadable, as before.

#### Scenario: A cancelled scan
- **WHEN** a scan is cancelled after nmap finished two hosts
- **THEN** reading its file shows those two hosts and says the file is incomplete

#### Scenario: Nothing finished
- **WHEN** a scan file stops before its first host is complete
- **THEN** it is reported as unreadable
