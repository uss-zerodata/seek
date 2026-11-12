# Spec Delta

## ADDED Requirements

### Requirement: A row's host can be marked from anywhere
The viewer SHALL mark the host a row belongs to - from a host, a port, a
screenshot or a bucket row - with one key in both front ends, and unmark it when
it is marked. The gallery and a capture's page SHALL offer the same for the
capture's host.

#### Scenario: From a port
- **WHEN** the user stands on 80/tcp of `192.0.2.1` and presses `H`
- **THEN** the host `192.0.2.1` is marked, not the port

#### Scenario: From the screenshots
- **WHEN** the user presses "mark host" on a screenshot of `192.0.2.30`
- **THEN** `192.0.2.30` is marked, and the button says so on every screenshot of that host
