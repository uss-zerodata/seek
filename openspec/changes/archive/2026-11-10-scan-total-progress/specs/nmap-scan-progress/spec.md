## ADDED Requirements

### Requirement: A running scan shows the progress of the whole scan
While an nmap scan runs, its run SHALL show an overall percentage, the hosts
finished out of the total, the current host group's phase and percentage, and an
estimate of the time left. A host SHALL count as finished when nmap reports it,
up or down. The current group SHALL count by its size and its phase's progress.

#### Scenario: A scan of several groups
- **WHEN** a scan of 512 addresses has reported 128 hosts and is halfway through the port scan of a group of 64
- **THEN** the run shows about 31 %, 128 of 512 hosts, and the group's port scan at 50 %

#### Scenario: Down hosts
- **WHEN** nmap reports 40 hosts as down after host discovery
- **THEN** they count as finished

### Requirement: The total is counted without probing
When a scan starts, the system SHALL count its targets by listing them with
nmap (`-sL -n`), over the same target options, so that ranges, CIDR, `-iL` and
`--exclude` count as nmap counts them. Counting SHALL send nothing to the
targets and SHALL NOT delay the scan. With `-iR`, or when counting fails, the run
SHALL show counts without a percentage of the whole.

#### Scenario: Excluded addresses
- **WHEN** a scan covers 10.0.0.0/24 with `--exclude 10.0.0.1`
- **THEN** the total is 255

#### Scenario: Random targets
- **WHEN** a scan uses `-iR 100`
- **THEN** the run shows the hosts reported and the group's progress, and no overall percentage

### Requirement: The overall figure is honest
The overall percentage SHALL never go back while the scan runs, and SHALL stay
below 100 % until nmap ends. Without `-v`, nmap reports only up hosts, so the
run SHALL NOT show an overall percentage. It SHALL show the hosts reported and
say that `-v` gives the scan's progress.

#### Scenario: A new phase
- **WHEN** a group moves from the port scan at 90 % to the service scan at 5 %
- **THEN** the overall percentage does not drop

#### Scenario: Without -v
- **WHEN** a scan runs without `-v`
- **THEN** the run shows the hosts reported and that `-v` gives progress, and no overall percentage

### Requirement: Milestones follow the whole scan
Progress notifications SHALL be sent when the overall percentage first reaches
25, 50 and 75 %. A group's phase percentage SHALL NOT send them. A run with no
overall percentage SHALL send none until it ends.

#### Scenario: The first group of many
- **WHEN** the first of ten groups reaches 80 % of its port scan
- **THEN** no milestone is sent
