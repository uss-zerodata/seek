## Purpose

Help the user arrive at the nmap command that suits the question and the network: a guided builder that explains every trade-off and derives timing from data, and a list of commands used before.

## ADDED Requirements

### Requirement: The chooser offers the builder and earlier commands beside the presets
When the user starts a new scan, the chooser SHALL offer, in this order: the guided builder, the recently used commands, the most frequently used commands, and the configured presets. Choosing any of them SHALL lead to the editable command and then the review, as a preset does.

#### Scenario: Opening the chooser
- **WHEN** the user starts a new scan for marked hosts
- **THEN** the chooser lists "build a command", then recent commands, then frequent commands, then the presets

#### Scenario: Reusing a command
- **WHEN** the user chooses a recent command
- **THEN** its arguments are combined with the current targets and shown as the editable command

### Requirement: Earlier commands never carry targets
A recent or frequent command SHALL be the arguments of a command only. Targets, output flags and their file names SHALL be removed. The commands SHALL come from the scan files of the session and from a history file in the user's state directory. The history file SHALL record a command when a scan started from seek, after the targets and output flags are removed, with how often and when it was last used. Nothing else SHALL be written.

#### Scenario: A command from a scan file
- **WHEN** a scan file records `nmap -sS -T4 -p 22,80 -oA out/scan 10.0.0.0/24`
- **THEN** the recent list offers `-sS -T4 -p 22,80`

#### Scenario: The history file
- **WHEN** a scan of `10.0.0.5` with `-sV --script vuln` is started
- **THEN** the history file gains `-sV --script vuln` and contains no address, host name or path

### Requirement: The builder asks goal-first questions and shows the command as it grows
The builder SHALL ask one step at a time: the goal, then the protocol and port breadth where the goal needs ports, then how the hosts are reached, then the network conditions. A step that the goal makes irrelevant SHALL be skipped. Each step SHALL show the command built so far. Going back one step SHALL keep the later answers that still apply.

#### Scenario: A discovery goal
- **WHEN** the user chooses "find live hosts"
- **THEN** no port breadth step is asked, and the command contains `-sn`

#### Scenario: Going back
- **WHEN** the user goes back from the network step to the breadth step
- **THEN** the breadth choice made before is still selected

### Requirement: Every choice states its trade-off
Each choice in the builder SHALL state what it gains and what it costs, in one or two lines each, where possible with a measured figure from nmap's documentation, such as the share of open ports the top 100 or top 1000 ports find. The explanation SHALL name the options that the choice adds to the command.

#### Scenario: Port breadth
- **WHEN** the breadth step is shown for TCP
- **THEN** "top 100" says it is fastest and finds about 78 % of open TCP ports, "top 1000" about 93 %, and "all ports" says it finds everything at about 65 times the work of top 1000

### Requirement: The builder always ends with a fast and a reliable command
The last step SHALL present two complete commands for the same answers: one built for speed and one built for reliability. Each SHALL list the options in which they differ, and what the fast one may miss. Both SHALL be offered whatever the answers are. The two SHALL differ only in options the user has not set: a value the user set SHALL appear unchanged in both.

#### Scenario: A value the user set
- **WHEN** the user set `--max-retries 3` in the fine-tune step
- **THEN** both the fast and the reliable command contain `--max-retries 3`, and neither profile changes it

#### Scenario: UDP service identification
- **WHEN** the answers are "identify services", UDP, top 100
- **THEN** the fast command contains `--version-intensity 0` and a lower `--max-retries`, the reliable command contains neither, and the fast one says it may report fewer versions and more `open|filtered` ports

### Requirement: Timing comes from earlier scans when they cover the targets
When earlier scans in the session recorded round-trip times for some of the targets, the builder SHALL derive the RTT timeouts from them: an initial timeout of about twice the largest smoothed round-trip time, and a maximum of three times it for speed and four times it for reliability, kept between 100 ms and 1000 ms. The command step SHALL say which values were derived, from how many hosts, and from which data.

#### Scenario: A LAN seen before
- **WHEN** earlier scans recorded round-trip times of 0.4 to 1.2 ms for the targets
- **THEN** both commands use `--max-rtt-timeout 100ms`, and the step says the value is the documented lower bound, based on the RTTs measured on those hosts

#### Scenario: No earlier data
- **WHEN** no earlier scan covers the targets and the user declines to measure
- **THEN** the commands use the template defaults (`-T4` for speed, `-T3` timing for reliability), and the step says that nothing was measured

### Requirement: A measurement is taken only after the user confirms it
The builder SHALL offer to measure round-trip times when no earlier data covers the targets. Before anything is sent, it SHALL state what it will send, to how many hosts, and how long it may take. It SHALL send nothing without that confirmation. The measurement SHALL use TCP connections to open ports already known, or otherwise a host discovery scan, limited to a small number of hosts and a few seconds. Its result SHALL be used like data from an earlier scan, and labelled as measured.

#### Scenario: Measuring known open ports
- **WHEN** the targets have known open ports and the user confirms the measurement
- **THEN** a few TCP connections per host to those ports are timed, and the commands use the derived timeouts, labelled as measured now

#### Scenario: Declining
- **WHEN** the user declines the measurement
- **THEN** no packet is sent, and the builder continues with defaults

### Requirement: The browser offers the same chooser and builder
The browser SHALL offer the same chooser entries, the same builder steps and explanations, the same two commands, and the same confirmed measurement. All of them SHALL be generated by the same code as in the terminal.

#### Scenario: Same answers, same commands
- **WHEN** the same answers are given in the terminal and in the browser for the same targets
- **THEN** both offer the same fast and reliable commands

### Requirement: Recorded round-trip times are read
The reader SHALL keep, for each host, the smoothed round-trip time, its variance and the timeout that nmap recorded, when a scan file has them.

#### Scenario: A host with timing
- **WHEN** a scan file has `<times srtt="1200" rttvar="400" to="100000"/>` for a host
- **THEN** that host's recorded round-trip time is 1.2 ms, its variance 0.4 ms and its timeout 100 ms

### Requirement: Every nmap option can be set
The builder SHALL know every option that nmap documents in its option summary and its man pages, in nmap's own eleven groups. A fine-tune step SHALL list them all, by group, and SHALL let the user set, change or clear any of them.

#### Scenario: An option outside the guided steps
- **WHEN** the user opens fine-tune and sets `--data-length 24` under firewall/IDS evasion
- **THEN** the command contains `--data-length 24`

### Requirement: Options seek controls are shown, not offered
The options seek controls itself SHALL be listed in fine-tune with the reason, and SHALL NOT be settable: the output files (`-oN`, `-oX`, `-oS`, `-oG`, `-oA`, `--append-output`), the target input (`-iL`, `-iR`), and the modes that do not scan (`--resume`, `--iflist`, `--script-help`, `--script-updatedb`, `-V`, `-h`).

#### Scenario: An option seek controls
- **WHEN** the user looks for `-oX` in fine-tune
- **THEN** it is listed as handled by seek, which writes all three formats beside the scans, and it cannot be set

### Requirement: An option's value is checked where it is typed
Each option SHALL accept only its documented value form: none, a number within its range, a time with an `ms`, `s`, `m` or `h` unit, a port list, a comma list, a choice from a fixed set, or text. An invalid value SHALL be named under the field with what is expected, and SHALL stay out of the command until it is valid. When two options conflict according to nmap's documentation, the builder SHALL name both and the rule, and SHALL keep the command valid.

#### Scenario: A bad time
- **WHEN** the user types `fast` as `--host-timeout`
- **THEN** the field says a time is expected (for example `30m` or `900s`), and the command does not change

#### Scenario: Two TCP scan types
- **WHEN** `-sS` is set and the user sets `-sT`
- **THEN** the builder says only one TCP scan type can run at a time, and the command contains only the one chosen last

#### Scenario: A combination nmap allows
- **WHEN** `-sS` is set and the user sets `-sU`
- **THEN** both stay, because UDP may be combined with one TCP scan type

### Requirement: Every value says where it came from
Each option in the command SHALL carry where its value came from: the user, the goal, the speed or reliability profile, earlier scans, a measurement, or nmap's default. The fine-tune step and the final step SHALL show this beside the value. A value the user set SHALL take priority over every other source, and the user SHALL be able to return it to the derived value.

#### Scenario: Provenance of a timeout
- **WHEN** `--max-rtt-timeout 100ms` was derived from earlier scans
- **THEN** it is shown as "from earlier scans: slowest of 12 hosts 1.2 ms, raised to the 100 ms floor"

#### Scenario: Resetting a value
- **WHEN** the user set `--max-rtt-timeout 400ms` and then resets it
- **THEN** the derived value and its source are shown again

### Requirement: Each option explains itself
For the option under the cursor, the builder SHALL show its documented description, the form of its value, its default, whether it needs root, what it conflicts with, and the nmap documentation page it comes from.

#### Scenario: Help on an option
- **WHEN** the cursor is on `--defeat-rst-ratelimit`
- **THEN** the help says it ignores RST rate limits for SYN-type scans, that closed ports may then show as filtered, that it takes no value, and names the timing and performance page

### Requirement: The builder is easy to follow and fully keyboard driven
The builder SHALL always show which step the user is on and which steps are done or still ahead, and SHALL let the user jump back to a done step. It SHALL show the command built so far at all times, and a line naming the keys of the current step. Every action SHALL be possible from the keyboard. The recommended choice of a step SHALL be marked in words, not by colour alone. Leaving with answers given SHALL ask before discarding them.

#### Scenario: Where am I
- **WHEN** the user is on the network step after answering the goal, protocol and breadth
- **THEN** the step indicator shows those three as done, the network step as current, and fine-tune and choose as ahead

#### Scenario: Leaving with answers
- **WHEN** the user presses Esc after answering two steps
- **THEN** the builder asks whether to discard the answers, and stays open if the user says no

### Requirement: The builder fits the terminal
The builder SHALL fit terminals from 60x18 upwards: the step, the command and the key line SHALL stay on screen, and the long parts SHALL scroll. When there is room, it SHALL use the width for the step list and for option help beside the content.

#### Scenario: A small terminal
- **WHEN** the builder is opened in a 60x18 terminal
- **THEN** the step, the choices, the command and the key line are all on screen, and the choices scroll

#### Scenario: A wide terminal
- **WHEN** the builder is opened in a 160x48 terminal
- **THEN** the step list, the content and the help for the focused option are side by side
