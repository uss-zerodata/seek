## Purpose

Tell the user through an ntfy-compatible webhook when a scan or capture ends and, if asked, how far it has got, without sending anything about the engagement itself.

## ADDED Requirements

### Requirement: A notification URL is configured and chosen per run
The configuration SHALL have a notification URL, empty by default, and a progress switch, off by default. A URL without a scheme SHALL be read as `https://`. A URL that is not http or https SHALL be refused when the configuration is read. Every scan review and capture review SHALL show the URL and the switch with the configured values. The user SHALL be able to change both, or clear the URL, for that run only.

#### Scenario: A configured default
- **WHEN** `notify_url = "notify.hektor.cc/test"` is configured and the user opens a scan review
- **THEN** the review shows `https://notify.hektor.cc/test`, and a run started from it notifies that URL

#### Scenario: Turned off for one run
- **WHEN** the user clears the URL in the review and starts the run
- **THEN** no notification is sent for that run, and the next review shows the configured URL again

#### Scenario: Nothing configured
- **WHEN** no URL is configured and the user leaves the field empty
- **THEN** no request leaves the machine

### Requirement: The end of a run is notified
When a run with a notification URL ends, the system SHALL POST one message to that URL in ntfy's format: the message text as the body, and a title, tags and priority as headers. This SHALL apply to nmap scans and to gowitness captures, from either front end. A failed or cancelled run SHALL be notified like a finished one, with its outcome.

#### Scenario: A scan finishes
- **WHEN** a scan with a notification URL finishes
- **THEN** one message arrives whose title names the preset and whose text says it finished and how long it took

#### Scenario: A capture fails
- **WHEN** a capture with a notification URL fails
- **THEN** one message arrives saying that the gowitness capture failed, with a higher priority than a success

### Requirement: Progress is notified at milestones when asked
When the progress switch is on for a run, the system SHALL send one message the first time the run's reported progress reaches each of 25, 50 and 75 percent. When the run reports no progress, the system SHALL send nothing until the run ends.

#### Scenario: A long scan with progress on
- **WHEN** a scan with progress on reports 30 %, then 80 %
- **THEN** a message for 25 % is sent at the first report, and messages for 50 % and 75 % at the second, each once

#### Scenario: Progress off
- **WHEN** progress is off for a run
- **THEN** only the message at the end is sent

### Requirement: A notification says nothing about the engagement
A notification SHALL contain only the preset name or the tool name, the outcome or the milestone, and the elapsed time. It SHALL NOT contain a target, an address, a host name, a URL, a file path, a directory name or any output of the tool.

#### Scenario: Message content
- **WHEN** a scan of `10.0.0.0/24` writing to `/home/alice/acme` finishes
- **THEN** the message contains neither `10.0.0` nor `acme` nor any line nmap printed

### Requirement: A failed delivery never affects the run
A notification SHALL be sent without blocking the interface or the run. When delivery fails, the run's state and result SHALL stay as they are, and the failure SHALL be written into the run's log with the reason.

#### Scenario: The webhook is unreachable
- **WHEN** the notification URL cannot be reached at the end of a scan
- **THEN** the scan is still listed as finished, and its log says that the notification failed and why
