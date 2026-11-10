## RENAMED Requirements

- FROM: `### Requirement: One scan at a time, every run kept`
- TO: `### Requirement: Scans may run together, every run kept`

## MODIFIED Requirements

### Requirement: Scans may run together, every run kept
The system SHALL let a scan start while another scan runs. The review before it
starts SHALL name every running scan and state the cost: the scans share the
network path, each one's timing adapts to the other's traffic, both take
longer, and rate-limited targets drop more probes. Starting SHALL stay possible.
A scan whose output files a running scan already writes SHALL be refused.

Every run of the session SHALL be listed with its preset, its scope, its state —
running, finished, failed or cancelled — its duration, and a one-line result.
Selecting a run SHALL show that run's report. Runs SHALL survive the completion
of the scan and SHALL NOT be persisted beyond the session.

#### Scenario: A second scan while one runs
- **WHEN** the user starts a scan while another is running
- **THEN** the review names the running scan and says what running both costs, and the scan starts when the user confirms

#### Scenario: The same output twice
- **WHEN** a scan would write to the output files of a scan that is running
- **THEN** it is refused, naming the running scan

#### Scenario: The run list
- **WHEN** three scans have been run in a session
- **THEN** all three are listed with their state, duration and result, and any of them can be selected

### Requirement: Output streams while the scan runs
The output of a running scan SHALL be shown as it is produced, and the display
SHALL follow the newest line unless the user has scrolled away from it. The user
SHALL be able to freeze the display; freezing SHALL NOT affect the scan, the
interface SHALL say the scan still runs, and no output SHALL be lost.

The user SHALL be able to cancel a running scan: the process ends and the run is
recorded as cancelled with its output. With several scans running, cancelling
SHALL act on the one the user chose.

Every route out of the application SHALL first name what is running and say
that leaving ends it and keeps only the hosts finished so far, and SHALL leave
only on an explicit answer. Dismissing that question SHALL keep the application
open. No scan SHALL be left running once the application has gone.

#### Scenario: Live output
- **WHEN** a scan is running
- **THEN** its output appears as it is produced and the view follows the newest line

#### Scenario: Freezing the display
- **WHEN** the user freezes the display
- **THEN** the view stops moving, the interface states that the scan is still running, and nothing is lost when it is unfrozen

#### Scenario: Cancelling
- **WHEN** the user cancels a running scan
- **THEN** the process ends, the run is recorded as cancelled, and the output it produced is kept

#### Scenario: Cancelling one of several
- **WHEN** two scans are running and the user cancels the one selected in the run list
- **THEN** that scan ends and the other keeps running

#### Scenario: Leaving while a scan runs
- **WHEN** the user quits, by any of the ways the application can be quit, while a scan is running
- **THEN** the system names the running scans, says that leaving ends them and keeps the hosts finished so far, and quits only on an explicit answer

#### Scenario: The safe answer is the easy one
- **WHEN** the user dismisses that question rather than answering it
- **THEN** the application stays open and the scan keeps running

#### Scenario: Leaving with nothing running
- **WHEN** the user quits and no scan is running
- **THEN** the application exits without asking

### Requirement: A finished scan is written where an external one would be
A scan SHALL leave its output in the directory the viewer was opened on — the
working directory when it was opened on individual files — in nmap's own
formats, under a name that identifies the preset and when it ran. The file
SHALL be indistinguishable in kind from one produced by running nmap outside
the application.

The result SHALL be merged into the model with the same provenance rules as any
other scan file. A scan that fails or is cancelled SHALL keep the hosts it
finished, and the file SHALL be named as incomplete.

#### Scenario: The file that is left behind
- **WHEN** a scan finishes successfully
- **THEN** its output is written to the launch directory in nmap's own formats, named for the preset and the time it ran

#### Scenario: The model catches up
- **WHEN** a scan finishes successfully
- **THEN** its hosts and services appear in the overviews, attributed to that scan

#### Scenario: A failed scan
- **WHEN** a scan fails or is cancelled after nmap finished some hosts
- **THEN** those hosts stay in the model, the file is named as incomplete, and the run says what happened
