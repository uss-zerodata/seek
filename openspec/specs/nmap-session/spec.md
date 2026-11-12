# nmap-session Specification

## Purpose
One engagement session - the scans and captures read, the runs started, and the
records marked - shared by every front end attached to it, so the terminal and
the browser are two views of the same work rather than two copies of it.

## Requirements

### Requirement: One session behind every front end
A session SHALL hold the model read from the paths it was opened on, every scan
and capture run started in it, and the set of marked records. Every front end
attached to it - the terminal viewer, the web interface, or both - SHALL read and
change that one session. When a run finishes, the session SHALL fold its output
into the model once, and every front end SHALL see the new model.

#### Scenario: A scan started in the browser
- **WHEN** the user starts a scan from the web interface while the terminal viewer is open
- **THEN** the terminal viewer's Scans tab lists the run, and when it finishes both show the new hosts

#### Scenario: A capture started in the terminal
- **WHEN** a capture started in the terminal viewer finishes
- **THEN** the web gallery lists its screenshots on the next page load, without restarting anything

### Requirement: Marks belong to the session
Marking and unmarking SHALL change the session's marks, so a record marked in one
front end is marked in every other, and an export from either uses the same
marks in the same order.

#### Scenario: Mark in the browser, export in the terminal
- **WHEN** the user marks three hosts in the web interface and then opens the export dialog in the terminal viewer
- **THEN** the export offers those three marked hosts

#### Scenario: Clearing is shared too
- **WHEN** the user clears the marks in the terminal viewer
- **THEN** the web interface shows no marks on its next update

### Requirement: Where a user is stays with that user
Which tab is open, the filter, the sort, the drill-down path and the selected row
SHALL belong to each front end and SHALL NOT be changed by another. Two browser
windows SHALL be independent of each other in the same way.

#### Scenario: Filtering in one does not filter the other
- **WHEN** the user filters the host list in the browser
- **THEN** the terminal viewer's host list is unchanged

### Requirement: One run per tool, whoever starts it
The session SHALL run at most one nmap scan and one gowitness capture at a time,
whichever front end asks. A request to start a second run of a tool that is busy
SHALL be refused with what is running and for how long.

#### Scenario: A second scan from the other front end
- **WHEN** a scan started in the terminal is running and the user starts another from the browser
- **THEN** the browser is told a scan is already running, naming it

### Requirement: Front ends are told when something changes
The session SHALL notify its front ends when the model is replaced, a run starts,
produces output, or ends, and when the marks change, so each can update what it
shows without polling the whole model.

#### Scenario: Live output
- **WHEN** a running scan writes a line of output
- **THEN** every front end showing that run's log receives the line

### Requirement: Tags belong to the session
Tag definitions, manual tags, the computed tags and the rule problems SHALL be
held by the session, so every front end shows the same tags. A tag change made
in one front end SHALL reach every other.

#### Scenario: Tag in the browser, see it in the terminal
- **WHEN** the user tags a host `explored` in the web interface
- **THEN** the terminal viewer shows the host as `explored` on its next update

#### Scenario: A reload reaches every front end
- **WHEN** the user reloads the rule files in the terminal viewer
- **THEN** the web interface shows the recomputed tags on its next update

### Requirement: Tags follow the model
Tags SHALL be recomputed whenever the model, the captures, the rule files or the
manual tags change. A recomputation SHALL never show a mix of old and new tags.

#### Scenario: A scan adds a host
- **WHEN** a running scan adds a host that a rule matches
- **THEN** the host is tagged after the scan's results are read in

#### Scenario: A capture adds a title
- **WHEN** a capture finishes and gives port 80 the title a rule requires
- **THEN** the host is tagged without reading the scans again

#### Scenario: Marks survive a recomputation
- **WHEN** tags are recomputed while hosts are marked
- **THEN** the same hosts stay marked
