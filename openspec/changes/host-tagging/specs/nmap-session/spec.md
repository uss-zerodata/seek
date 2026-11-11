## ADDED Requirements

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
