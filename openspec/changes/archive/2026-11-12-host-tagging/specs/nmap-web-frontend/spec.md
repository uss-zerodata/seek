## ADDED Requirements

### Requirement: Tags are shown in the browser as in the terminal
The web interface SHALL show the same tags, issues, uncertainty markers and rule
problems as the terminal viewer, in its lists and records, and SHALL accept the
same `tag:` filter and tag grouping.

#### Scenario: The same tags
- **WHEN** a host carries `zebra-zd420` as an assumption in the terminal viewer
- **THEN** the browser shows the same tag with the same marker and the same missing evidence

#### Scenario: Tag definitions as data
- **WHEN** a client requests the tag list from the versioned API
- **THEN** it receives every tag with its description, issues, sources, host count, uncertain count and the rule problems

### Requirement: Tagging and the rule builder work in the browser
The browser SHALL offer manual tagging, tag definitions, copying to the global
file and the rule builder, with the same keys as the terminal. These requests
SHALL be accepted only from the interface's own origin.

#### Scenario: Tagging from the browser
- **WHEN** the user marks two services in the browser and tags them `high-value`
- **THEN** both services carry the tag, and the tag is saved in the project's tag file

#### Scenario: Another site
- **WHEN** a request to add a tag arrives with an `Origin` of another site
- **THEN** it is refused and no file is changed

#### Scenario: The builder in the browser
- **WHEN** the user opens the rule builder in the browser with five marked hosts
- **THEN** it proposes the same facts and exclusions, with the same counts, as the terminal viewer
