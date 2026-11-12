# Spec Delta

## ADDED Requirements

### Requirement: The browser rule builder is the same workbench
The browser rule builder SHALL offer the terminal's workbench:
- the fact states, the editor with its modes and port scopes;
- the selection and match lists, and the same-port toggle;
- the save dialog, and every way to open it.

It SHALL take the same keys, and the same draft SHALL give the same counts and
save the same rule.

#### Scenario: The same rule from both
- **WHEN** the user widens "product equals `Zebra httpd` on 80/tcp" to contains `zebra`, ports `80,8080`, and saves it in the browser, and makes the same edit in the terminal
- **THEN** both show the same counts and save the same condition

#### Scenario: An invalid edit in the browser
- **WHEN** the browser sends a draft with an invalid regex
- **THEN** the request is refused with a 422 that names the problem, and nothing is saved

#### Scenario: Saving a tag from another site
- **WHEN** a request to save the tag editor arrives with an `Origin` of another site
- **THEN** it is refused and no file is changed

### Requirement: The browser tag editor is the terminal's
The browser SHALL offer the same tag editor - name, description, issues with
references, rules opened in the builder or deleted - saved as one change, and
SHALL ask before a change rewrites a person's rule file.

#### Scenario: A person's file from the browser
- **WHEN** the browser saves a tag whose changed rule is in `seek-rules.yaml`
- **THEN** the request is refused with a 409 naming the file until it confirms, and then the file is written

### Requirement: The viewer loads whole
Every script of the browser interface SHALL load. A script that does not load
SHALL fail the tests, because it stops every key and list of the viewer.

#### Scenario: A name declared twice
- **WHEN** a script declares one name twice
- **THEN** the test that loads every script fails, naming the script
