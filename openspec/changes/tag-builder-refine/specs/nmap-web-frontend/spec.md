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

#### Scenario: Replacing a rule from another site
- **WHEN** a request to replace a rule arrives with an `Origin` of another site
- **THEN** it is refused and no file is changed
