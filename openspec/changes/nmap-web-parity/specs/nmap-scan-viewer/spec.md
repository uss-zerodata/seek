## ADDED Requirements

### Requirement: The viewer shares its session with the web interface
The terminal viewer SHALL keep its model, its runs and its marks in the session
it shares with the web interface. A scan or capture started from the browser
SHALL be listed in the viewer's Scans tab and supervised exactly like one started
in the terminal - including the quit guard, which SHALL ask before quitting while
a browser-started run is still going. A mark made in the browser SHALL be shown
on the viewer's rows and counted in its status bar, and the viewer's own tab,
filter, sort and cursor SHALL NOT be moved by anything done in the browser.

#### Scenario: A run started in the browser shows in the terminal
- **WHEN** the user starts a capture in the browser
- **THEN** the terminal viewer's status bar counts it as running and its Scans tab lists it

#### Scenario: Quitting while a browser-started scan runs
- **WHEN** the user quits the terminal viewer while a scan started in the browser is running
- **THEN** the viewer asks first, as it does for a scan it started itself

#### Scenario: A mark from the browser
- **WHEN** the user marks a host in the browser
- **THEN** the terminal viewer shows the host's row as marked and its mark count goes up by one

#### Scenario: The cursor stays put
- **WHEN** the user drills into a host in the browser
- **THEN** the terminal viewer's list, tab and selected row do not change
