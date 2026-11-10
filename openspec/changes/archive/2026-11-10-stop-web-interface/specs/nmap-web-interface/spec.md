## ADDED Requirements

### Requirement: The terminal viewer can stop the web interface
While the web interface is running, `w` SHALL offer three choices: open the browser at the selected row, copy the interface's address, or stop the web interface. The command palette SHALL offer "Stop the web interface" whenever it is running. Stopping SHALL end the server and close its port, SHALL say that it stopped, and SHALL leave the viewer and any running scan untouched. `w` afterwards SHALL start it again.

#### Scenario: Stopping from the viewer
- **WHEN** the web interface is running and the user presses `w` and chooses to stop it
- **THEN** the port is closed, the viewer says the web interface stopped, and the status line no longer shows it

#### Scenario: Reopening
- **WHEN** the web interface is running and the user presses `w` and chooses to open the browser
- **THEN** the browser opens at the selected row, as before

#### Scenario: A scan keeps running
- **WHEN** a scan is running and the user stops the web interface
- **THEN** the scan carries on in the viewer

### Requirement: The browser can stop the interface it is on
The browser SHALL offer a Stop control that asks for confirmation first. In the terminal viewer, it SHALL stop only the web interface. For `seek nmap serve`, it SHALL end the server as an interrupt does, including cancelling runs in progress, and the confirmation SHALL say so. The request SHALL be subject to the same-origin rule that applies to every change.

#### Scenario: Stop from the browser, in the viewer
- **WHEN** the user confirms Stop in a browser opened from the viewer
- **THEN** the web interface stops and the terminal viewer keeps running

#### Scenario: Stop from the browser, headless
- **WHEN** the user confirms Stop in a browser opened on `seek nmap serve`
- **THEN** the process cancels any run in progress and exits, as it does on Ctrl+C

#### Scenario: Another site
- **WHEN** a page on another site sends the stop request
- **THEN** it is refused and nothing stops

### Requirement: Open pages learn that the interface stopped
When the interface stops, the pages still open on it SHALL be told before the connection ends, and SHALL show that the web interface was stopped, rather than that the connection was lost. Stopping SHALL NOT wait for open pages to close.

#### Scenario: A page left open
- **WHEN** the interface is stopped while a page is open on it
- **THEN** the page says the web interface was stopped, and the server is gone within two seconds
