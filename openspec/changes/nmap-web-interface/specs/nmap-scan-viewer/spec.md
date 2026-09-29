## ADDED Requirements

### Requirement: The web interface is opened from the viewer
The viewer SHALL open the web interface with a bare key and from the command
palette by name. The first use SHALL start the interface; later uses SHALL reuse
the running one. Each use SHALL open the browser at the page for the selected
row: a host row at the host's page, a service row at that service across hosts,
a row whose record identifies exactly one capture at that capture's page, and
anything else at the gallery. Opening the web interface SHALL NOT change the
list, its selection or its filter.

While the interface is running, the status bar SHALL say so and give its
address. Quitting the viewer SHALL stop it. The existing way of starting
gowitness's own report server SHALL remain available alongside it.

#### Scenario: Opening at the selected host
- **WHEN** the cursor is on host `192.0.2.1` and the user opens the web interface
- **THEN** the interface is started and the browser is opened at that host's page

#### Scenario: A second use reuses the server
- **WHEN** the interface is already running and the user opens it again on another row
- **THEN** no second server is started and the browser is opened at that row's page

#### Scenario: Nothing specific selected
- **WHEN** the selected row is a statistic
- **THEN** the browser is opened at the gallery

#### Scenario: The status bar says it is running
- **WHEN** the interface is running
- **THEN** the status bar shows that it is running and its address

#### Scenario: Reachable by name
- **WHEN** the user searches the command palette for "web"
- **THEN** the action that opens the web interface is listed

#### Scenario: Quitting stops it
- **WHEN** the user quits the viewer while the interface is running
- **THEN** the interface stops and its port is free again

#### Scenario: Both servers
- **WHEN** the user has opened the web interface and then starts gowitness's report server
- **THEN** both are running, each on its own port
