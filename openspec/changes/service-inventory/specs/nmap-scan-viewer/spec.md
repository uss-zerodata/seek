## MODIFIED Requirements

### Requirement: The overviews are presented as tabs
The available overviews SHALL be shown as a row of tabs, so that what can be
looked at is visible rather than something the user has to know a key for. The
active overview SHALL be marked, and a tab SHALL be selectable both by pointer
and by keyboard. Selecting a tab SHALL replace the current overview: a
drill-down belongs to the overview it was opened from, not to a different one.
Detail views SHALL NOT appear as tabs. Each overview SHALL keep its own filter,
sort and selected row, so returning to a tab - by selecting it, or by going back
to the first one - shows it as it was left.

The marked tab SHALL follow the list on screen: when a drill-down lands on the
subject of another overview, that overview's tab SHALL be marked, without the
drill-down becoming a tab and without the path back being discarded.

Each list SHALL be titled with what it is showing, together with the path taken
to reach it; where the active tab already names the list, that title need not be
repeated. Each column SHALL carry a heading naming it, and the heading of the
column currently sorted SHALL show the direction.

#### Scenario: The overviews are visible as tabs
- **WHEN** the viewer is open
- **THEN** the host, service, statistics, grouping and inventory overviews are all shown as tabs, with the active one marked

#### Scenario: Selecting a tab changes the overview
- **WHEN** the user selects the services tab
- **THEN** the service overview is shown and the tab is marked active

#### Scenario: Returning to a tab
- **WHEN** the user filters the host list, moves to another row, switches to the statistics and back
- **THEN** the host list shows the same filter, sort and selected row, and the statistics had their own filter

#### Scenario: A tab replaces a drill-down
- **WHEN** the user has drilled into a host and then selects another tab
- **THEN** that overview is shown rather than the drill-down being kept beneath it

#### Scenario: The marked tab follows the list
- **WHEN** a drill-down shows the hosts of one grouping bucket
- **THEN** that grouping's tab is marked, and the drill-down is still one level above the overview it was opened from

#### Scenario: The path to a detail is shown
- **WHEN** the user opens a host from the host list
- **THEN** the title shows both the list it came from and the host now being shown

#### Scenario: Columns are headed and the sort is marked
- **WHEN** a list is sorted by one of its columns
- **THEN** every column shows its name and the sorted one shows the direction

#### Scenario: The inventory is a tab
- **WHEN** the user selects the Inventory tab and then drills into a product
- **THEN** the services running it are listed, and going back returns to the Inventory tab as it was left
