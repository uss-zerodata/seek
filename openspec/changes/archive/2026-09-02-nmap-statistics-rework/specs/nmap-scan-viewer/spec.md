## MODIFIED Requirements

### Requirement: Aggregate statistics
The system SHALL provide a statistics view over the current (filtered) model
giving at least: the number of targets, how many were asserted up, how many show
evidence of being reachable, and how many have open ports; per service name, how
many times it occurs and on which ports; and per open port, how many hosts
expose it and which services were seen on it. It SHALL also report the total
number of distinct services and the total number of distinct open ports.

The view SHALL be divided into labelled sections — at least host coverage, the
per-service breakdown and the per-port breakdown — each introduced by a heading
row that is visually distinct from the figures under it. Sections SHALL appear
in a fixed order, and no ordering the user chooses SHALL interleave the lines of
one section with another's or separate a heading from its section. A section
whose lines are all excluded by the filter SHALL disappear, heading included.

Every line SHALL open the records it counts, so that a figure is a way into the
data rather than a summary of it. No figure SHALL be reported only as a
truncated list inside another line's detail.

#### Scenario: Host counts distinguish asserted from evidenced
- **WHEN** the statistics view is shown for a `-Pn` scan
- **THEN** targets, asserted-up, evidenced-reachable and hosts-with-open-ports are each reported separately

#### Scenario: Service occurrence counts
- **WHEN** the statistics view is shown
- **THEN** each service name is listed with how many times it occurs and the ports it was seen on

#### Scenario: Port occurrence counts
- **WHEN** the statistics view is shown for a scan with twelve distinct open ports
- **THEN** each of the twelve is a line of its own giving how many hosts expose it and the services seen on it

#### Scenario: The sections are headed and ordered
- **WHEN** the statistics view is shown
- **THEN** the coverage figures, the service lines and the port lines appear under their own headings, in that order

#### Scenario: Filtering a section empty removes its heading
- **WHEN** a filter leaves no line under one of the headings
- **THEN** that heading is not shown, and the sections that still have lines are

#### Scenario: Statistics follow the filter
- **WHEN** a filter is active and the statistics view is shown
- **THEN** the figures describe the filtered subset

### Requirement: Sorting
Each view SHALL allow sorting by any of its columns, in ascending and descending
order, and SHALL indicate which column is sorted and in which direction, both on
the column itself and in the status line. Sorting SHALL apply to the filtered set.

Choosing a column and reversing the order SHALL be separate actions: choosing a
column SHALL always sort ascending, and one dedicated action SHALL reverse the
current order. Values SHALL be ordered by their meaning rather than their text —
in particular IP addresses SHALL sort numerically, so that `10.0.0.2` precedes
`10.0.0.11`, and port numbers SHALL sort numerically even where they are shown
as part of a label such as `80/tcp`.

A view SHALL be able to declare the order it opens in, so that a list arrives in
the order that is useful for what it shows rather than always ascending by its
first column. In a view divided into sections, sorting SHALL order the lines
within each section.

Clicking a column heading SHALL sort by that column, so the sort is reachable
without knowing a key.

#### Scenario: Sort by a column
- **WHEN** the user sorts the host view by service count
- **THEN** hosts are ordered by that count and the view indicates the sorted column and direction

#### Scenario: Reversing a sort
- **WHEN** the user invokes the reverse action
- **THEN** the order reverses, and choosing a column again does not

#### Scenario: Addresses sort numerically
- **WHEN** a host list containing `10.0.0.2`, `10.0.0.11` and `10.0.0.100` is sorted by address
- **THEN** they are ordered `10.0.0.2`, `10.0.0.11`, `10.0.0.100`

#### Scenario: Ports sort numerically
- **WHEN** a list containing ports `80/tcp`, `443/tcp` and `8080/tcp` is sorted by its port column
- **THEN** they are ordered `80/tcp`, `443/tcp`, `8080/tcp`

#### Scenario: A view opens in its own order
- **WHEN** the statistics view is opened
- **THEN** its service and port lines are ordered by how often they occur, not alphabetically

#### Scenario: Sorting a sectioned view
- **WHEN** the user sorts the statistics view by one of its columns
- **THEN** the lines are ordered within each section and the headings stay at the top of their own section

#### Scenario: Sorting by clicking a heading
- **WHEN** the user clicks the heading of a column
- **THEN** the list is sorted by that column, as if its number had been pressed

#### Scenario: Sorting respects the filter
- **WHEN** a filter is active and the user sorts
- **THEN** only the filtered rows are ordered, and the filter stays applied

### Requirement: The overviews are presented as tabs
The available overviews SHALL be shown as a row of tabs, so that what can be
looked at is visible rather than something the user has to know a key for. The
active overview SHALL be marked, and a tab SHALL be selectable both by pointer
and by keyboard. Selecting a tab SHALL replace the current overview: a
drill-down belongs to the overview it was opened from, not to a different one.
Detail views SHALL NOT appear as tabs.

The marked tab SHALL follow the list on screen: when a drill-down lands on the
subject of another overview, that overview's tab SHALL be marked, without the
drill-down becoming a tab and without the path back being discarded.

Each list SHALL be titled with what it is showing, together with the path taken
to reach it; where the active tab already names the list, that title need not be
repeated. Each column SHALL carry a heading naming it, and the heading of the
column currently sorted SHALL show the direction.

#### Scenario: The overviews are visible as tabs
- **WHEN** the viewer is open
- **THEN** the host, service, statistics and grouping overviews are all shown as tabs, with the active one marked

#### Scenario: Selecting a tab changes the overview
- **WHEN** the user selects the services tab
- **THEN** the service overview is shown and the tab is marked active

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

### Requirement: Drilling continues from wherever the user is
Every row that stands for hosts or services SHALL be openable, and the
destinations SHALL chain, so that the user can keep going down instead of
unwinding to an overview to approach the data from another angle. A host opens
its services; a service on a host opens that service across the whole scan set;
a host in any of those lists opens its own record again. Rows of a grouping and
the lines of the statistics view SHALL open the records behind them. A service
that is open on no host SHALL still open the hosts that report the port.

Where a drill-down lands on the subject of one of the overviews — a service
across every host, the hosts in a grouping, a list of hosts — the tab row SHALL
mark that overview, so it keeps saying where the user is. A view that is one
record rather than an overview's subject SHALL keep the tab it was opened from.
Marking a tab this way SHALL NOT replace the stack: the path back is unchanged
and going back SHALL restore the tab of the level returned to. Only a tab the
user selects replaces the current overview.

Each kind of statistics line SHALL open what it counts: a coverage figure opens
that set of hosts, the distinct-services and distinct-ports totals open the
matching grouping, a service line opens the hosts running that service, and a
port line opens the hosts exposing that port. A heading row SHALL open nothing.
These SHALL be drill-downs like any other, so that going back returns to the
statistics view with its selection intact.

#### Scenario: From a grouping to one host's record
- **WHEN** the user opens a `by product` row and then one of the hosts listed in it
- **THEN** that host's full record is shown, with the path back through both levels

#### Scenario: From one host's port to every host running it
- **WHEN** the user opens a host, then one of its services
- **THEN** every host running that same service is listed

#### Scenario: A coverage figure opens its hosts
- **WHEN** the user opens the evidenced-reachable figure
- **THEN** exactly those hosts are listed, as a list of hosts with their usual columns

#### Scenario: A total opens the breakdown behind it
- **WHEN** the user opens the distinct-open-ports total
- **THEN** the grouping by port is shown

#### Scenario: A statistics line opens its hosts
- **WHEN** the user opens the `http` line of the statistics view
- **THEN** the hosts counted on that line are listed

#### Scenario: A port line opens its hosts
- **WHEN** the user opens the `443/tcp` line of the statistics view
- **THEN** the hosts exposing that port are listed

#### Scenario: Going back from a statistic
- **WHEN** the user goes back from anything opened out of the statistics view
- **THEN** the statistics view is shown again with the same line selected

#### Scenario: The tab follows the drill-down
- **WHEN** the user opens a service from one host's record, and that service is then shown across every host
- **THEN** the services tab is marked, while the path back through the host record is unchanged

#### Scenario: A record keeps the tab it was opened from
- **WHEN** the user opens a grouping, then one of its hosts
- **THEN** that grouping's tab stays marked, because a single host's record is no overview's subject

#### Scenario: Going back restores the tab
- **WHEN** the user goes back from a drill-down that marked another tab
- **THEN** the tab of the level returned to is marked again

#### Scenario: A port that is open nowhere
- **WHEN** the user opens a service whose port is closed or filtered on every host
- **THEN** the hosts that report that port are listed rather than nothing happening
