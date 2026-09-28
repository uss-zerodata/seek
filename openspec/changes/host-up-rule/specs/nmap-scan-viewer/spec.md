## RENAMED Requirements

- FROM: `### Requirement: Host reachability is reported by evidence, not by asserted state`
- TO: `### Requirement: A host is up by an open port or by real host discovery`

## MODIFIED Requirements

### Requirement: A host is up by an open port or by real host discovery
When a scan was run with host discovery disabled (`-Pn`), nmap marks every target
`up` regardless of whether it responded, with the status reason `user-set`. The
system SHALL NOT present such an asserted state as an observed one, and SHALL
detect it per host from that reason.

The system SHALL decide whether a host is up by one rule, and every part of the
viewer that says whether a host is up — the host list's state, the up-only
filter, the statistics, the `-Pn` warning and the export — SHALL use that rule:

- a host with at least one open port SHALL be up, however it was scanned;
- a host that a scan with host discovery recorded `up` SHALL be up, even with no
  open port;
- a host whose only claim to being up is a state asserted by `-Pn` SHALL NOT be
  up. Closed ports, filtered ports, an OS match or script results SHALL NOT make
  it up.

The host list SHALL say which of these applies: up by host discovery, up only
through an open port, asserted but unconfirmed, or down. It SHALL keep nmap's
recorded state and reason available, and SHALL make it visible when a scan
asserted more hosts up than the rule accepts, rather than silently reporting the
asserted number. The interface SHALL call this state "up".

A second, tighter host-list filter SHALL keep only the hosts with at least one
open port, on a key of its own. The two filters SHALL be independent toggles
that combine; since every host with an open port is up, both together SHALL
list the same hosts as the tighter one alone, and turning either off SHALL leave
the other as it was. From any other overview, either key SHALL go to the host
list and apply there. The list's title SHALL name the filters that are on.

Both keys SHALL ask the same question of a single host's port list, the one
list that shows closed and filtered ports as well as open ones: there either
SHALL restrict the list to open ports, in place, without leaving the host. The
choice SHALL carry to the next host opened, and SHALL be independent of the
host-list filters. A host with no open port SHALL say so and name the key that
lists every port.

#### Scenario: A `-Pn` scan does not report every target as up
- **WHEN** a scan run with `-Pn` marks 255 targets `up` with reason `user-set`, and only 9 of them have an open port
- **THEN** the viewer reports 9 hosts as up, not 255

#### Scenario: Under `-Pn`, only an open port counts
- **WHEN** a `-Pn` scan records a host with only closed and filtered ports, an OS guess and a script result
- **THEN** the host is not up, and the host list labels it as unconfirmed

#### Scenario: Host discovery is enough without `-Pn`
- **WHEN** a scan without `-Pn` records a host `up` with reason `echo-reply` and finds no open port on it
- **THEN** the host is up

#### Scenario: An open port is always enough
- **WHEN** a host has an open port and its recorded state is `down` or asserted
- **THEN** the host is up, and the host list shows that the open port is what makes it up

#### Scenario: The discrepancy is surfaced
- **WHEN** a scan asserted host state for more hosts than are up by the rule
- **THEN** the interface says so, giving both the asserted count and the count of hosts that are up

#### Scenario: The raw state remains available
- **WHEN** a host is marked `up` with reason `user-set` but has no open port
- **THEN** the viewer can still show that nmap recorded it as `up`, and why

#### Scenario: Filtering to up hosts uses the rule
- **WHEN** the user filters the host view to up hosts in a scan set that mixes `-Pn` and discovery scans
- **THEN** exactly the hosts with an open port or a recorded discovery `up` are listed

#### Scenario: Filtering to hosts with an open port
- **WHEN** the user presses `r` on a host list holding a `-Pn` host with an open port, a host that answered discovery with no open port, and a `-Pn` host with neither
- **THEN** only the first is listed, and the title says the list is limited to open ports

#### Scenario: The two filters combine
- **WHEN** both `u` and `r` are on and the user presses `r` again
- **THEN** the list shows every up host, and `u` is still on

#### Scenario: The open-port filter from another tab
- **WHEN** the user presses `r` on the statistics tab
- **THEN** the host list is shown, limited to hosts with an open port

#### Scenario: A host's ports filtered to the open ones
- **WHEN** a host's port list shows two open ports and one closed, and the user presses `u` or `r`
- **THEN** only the two open ports are listed, the host stays open, and the host list is not filtered

#### Scenario: A host with no open port
- **WHEN** the port list is restricted to open ports and the host has none
- **THEN** the list says that no port is open and that `u` lists every port

### Requirement: Parse and consolidate multiple scan files
Consolidating several scans is the normal case, not an edge case: a single
engagement typically produces separate discovery, port and service scans that are
only useful read together. The system SHALL accept any number of nmap XML files
in one invocation and SHALL present them as one consolidated model. It SHALL
also accept a directory, collecting the nmap XML files directly within it, so
that naming five or more files individually is never required.

A host that appears in more than one file SHALL be reconciled into a single host
rather than duplicated, keyed on its address. Facts that differ between files
SHALL be combined rather than overwritten: the union of its services, and for
single-valued facts such as OS or hostname, a value from a file that has one in
preference to one that does not.

Where two scans identify the same service differently, a scan that actually
probed the port SHALL take precedence over one that only guessed the service
from the port number, regardless of the order the files were given in. An
observed host state SHALL likewise take precedence over an asserted one, and
where two observed states disagree, `up` SHALL take precedence over `down`,
regardless of file order.

The system SHALL record which source file each host and each service was seen in,
and SHALL make that provenance visible, so that when scans disagree or a fact
appears in only one of them the user can tell which scan it came from.

#### Scenario: A directory is expanded to the scans inside it
- **WHEN** the user points the viewer at a directory containing five nmap XML files
- **THEN** all five are parsed and consolidated into one model

#### Scenario: Provenance is retained
- **WHEN** a host appears in three of five consolidated scans
- **THEN** the viewer can show which three it was seen in

#### Scenario: A service seen in only one scan is attributable
- **WHEN** one scan finds a port that the others did not
- **THEN** that service is attributed to the scan that found it

#### Scenario: Hosts from several files are merged
- **WHEN** two scan files each contain `10.0.0.5`, one with port 22 and one with port 80
- **THEN** the model holds one host `10.0.0.5` with both services

#### Scenario: A later file fills in a missing fact
- **WHEN** one file records no OS for a host and another records one
- **THEN** the merged host carries the recorded OS

#### Scenario: Services are not duplicated across files
- **WHEN** the same host and port appears in two files
- **THEN** it appears once in the merged model

#### Scenario: A probed identification beats a port-table guess
- **WHEN** one scan without version detection reports port 3128 as `squid-http` from the port table, and another scan with version detection reports it as `http` running a specific product
- **THEN** the consolidated service is the probed one, in either file order

#### Scenario: An observed host state beats an asserted one
- **WHEN** one scan asserts a host `up` with reason `user-set` and another records it `up` for an observed reason
- **THEN** the consolidated host carries the observed state and reason

#### Scenario: Observed up beats observed down
- **WHEN** one discovery scan records a host `down` and another discovery scan records it `up`
- **THEN** the consolidated host is `up` with that scan's reason, in either file order

#### Scenario: An asserted up does not beat an observed down
- **WHEN** a discovery scan records a host `down` and a `-Pn` scan asserts it `up` without finding an open port
- **THEN** the consolidated host keeps the recorded `down`

### Requirement: Aggregate statistics
The system SHALL provide a statistics view over the current (filtered) model
giving at least: the number of targets, how many were asserted up, how many are
up by the rule that decides whether a host is up, and how many have open ports;
per service name, how many times it occurs and on which ports; and per open
port, how many hosts expose it and which services were seen on it. It SHALL also
report the total number of distinct services and the total number of distinct
open ports.

The view SHALL be divided into labelled sections — at least host coverage, the
per-service breakdown and the per-port breakdown — each introduced by a heading
row that is visually distinct from the figures under it. Sections SHALL appear
in a fixed order, and no ordering the user chooses SHALL interleave the lines of
one section with another's or separate a heading from its section. A section
whose lines are all excluded by the filter SHALL disappear, heading included.

Every line SHALL open the records it counts, so that a figure is a way into the
data rather than a summary of it. No figure SHALL be reported only as a
truncated list inside another line's detail.

#### Scenario: Host counts distinguish asserted from up
- **WHEN** the statistics view is shown for a `-Pn` scan
- **THEN** targets, asserted-up, up and hosts-with-open-ports are each reported separately

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

### Requirement: Derived lists can be exported
The output of this viewer is frequently the input to another command, so the
system SHALL let the user export derived lists: at least the host addresses, the
addresses of the hosts that are up by the rule that decides whether a host is
up, the distinct open ports as a comma-separated list, `host:port` pairs, and
HTTP/HTTPS URLs constructed from the detected services including non-standard
ports. Export SHALL offer the same destinations as the search session — standard
output, the clipboard, or a file — and, when scanning is available, scanning the
selected records as a further destination, which SHALL carry their addresses
into the scan flow as the scope.

An export SHALL act on the marked records when any exist, and on the current
(filtered) view when none do. Which of the two is being exported SHALL be stated
before the user commits to it, so that the source is never inferred.

The unit of an export SHALL be a record — a host, together with one of its
services where the row stood for a service — so that a service's own facts can
be exported rather than collapsed to the host's address. A derived list that
names hosts SHALL name each host once, however many of its services are
selected.

#### Scenario: Export a host list
- **WHEN** the user exports host addresses from a filtered host view
- **THEN** the addresses of the filtered hosts are produced, one per line

#### Scenario: Export the up hosts
- **WHEN** the user exports up hosts from a scan set holding a `-Pn` host with no open port, a `-Pn` host with an open port, and a host that answered discovery with no open port
- **THEN** the last two addresses are produced and the first is not

#### Scenario: The export agrees with the filter
- **WHEN** the user filters the host view to up hosts and exports all hosts, and separately exports up hosts from the unfiltered view
- **THEN** both exports produce the same addresses

#### Scenario: Export a port list
- **WHEN** the user exports the port list
- **THEN** the distinct open ports of the current view are produced as a comma-separated list

#### Scenario: Export URLs
- **WHEN** the user exports URLs and a host offers HTTP on a non-standard port
- **THEN** a URL including that port is produced, with the scheme reflecting whether the service is TLS-wrapped

#### Scenario: URLs cover the names a host answers to
- **WHEN** a host has a resolved name and its TLS service's certificate claims another
- **THEN** the URL export produces the address and both names, each with that service's scheme and port

#### Scenario: A name nothing can resolve is not exported
- **WHEN** a certificate claims a wildcard name or an address
- **THEN** it does not appear in the URL export

#### Scenario: Exports respect the filter
- **WHEN** a filter is active, nothing is marked, and the user exports any derived list
- **THEN** only the filtered rows contribute to it

#### Scenario: Marks win over the view
- **WHEN** records are marked and the user exports
- **THEN** the marked records are exported, whatever the current view is filtered to

#### Scenario: The source is stated
- **WHEN** the user starts an export
- **THEN** it says whether it will export the marked records or the rows on screen, and how many

#### Scenario: Scanning the selection
- **WHEN** the user chooses to scan the selected records and nmap is available
- **THEN** their addresses become the scope of a new scan, reviewed and confirmed like any other

#### Scenario: Scanning is offered only when it can be done
- **WHEN** nmap is unavailable
- **THEN** the export dialog does not offer scanning as a destination

### Requirement: An empty list explains itself
A list with no rows SHALL say why it is empty and how to leave that state. It
SHALL keep the column headers, which say what would be there, and place the
message where the rows would have been.

The wording SHALL follow the cause: a filter that matched nothing SHALL name the
filter text and say that it can be cleared, and SHALL say how many rows are
behind it; a list emptied by an option SHALL name the option that widens it; a
scan with no hosts SHALL say that rather than appearing to have failed.

A list that is empty only because the work behind it has not finished SHALL be
distinguished from one that has settled with nothing in it, so that the user is
never given a premature negative: while scans are still being read, or an
overview is still being projected, the message SHALL say that the work is still
running and SHALL say how far it has got.

While a list is empty the record pane SHALL be hidden, since there is no record
to report, and the message SHALL sit inside the same region the rows occupy.

#### Scenario: A filter matches nothing
- **WHEN** the user filters a list of 250 hosts by a term that matches none of them
- **THEN** the list says that nothing matches that term, that `Esc` clears the filter, and how many rows are behind it

#### Scenario: The headers stay
- **WHEN** a list is empty
- **THEN** its column headers are still shown and the message appears directly beneath them

#### Scenario: An option emptied the list
- **WHEN** the up-only host list has no host that is up
- **THEN** the message says that no host is up and names the key that lists every host

#### Scenario: Two options emptied the list
- **WHEN** both host-list filters are on and no host has an open port
- **THEN** the message says that no host has an open port and names both keys

#### Scenario: Empty because the work is not finished
- **WHEN** the host list has no rows because the scans are still being read
- **THEN** the message says the reading is still going and how far it has got, and is distinct from the settled no-hosts message

#### Scenario: The empty state ends
- **WHEN** the filter is cleared and rows return
- **THEN** the message is gone and the record pane is shown again

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
- **WHEN** the user opens the up figure
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

### Requirement: The selected row's full record is shown
The table can only show what fits in its columns, so the system SHALL display the
complete record for the row the cursor is on, and SHALL update it as the cursor
moves — without the user having to navigate away to see it. That record SHALL
include everything the scan carried for that entry which the columns omit: for a
host its operating system, the state *and the reason* it was recorded with, which
scans it was seen in and its services; for a service its product, version, extra
information, how it was detected, and which scans saw it; and in both cases the
full text of any script results and the full detail of any vulnerability records
— identifier, title, state, severity where given, cross-reference identifiers,
disclosure date and reference URLs.

The scans that recorded the subject SHALL be listed as entries in their own
right rather than named in a run of text, one per line, each carrying what that
scan established about the subject — so that the record says not only which
scans saw it but what each of them contributed, and so that each is separately
openable as raw output.

Where a host's state was asserted rather than observed, the detail SHALL say so.
The pane SHALL be dismissible, and SHALL be dropped automatically when the
terminal is too short to show it and a usable list at once.

#### Scenario: Detail follows the cursor
- **WHEN** the user moves the cursor from one row to another
- **THEN** the displayed record changes to that of the newly selected row

#### Scenario: Vulnerability detail is reachable without navigating away
- **WHEN** the cursor is on a service carrying a vulnerability record
- **THEN** its identifier, title, state, cross-reference identifiers, disclosure date and reference URLs are shown

#### Scenario: Script output is reachable without navigating away
- **WHEN** the cursor is on an entry carrying script results
- **THEN** those scripts are listed with their output

#### Scenario: The scans that saw the subject are listed one per line
- **WHEN** the cursor is on a host seen by several scans
- **THEN** each scan is a line of its own saying what it established, rather than a comma-separated list of file names

#### Scenario: An asserted state is labelled in the detail
- **WHEN** the cursor is on a host whose `up` state came from `-Pn` and which has no open port
- **THEN** the detail says the state was asserted and is unconfirmed, rather than observed

#### Scenario: What makes a host up is labelled in the detail
- **WHEN** the cursor is on a host that is up only because of an open port
- **THEN** the detail says the open port is what makes it up, and still shows the state nmap recorded

#### Scenario: The pane can be dismissed
- **WHEN** the user presses the detail-pane key
- **THEN** the pane is hidden and the list occupies the freed space

#### Scenario: The pane is dropped on a short terminal
- **WHEN** the terminal is too short to show both the list and the detail
- **THEN** the detail is hidden and the list stays usable

### Requirement: An export names its own fields and format
An exported list is read by another tool, so its shape matters as much as its
contents. Alongside the named derived lists, the system SHALL let the user
choose which fields to write, from a catalogue covering both host facts —
address, hostname, operating system, recorded state, whether the host is up,
the scans a record was seen in — and service facts — port, protocol, service
name, product, version, and the URL where one applies. Field order in the output
SHALL be fixed by the catalogue, so that two exports of the same fields are
comparable.

The system SHALL write JSON, CSV and plain text. CSV SHALL carry a header row
naming the fields and SHALL quote values that need it; JSON SHALL be a list with
one object per record, keyed by field name; text SHALL write one record per
line. A record whose output row is identical to one already written SHALL be
written once.

#### Scenario: Choosing fields
- **WHEN** the user exports with the fields address, port and service
- **THEN** each record is written with exactly those three values, in the catalogue's order

#### Scenario: A service-level export
- **WHEN** the user exports marked services rather than hosts
- **THEN** the port and service of each marked service appear, rather than only the host's address

#### Scenario: CSV carries a header
- **WHEN** the user exports as CSV
- **THEN** the first line names the fields, and a value containing a comma is quoted

#### Scenario: JSON is one object per record
- **WHEN** the user exports as JSON
- **THEN** the output parses as a list of objects whose keys are the chosen fields

#### Scenario: Repeated rows collapse
- **WHEN** the chosen fields are the address alone and several marked services belong to one host
- **THEN** that address is written once

### Requirement: Sorting
Each view SHALL allow sorting by any of its columns, in ascending and descending
order, and SHALL indicate which column is sorted and in which direction, both on
the column itself and in the status line. Sorting SHALL apply to the filtered set.

Choosing a column SHALL sort by it ascending; choosing the column that is
already sorted SHALL reverse the order, and choosing it again SHALL reverse it
back. Which column counts as already sorted SHALL be the one the view indicates,
including the order a view opens in. Values SHALL be ordered by their meaning rather than their text —
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
- **WHEN** the user sorts by a column and then chooses the same column again
- **THEN** the order reverses, and choosing it a third time restores ascending order

#### Scenario: Another column starts ascending
- **WHEN** the list is sorted descending by one column and the user chooses another
- **THEN** the list is sorted by the new column in ascending order

#### Scenario: The opening order counts as chosen
- **WHEN** a list opens sorted by its first column and the user chooses that column
- **THEN** the order reverses

#### Scenario: Addresses sort numerically
- **WHEN** a host list containing `10.0.0.2`, `10.0.0.11` and `10.0.0.100` is sorted by address
- **THEN** they are ordered `10.0.0.2`, `10.0.0.11`, `10.0.0.100`

#### Scenario: Ports sort numerically
- **WHEN** a list containing ports `80/tcp`, `443/tcp` and `8080/tcp` is sorted by its port column
- **THEN** they are ordered `80/tcp`, `443/tcp`, `8080/tcp`

#### Scenario: The protocol only breaks ties
- **WHEN** a list holding `8080/tcp`, `80/tcp`, `22/tcp`, `8080/udp`, `443/tcp` and `53/udp` is sorted by its port column
- **THEN** they are ordered `22/tcp`, `53/udp`, `80/tcp`, `443/tcp`, `8080/tcp`, `8080/udp`

#### Scenario: A column listing several ports sorts numerically
- **WHEN** a grouping is sorted by its Ports column
- **THEN** its rows are ordered by their ports compared as numbers, first port first, and the ports within each cell are in the same order

#### Scenario: A view opens in its own order
- **WHEN** the statistics view is opened
- **THEN** its service and port lines are ordered by how often they occur, not alphabetically

#### Scenario: Sorting a sectioned view
- **WHEN** the user sorts the statistics view by one of its columns
- **THEN** the lines are ordered within each section and the headings stay at the top of their own section

#### Scenario: Sorting by clicking a heading
- **WHEN** the user clicks the heading of a column
- **THEN** the list is sorted by that column, as if its number had been pressed,
  and clicking it again reverses the order

#### Scenario: Sorting respects the filter
- **WHEN** a filter is active and the user sorts
- **THEN** only the filtered rows are ordered, and the filter stays applied
