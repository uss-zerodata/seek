## Purpose

Reads one or more nmap XML output files into a single merged model of hosts and
services, and presents them as sortable, filterable overviews with drill-down in
both directions, so an assessment's scans can be read as records rather than as
lines of XML.

## ADDED Requirements

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
observed host state SHALL likewise take precedence over an asserted one.

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

### Requirement: Malformed input is reported and skipped
A file that cannot be parsed SHALL NOT abort the run. The system SHALL report
which files failed and continue with those that succeeded. When no file can be
parsed the system SHALL say so and exit without opening an empty viewer.

#### Scenario: One bad file among several
- **WHEN** three files are given and one is truncated mid-document
- **THEN** the viewer opens with the other two and reports the file that failed

#### Scenario: A file that is not nmap output
- **WHEN** a well-formed XML file that is not an nmap run is given
- **THEN** it is reported as not an nmap scan and skipped

#### Scenario: Nothing parseable
- **WHEN** every given file fails to parse
- **THEN** the system reports the failures and exits without opening the viewer

### Requirement: Host overview
The system SHALL provide a view listing every host in the merged model with at
least its address, its hostname, its operating system, and the number of services
on it. A host with no hostname or no identified OS SHALL still be listed, with
those fields shown as absent rather than omitted from the list. Hosts that were
scanned but found down SHALL be distinguishable from hosts that are up.

#### Scenario: Hosts are listed with their summary fields
- **WHEN** the viewer opens on a scan of 256 hosts
- **THEN** each host is listed with its address, hostname, OS and service count

#### Scenario: Missing facts do not hide a host
- **WHEN** a host has neither a hostname nor an identified OS
- **THEN** it still appears in the list, with those fields marked absent

#### Scenario: Down hosts are distinguishable
- **WHEN** a scan contains both up and down hosts
- **THEN** the view distinguishes them

### Requirement: Service overview
The system SHALL provide a view listing services aggregated across all hosts,
with at least port, protocol, service name, product, version, extra information,
and a count of associated vulnerabilities. Identical services on different hosts
SHALL be grouped into one row carrying the number of hosts that run it.

#### Scenario: Services are listed with their detail fields
- **WHEN** the service view is shown
- **THEN** each row shows port, protocol, name, product, version, extra info and a vulnerability count

#### Scenario: The same service on many hosts is one row
- **WHEN** twenty hosts run `tcp/80 Apache httpd 2.4.52`
- **THEN** the service view shows one row for it, indicating twenty hosts

### Requirement: Drill down from a host to its services
Selecting a host SHALL show every service on that host together with the details
of each, and SHALL allow returning to the view it was opened from.

#### Scenario: Host detail lists its services
- **WHEN** the user selects host `10.0.0.5` in the host view
- **THEN** every service on that host is listed with its details

#### Scenario: Returning from a host detail
- **WHEN** the user goes back from a host detail
- **THEN** the previous view is restored, including its filter and sort

### Requirement: Drill down from a service to its hosts
Selecting a service SHALL show every host running it, with that host's specific
details for the service — its version, extra information and any vulnerabilities
recorded on that host — and SHALL allow returning to the view it was opened from.

#### Scenario: Service detail lists its hosts
- **WHEN** the user selects `tcp/80 apache` in the service view
- **THEN** every host running it is listed with that host's specifics for that service

### Requirement: Drilling continues from wherever the user is
Every row that stands for hosts or services SHALL be openable, and the
destinations SHALL chain, so that the user can keep going down instead of
unwinding to an overview to approach the data from another angle. A host opens
its services; a service on a host opens that service across the whole scan set;
a host in any of those lists opens its own record again. Rows of a grouping and
the per-service lines of the statistics view SHALL open the hosts behind them.
A service that is open on no host SHALL still open the hosts that report the
port.

#### Scenario: From a grouping to one host's record
- **WHEN** the user opens a `by product` row and then one of the hosts listed in it
- **THEN** that host's full record is shown, with the path back through both levels

#### Scenario: From one host's port to every host running it
- **WHEN** the user opens a host, then one of its services
- **THEN** every host running that same service is listed

#### Scenario: A statistics line opens its hosts
- **WHEN** the user opens the `http` line of the statistics view
- **THEN** the hosts counted on that line are listed

#### Scenario: A port that is open nowhere
- **WHEN** the user opens a service whose port is closed or filtered on every host
- **THEN** the hosts that report that port are listed rather than nothing happening

#### Scenario: Host specifics differ within one service group
- **WHEN** two hosts run the same service at different versions
- **THEN** each host's row in the service detail shows its own version

### Requirement: Fuzzy filtering
Each view SHALL provide a filter that narrows the listed rows as the user types,
using the same query grammar as the search session — space-separated terms
combined with AND, `'exact`, `^prefix`, `suffix$`, `!negate`, and smart-case —
matched against the row's fields. Clearing the filter SHALL restore the full
list. The characters a row matched on SHALL be highlighted where they appear in
the list, so the user can see why a row survived the filter.

A filter term denoting an address range SHALL be understood as one and tested
against the addresses the row belongs to, rather than as text. That covers both
an explicit prefix (`10.10.10.32/26`) and a complete address, which denotes the
single host (`10.10.10.5` is `10.10.10.5/32`). A term that is not a complete
address — one still being typed, or an invalid one — SHALL remain an ordinary
fuzzy term, so that partial input still matches every address containing it.
Range terms and fuzzy terms SHALL compose in one expression, and a range term
SHALL be negatable like any other. The range actually being applied SHALL be
visible, since a prefix is resolved to the network containing it.

#### Scenario: Typing narrows the list
- **WHEN** the user types `apache` in the service view's filter
- **THEN** only rows matching `apache` remain listed

#### Scenario: The query grammar is honoured
- **WHEN** the user filters with `'http !443`
- **THEN** rows are those containing the exact substring `http` and not matching `443`

#### Scenario: Clearing restores everything
- **WHEN** the user clears a non-empty filter
- **THEN** every row is listed again

#### Scenario: Matched characters are highlighted
- **WHEN** a filter is active and a row is listed because one of its fields matched
- **THEN** the matching characters are visually marked within that field

#### Scenario: Filtering by an address range
- **WHEN** the user filters with `10.10.10.32/26`
- **THEN** only rows whose addresses fall in `10.10.10.0`–`10.10.10.63` are listed

#### Scenario: A range and a fuzzy term together
- **WHEN** the user filters with `10.10.10.0/24 apache`
- **THEN** rows must both fall in that range and fuzzy-match `apache`

#### Scenario: A complete address selects that host alone
- **WHEN** the user filters with `10.10.10.5`
- **THEN** only the host `10.10.10.5` is listed, and `10.10.10.50` is not

#### Scenario: A partial address still matches many
- **WHEN** the user has typed `10.10.10.` and not yet completed the address
- **THEN** every host under `10.10.10.` is still listed

#### Scenario: The applied range is visible
- **WHEN** a range term is active
- **THEN** the interface shows the range being applied

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

#### Scenario: Sorting respects the filter
- **WHEN** a filter is active and the user sorts
- **THEN** only the filtered rows are ordered, and the filter stays applied

### Requirement: Script results are captured
The system SHALL capture every `<script>` result attached to a host or a service,
preserving its identifier, its free-text output, and — where the script emits
them — its structured `<table>` / `<elem>` entries as a keyed tree. Script
results SHALL be visible in the detail view of whatever they were attached to.

#### Scenario: Structured script output is preserved as keys and values
- **WHEN** a script result carries nested `<table key="…"><elem key="…">` entries
- **THEN** those keys and values are available, not only the free-text output

#### Scenario: Free-text-only script output is preserved
- **WHEN** a script result carries only an `output` attribute with no nested elements
- **THEN** its text is still captured and shown

#### Scenario: Host-level scripts are attached to the host
- **WHEN** a scan contains `<hostscript>` results
- **THEN** they appear in that host's detail view rather than against a service

### Requirement: Vulnerabilities are extracted from script results
The system SHALL recognise vulnerability-bearing script results and lift them
into typed vulnerability records carrying at least an identifier, a title, and
the state the script reported (for example `VULNERABLE`), together with any
cross-reference identifiers, reference URLs and disclosure date the script
supplied. A severity SHALL be carried only when the script actually provides one
— the NSE `vuln` library reports a *state*, not a severity, and a severity SHALL
NOT be inferred from it. Where one script reports the same finding against
several ports of a host, the records SHALL NOT be double-counted for that
service. Vulnerabilities SHALL be
counted in the service overview and listed in the relevant detail view. A scan
whose scripts carry no vulnerability information SHALL report zero
vulnerabilities rather than failing or showing an empty section as an error.

#### Scenario: A vulnerability-bearing script yields records
- **WHEN** a service carries an NSE `vuln` library result whose table is keyed by a CVE identifier and contains a title, a state, cross-reference ids and reference URLs
- **THEN** a vulnerability record is produced carrying that identifier, title, state, ids and references

#### Scenario: State is not reported as a severity
- **WHEN** a script reports only a state such as `VULNERABLE` and no severity score
- **THEN** the record carries the state and leaves the severity unset

#### Scenario: Scripts reporting nothing found yield no records
- **WHEN** a vulnerability script runs but reports that it found nothing, with no structured output
- **THEN** no vulnerability record is produced for it and it is not counted

#### Scenario: Counts appear in the service overview
- **WHEN** a service has vulnerability records
- **THEN** the service overview shows how many

#### Scenario: A scan without vulnerability scripts
- **WHEN** a scan contains only scripts such as `http-title` and `ssl-cert` that carry no vulnerability information
- **THEN** every vulnerability count is zero and the viewer operates normally

### Requirement: Entry point
The system SHALL provide a `nmap` subcommand taking one or more file paths, or a
directory, and opening the viewer on them. The viewer is a purpose-built
interface for scan output and SHALL be reached this way; the file-search session
SHALL NOT carry nmap-specific actions or hints.

#### Scenario: Opening files directly
- **WHEN** the user runs the `nmap` subcommand with two scan files
- **THEN** the viewer opens on the merged model of both

#### Scenario: The search session stays a file search
- **WHEN** the highlighted result in a search session is an nmap XML file
- **THEN** the search session offers no nmap-specific action for it

#### Scenario: No paths given
- **WHEN** the subcommand is run with no file paths
- **THEN** the system explains what it expects and exits without opening the viewer

### Requirement: Host reachability is reported by evidence, not by asserted state
When a scan was run with host discovery disabled (`-Pn`), nmap marks every target
`up` regardless of whether it responded, with the status reason `user-set`. The
system SHALL NOT present such an asserted state as an observed one. It SHALL
detect that a scan asserted host state, and SHALL classify each host by the
evidence actually present — whether it has any responding port, any service, any
OS match, or any script result — so that "reachable" reflects the scan's findings
rather than its assumptions.

The host overview SHALL default to the evidence-based classification, SHALL keep
the raw nmap state available, and SHALL make the discrepancy visible rather than
silently reporting the asserted number. Filtering by reachability SHALL operate
on the evidence-based classification.

#### Scenario: A `-Pn` scan does not report every target as reachable
- **WHEN** a scan run with `-Pn` marks 255 targets `up` with reason `user-set`, and only 9 of them have any port, service, OS or script data
- **THEN** the viewer reports 9 hosts as showing evidence of being reachable, not 255

#### Scenario: The discrepancy is surfaced
- **WHEN** a scan asserted host state for more hosts than show any evidence
- **THEN** the interface says so, giving both the asserted count and the evidence-based count

#### Scenario: The raw state remains available
- **WHEN** a host is marked `up` with reason `user-set` but shows no evidence
- **THEN** the viewer can still show that nmap recorded it as `up`, and why

#### Scenario: A scan with real host discovery is unaffected
- **WHEN** a scan was run without `-Pn` and hosts are `up` for reasons such as `echo-reply` or `syn-ack`
- **THEN** the evidence-based classification agrees with the recorded state

#### Scenario: Filtering by reachability uses evidence
- **WHEN** the user filters the host view to reachable hosts in a `-Pn` scan
- **THEN** only hosts with evidence are listed

### Requirement: Aggregate statistics
The system SHALL provide a statistics view over the current (filtered) model
giving at least: the number of targets, how many were asserted up, how many show
evidence of being reachable, and how many have open ports; and per service name,
how many times it occurs and on which ports. It SHALL also report the total
number of distinct services and the set of distinct open ports.

#### Scenario: Host counts distinguish asserted from evidenced
- **WHEN** the statistics view is shown for a `-Pn` scan
- **THEN** targets, asserted-up, evidenced-reachable and hosts-with-open-ports are each reported separately

#### Scenario: Service occurrence counts
- **WHEN** the statistics view is shown
- **THEN** each service name is listed with how many times it occurs and the ports it was seen on

#### Scenario: Statistics follow the filter
- **WHEN** a filter is active and the statistics view is shown
- **THEN** the figures describe the filtered subset

### Requirement: Grouping views
The system SHALL be able to group open services by service name, by product, and
by port, listing the hosts in each group with the port and any product and
version detail. Groups SHALL be ordered by size by default.

#### Scenario: Group by service
- **WHEN** the user groups by service
- **THEN** each service name lists every host and port offering it, with product and version where known

#### Scenario: Group by product
- **WHEN** the user groups by product
- **THEN** services with no detected product are omitted from the grouping rather than collected under an empty name

#### Scenario: Group by port
- **WHEN** the user groups by port
- **THEN** each port lists the hosts exposing it, ordered by port number

#### Scenario: A group opens the hosts behind it
- **WHEN** the user opens a group
- **THEN** its hosts are listed, and each of those opens that host's record

### Requirement: Derived lists can be exported
The output of this viewer is frequently the input to another command, so the
system SHALL let the user export derived lists from the current (filtered) view:
at least the host addresses, the distinct open ports as a comma-separated list,
`host:port` pairs, and HTTP/HTTPS URLs constructed from the detected services
including non-standard ports. Export SHALL offer the same destinations as the
search session — standard output, the clipboard, or a file.

#### Scenario: Export a host list
- **WHEN** the user exports host addresses from a filtered host view
- **THEN** the addresses of the filtered hosts are produced, one per line

#### Scenario: Export a port list
- **WHEN** the user exports the port list
- **THEN** the distinct open ports of the current view are produced as a comma-separated list

#### Scenario: Export URLs
- **WHEN** the user exports URLs and a host offers HTTP on a non-standard port
- **THEN** a URL including that port is produced, with the scheme reflecting whether the service is TLS-wrapped

#### Scenario: Exports respect the filter
- **WHEN** a filter is active and the user exports any derived list
- **THEN** only the filtered rows contribute to it

### Requirement: Stateless operation
The system SHALL hold everything it needs for a run in memory for the duration of
that run. It SHALL NOT require an import or indexing step before files can be
read, SHALL NOT create or depend on a database or any other persistent store, and
SHALL NOT write to the filesystem except when the user explicitly exports. Two
invocations over the same files SHALL produce the same result regardless of what
was run before them.

#### Scenario: Files are read directly, with no import step
- **WHEN** the user opens scan files that have never been seen before
- **THEN** they are read and presented immediately, with no prior import required

#### Scenario: Nothing is left behind
- **WHEN** a session ends
- **THEN** no database, cache or index file has been created

#### Scenario: Repeat runs are identical
- **WHEN** the same files are opened twice with no change on disk
- **THEN** both runs present the same hosts, services and counts

#### Scenario: Removing a file removes its data
- **WHEN** a file is omitted from a subsequent invocation
- **THEN** nothing it contributed persists into that run

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

#### Scenario: An asserted state is labelled in the detail
- **WHEN** the cursor is on a host whose `up` state came from `-Pn` and which shows no evidence
- **THEN** the detail says the state was asserted rather than observed

#### Scenario: The pane can be dismissed
- **WHEN** the user presses the detail-pane key
- **THEN** the pane is hidden and the list occupies the freed space

#### Scenario: The pane is dropped on a short terminal
- **WHEN** the terminal is too short to show both the list and the detail
- **THEN** the detail is hidden and the list stays usable

### Requirement: List navigation
The system SHALL let the user move through a list with the up and down arrow
keys, page through it, and jump to its first and last row, so that a scan of
several hundred hosts can be traversed without holding a key down. Navigation
SHALL keep the selected row and its detail in step. The left and right arrow keys
SHALL scroll the selected row's record, since a row-oriented list has no
horizontal cursor to move. While the filter is being edited the arrow keys SHALL
move the text cursor as usual.

#### Scenario: Paging through a long list
- **WHEN** a list of 256 hosts is shown and the user presses page-down
- **THEN** the selection advances by approximately one screen

#### Scenario: Jumping to the ends
- **WHEN** the user presses the jump-to-last key
- **THEN** the final row is selected, and the jump-to-first key returns to the first

#### Scenario: Selection is reset when the rows change
- **WHEN** a filter changes which rows are listed
- **THEN** the selection lands on the first matching row and the detail shows it

#### Scenario: Going back lands on the row that was opened
- **WHEN** the user opens the fourth host in the list and then goes back
- **THEN** the fourth host is selected again, under the sort that was in effect

#### Scenario: Clearing a filter keeps the selected row
- **WHEN** the user clears an active filter while a row is selected
- **THEN** the whole list is shown again with that same row still selected

#### Scenario: Left and right scroll the record
- **WHEN** the selected row's record is taller than the space for it and the user presses the right arrow
- **THEN** the record scrolls, and the selected row does not change

#### Scenario: Arrows edit the filter while it is focused
- **WHEN** the user is typing in the filter and presses the left arrow
- **THEN** the text cursor moves and the record does not scroll

### Requirement: The overviews are presented as tabs
The available overviews SHALL be shown as a row of tabs, so that what can be
looked at is visible rather than something the user has to know a key for. The
active overview SHALL be marked, and a tab SHALL be selectable both by pointer
and by keyboard. Selecting a tab SHALL replace the current overview: a
drill-down belongs to the overview it was opened from, not to a different one.
Detail views SHALL NOT appear as tabs.

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

#### Scenario: The path to a detail is shown
- **WHEN** the user opens a host from the host list
- **THEN** the title shows both the list it came from and the host now being shown

#### Scenario: Columns are headed and the sort is marked
- **WHEN** a list is sorted by one of its columns
- **THEN** every column shows its name and the sorted one shows the direction

### Requirement: Every action is reachable by name
Keys are quick but easy to forget, so every action the viewer offers — changing
overview, moving through a list, sorting by any column of the overview currently
shown, filtering, exporting, and quitting — SHALL also be reachable from a
searchable command list, each entry naming what it does. The list SHALL reflect
the overview in view, so that the columns offered for sorting are the ones
actually present.

#### Scenario: Actions can be found by name
- **WHEN** the user opens the command list and types part of an action's name
- **THEN** that action is offered and can be run from there

#### Scenario: Sort entries match the overview
- **WHEN** the command list is opened while the service overview is shown
- **THEN** the sort entries name the service overview's columns

#### Scenario: The list is browsable without typing
- **WHEN** the user opens the command list and types nothing
- **THEN** the available actions are listed

### Requirement: The list is the thing being operated on
The selected row SHALL be visibly marked in the list at all times, so the user
can see what the detail below refers to and what an action will apply to. The
list SHALL therefore hold keyboard focus by default, and the filter SHALL be
entered deliberately and left again, rather than holding focus permanently.

Because a terminal emulator claims many modified keys — flow control on `Ctrl+S`,
tab switching on `Alt`+digit, focus traversal on `Tab` — actions SHALL be
reachable without those combinations.

#### Scenario: The selected row is marked
- **WHEN** the user moves the selection with the arrow keys
- **THEN** the newly selected row is visibly distinguished from the others

#### Scenario: Filtering is entered and left
- **WHEN** the user opens the filter, types, and confirms
- **THEN** focus returns to the list with the filter applied

#### Scenario: Actions avoid keys the terminal claims
- **WHEN** the viewer's actions are inspected
- **THEN** none of them require `Tab`, `Alt`+digit, or a control combination the terminal intercepts

### Requirement: Detail is laid out as a report
The record shown for the selected row SHALL be laid out for reading: labelled
values for single facts, and bulleted lists wherever there can be several
entries — services, scripts and vulnerabilities. It SHALL fit the space
available, preferring to show the identifying and status information of each
entry over its full supporting detail when space is short.

#### Scenario: Collections are shown as lists
- **WHEN** the selected host runs several services
- **THEN** they are shown as a list, one entry per line, rather than as a single run of text

#### Scenario: Single facts are labelled
- **WHEN** the detail shows a host's operating system and state
- **THEN** each is presented with a label identifying it

### Requirement: The interface matches the rest of the application
The viewer SHALL follow the same visual conventions as a search session: regions
separated by thin rules rather than filled bands, since the terminal palette
collapses background shades; rendered text carrying its own colour; and the same
highlight style for characters matched by a filter.

#### Scenario: Regions are separated by rules
- **WHEN** the viewer is open
- **THEN** the list and the detail are fenced by rules, and no region is drawn on a filled background band

### Requirement: The list fits the terminal
No row SHALL extend beyond the width of the terminal. Where the columns cannot
all be shown at their natural width, values SHALL be shortened with an
indication that something was removed, in preference to overflowing — the full
value is available in the detail below. The layout SHALL follow a resize.

#### Scenario: A narrow terminal shortens rather than overflows
- **WHEN** the terminal is too narrow for the columns at their natural width
- **THEN** the values are shortened to fit and no row extends past the right edge

#### Scenario: Widening restores detail
- **WHEN** the terminal is made wider
- **THEN** the columns are laid out again to use the space

### Requirement: A long record can be scrolled
When the record for the selected row is taller than the space available, the user
SHALL be able to scroll it without leaving the list or losing the selection.
Moving to another row SHALL return the record to its top.

#### Scenario: Scrolling a long report
- **WHEN** the selected row's record does not fit and the user scrolls it down
- **THEN** the rest of the record is shown, and the selection is unchanged

#### Scenario: A new selection starts at the top
- **WHEN** the user scrolls a record and then selects a different row
- **THEN** the new record is shown from its beginning
