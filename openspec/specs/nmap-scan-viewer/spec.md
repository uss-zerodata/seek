# nmap-scan-viewer Specification

## Purpose
Reads one or more nmap XML output files into a single merged model of hosts and
services, and presents them as sortable, filterable overviews with drill-down in
both directions, so an assessment's scans can be read as records rather than as
lines of XML.
## Requirements
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

When the given paths hold no readable scan and scanning is available, the
subcommand SHALL open the viewer on an empty model with the scope editor rather
than exiting: a directory with nothing in it yet is the case for starting a
scan, not an error. When scanning is unavailable it SHALL explain what it
expects and exit as before. The output directory for any scan started in that
session SHALL be the directory given, or the working directory when individual
files were given.

#### Scenario: Opening files directly
- **WHEN** the user runs the `nmap` subcommand with two scan files
- **THEN** the viewer opens on the merged model of both

#### Scenario: The search session stays a file search
- **WHEN** the highlighted result in a search session is an nmap XML file
- **THEN** the search session offers no nmap-specific action for it

#### Scenario: No paths given
- **WHEN** the subcommand is run with no file paths
- **THEN** the system explains what it expects and exits without opening the viewer

#### Scenario: A directory with no scans, and nmap available
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is available
- **THEN** the viewer opens with the scope editor, and that directory is where a scan will write

#### Scenario: A directory with no scans, and no nmap
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is not available
- **THEN** the system reports that there is nothing to read and exits
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
system SHALL let the user export derived lists: at least the host addresses, the
distinct open ports as a comma-separated list, `host:port` pairs, and HTTP/HTTPS
URLs constructed from the detected services including non-standard ports. Export
SHALL offer the same destinations as the search session — standard output, the
clipboard, or a file — and, when scanning is available, scanning the selected
records as a further destination, which SHALL carry their addresses into the
scan flow as the scope.

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

Opening the detail SHALL show the selected row's record full-screen for reading
and searching; a separate action SHALL show or hide the inline detail pane, so
the pane can be collapsed to give the list more room without losing the way into
the full-screen reader.

#### Scenario: Paging through a long list
- **WHEN** a list of 256 hosts is shown and the user presses page-down
- **THEN** the selection advances by approximately one screen

#### Scenario: Jumping to the ends
- **WHEN** the user presses the jump-to-last key
- **THEN** the final row is selected, and the jump-to-first key returns to the first

#### Scenario: Selection is reset when the rows change
- **WHEN** a filter changes which rows are listed
- **THEN** the selection lands on the first matching row and the detail shows it

#### Scenario: Left and right scroll the record
- **WHEN** the selected row's record is taller than the space for it and the user presses the right arrow
- **THEN** the record scrolls, and the selected row does not change

#### Scenario: Arrows edit the filter while it is focused
- **WHEN** the user is typing in the filter and presses the left arrow
- **THEN** the text cursor moves and the record does not scroll

#### Scenario: Opening and collapsing the detail
- **WHEN** the user invokes the open-detail action
- **THEN** the selected row's record opens full-screen, and a separate action collapses or restores the inline pane
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
reachable without those combinations. This applies to marking too: the search
session's marking keys are `Tab` and `Shift+Tab`, which the viewer SHALL NOT
reuse.

The selection cursor and a mark SHALL remain distinguishable from each other.

#### Scenario: The selected row is marked
- **WHEN** the user moves the selection with the arrow keys
- **THEN** the newly selected row is visibly distinguished from the others

#### Scenario: A marked row under the cursor
- **WHEN** the cursor is on a marked row
- **THEN** both that it is selected and that it is marked can be told apart

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
### Requirement: An empty list explains itself
A list with no rows SHALL say why it is empty and how to leave that state. It
SHALL keep the column headers, which say what would be there, and place the
message where the rows would have been.

The wording SHALL follow the cause: a filter that matched nothing SHALL name the
filter text and say that it can be cleared, and SHALL say how many rows are
behind it; a list emptied by an option SHALL name the option that widens it; a
scan with no hosts SHALL say that rather than appearing to have failed.

While a list is empty the record pane SHALL be hidden, since there is no record
to report, and the message SHALL sit inside the same region the rows occupy.

#### Scenario: A filter matches nothing
- **WHEN** the user filters a list of 250 hosts by a term that matches none of them
- **THEN** the list says that nothing matches that term, that `Esc` clears the filter, and how many rows are behind it

#### Scenario: The headers stay
- **WHEN** a list is empty
- **THEN** its column headers are still shown and the message appears directly beneath them

#### Scenario: An option emptied the list
- **WHEN** the reachable-only host list has no hosts with evidence
- **THEN** the message says so and names the key that lists every host

#### Scenario: The empty state ends
- **WHEN** the filter is cleared and rows return
- **THEN** the message is gone and the record pane is shown again
### Requirement: A modal fits the terminal and says how to leave
A modal offering choices SHALL present them so that every choice is reachable in
a terminal of 24 rows: it SHALL NOT require more rows than the terminal has, and
SHALL scroll if the choices do not fit. Choices SHALL be moved between and
selected with the same keys the lists behind them use.

Every modal SHALL state, in itself, how to choose and how to cancel.

#### Scenario: Every choice is reachable on a short terminal
- **WHEN** the export chooser offers six recipes on a 24-row terminal
- **THEN** all six can be reached, the last one included

#### Scenario: Modals move like the lists behind them
- **WHEN** the user presses the down key in a modal
- **THEN** the next choice is highlighted

#### Scenario: A modal says how to leave
- **WHEN** any modal is open
- **THEN** it shows how to choose and that `Esc` cancels
### Requirement: The key hints degrade by priority
The hint bar SHALL NOT be cut off mid-item. When the hints do not fit the
terminal width, the system SHALL drop hints by priority rather than by position:
the navigation hints, the help key and `Esc` SHALL always be shown, and the
remainder SHALL fill the space that is left. When any hint has been dropped, the
bar SHALL indicate that more exist.

#### Scenario: A narrow terminal
- **WHEN** the hints do not fit the terminal width
- **THEN** navigation and the help key are still shown, and the bar indicates that some hints are not

#### Scenario: A wide terminal
- **WHEN** every hint fits
- **THEN** all of them are shown and nothing indicates a hidden one

#### Scenario: No hint is cut in half
- **WHEN** the bar is rendered at any width
- **THEN** every hint it shows is shown whole
### Requirement: Records can be marked across the whole viewer
The set of records worth exporting is assembled while reading a scan, across
several views, and is rarely what any single view is showing. The system SHALL
therefore let the user mark the row under the cursor, and SHALL keep those marks
until they are cleared or the viewer exits — through filtering, sorting, drilling
down, going back and switching tabs. Marking SHALL be reachable with a bare key,
as every other action in the viewer is, and one further key SHALL clear every
mark at once.

A row SHALL mark the records it stands for, not the row itself: a host row marks
that host, a row standing for a group of host/service pairs — a service across
hosts, a grouping bucket, a statistics line — marks every pair in it, and a row
that stands for nothing, such as a section heading, marks nothing. Marking a row
whose records are already all marked SHALL unmark them.

Marked rows SHALL be visibly distinguishable from unmarked ones in every view,
and the number of marked records SHALL be shown while any exist.

#### Scenario: A mark survives moving around
- **WHEN** the user marks a host, filters the list, drills into another view, comes back and clears the filter
- **THEN** that host is still marked

#### Scenario: One key marks a whole bucket
- **WHEN** the user marks the `https` row of the service overview, which covers twelve hosts
- **THEN** all twelve host/service pairs are marked

#### Scenario: Marking is a toggle
- **WHEN** the user marks a row that is already fully marked
- **THEN** its records are unmarked

#### Scenario: Marks are visible
- **WHEN** any record is marked
- **THEN** the marked rows are distinguishable in the list and the number of marked records is shown

#### Scenario: A heading marks nothing
- **WHEN** the user marks a section heading in the statistics view
- **THEN** nothing is marked

#### Scenario: Marks are cleared in one action
- **WHEN** the user invokes the clear-marks action
- **THEN** no record is marked and the list shows none
### Requirement: An export names its own fields and format
An exported list is read by another tool, so its shape matters as much as its
contents. Alongside the named derived lists, the system SHALL let the user
choose which fields to write, from a catalogue covering both host facts —
address, hostname, operating system, recorded state, evidence of reachability,
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
### Requirement: Every name a host is known by is visible
A scan learns a host's names from several kinds of evidence — a reverse lookup,
the certificate a TLS service presents, where an HTTP service redirects, what a
Windows service announces about itself, and a certificate-transparency lookup —
and every kind SHALL be recognised, kept with the host it belongs to, and shown
wherever a name is relevant. A name found more than once SHALL keep every piece
of evidence behind it, not the first. A name that nothing could resolve,
such as a wildcard or an address, SHALL NOT be presented as one.

A host's record SHALL list every name known for it together with where each came
from. A service's record SHALL show the names its own certificate claims and
every URL it answers on, the scanned address included. A list that shows a
host's name SHALL indicate when more names are known for it than the one shown.
The filter SHALL match any of a host's names, so a host can be found by a name
no column displays.

The system SHALL also provide an overview of the names themselves: each name,
where it came from, and the hosts and ports behind it, opening to those hosts.

#### Scenario: A name only a certificate knows
- **WHEN** a host has no resolved name and its TLS service's certificate names it
- **THEN** that name is shown for the host rather than the host appearing to have none

#### Scenario: Where a name came from
- **WHEN** the user looks at the record of a host with a resolved name and a certificate name
- **THEN** both are listed, each saying whether it was resolved or read from a certificate, and on which port

#### Scenario: A service's own names and addresses
- **WHEN** the user looks at the record of an HTTP service on a host with two names
- **THEN** the names its certificate claims are shown, and a URL for the address and for each name

#### Scenario: More names than fit a column
- **WHEN** a list shows the name of a host that has three
- **THEN** it shows one and indicates that two more are known

#### Scenario: Finding a host by a certificate name
- **WHEN** the user filters by a name that appears only in a certificate
- **THEN** the host that presented it is matched

#### Scenario: A host serving several sites
- **WHEN** a host presents a certificate naming three sites and redirects to a fourth
- **THEN** all four are known for that host, each attributed to what revealed it

#### Scenario: Corroboration is kept
- **WHEN** a name is both a certificate subject and a redirect target
- **THEN** both are shown for it rather than only the first

#### Scenario: A cited URL is not a name
- **WHEN** a script's output cites an advisory URL on another host
- **THEN** that host is not recorded as a name of the scanned host

#### Scenario: The names overview
- **WHEN** the user opens the names overview
- **THEN** every name found is listed with its source and the hosts behind it, and opening one shows those hosts
### Requirement: The detail can be read full-screen and searched
The record shown for the selected row SHALL be openable in a full-screen reader
that uses the whole height, for records too tall for the inline pane — a host
with many services, a vulnerability write-up, and above all a scan's raw output.
The reader SHALL show the same content the inline pane shows for that row,
including a scan's report in its current mode, so it is reachable from every
tab. It SHALL scroll like a pager and SHALL be dismissed back to the list.

The reader SHALL let the user search its content: entering a term SHALL
highlight every occurrence in place, and the user SHALL be able to move to the
next and previous occurrence without losing the surrounding context. The number
of matches SHALL be shown, and a search that matches nothing SHALL say so rather
than appearing to do nothing. Clearing the search SHALL remove the highlighting
and leave the reader open.

When the reader is showing a scan that is still running, its output SHALL
continue to update as the scan produces it, and an active search SHALL apply to
the new output as it arrives.

The reader SHALL let the user read the previous and next entry of the list it
was opened from without leaving it, so neighbouring records can be compared in
one place. Stepping SHALL move the list selection with it, so leaving the reader
lands on the entry last read, and SHALL stop at the ends of the list rather than
wrapping. An active search SHALL survive the move and be recounted against the
entry stepped onto.

The keys the reader uses to scroll and to jump to its own top and bottom SHALL
act on the reader, never on the list underneath it.

#### Scenario: Opening the detail full-screen
- **WHEN** the user opens the detail of a selected row
- **THEN** its record is shown using the full height and can be scrolled and dismissed

#### Scenario: Searching the output
- **WHEN** the user searches the full-screen detail for a term that occurs several times
- **THEN** every occurrence is highlighted, the match count is shown, and next/previous move between them

#### Scenario: A search that matches nothing
- **WHEN** the searched term does not occur
- **THEN** the reader says so rather than leaving the user unsure whether it searched

#### Scenario: Reading a running scan
- **WHEN** the reader is open on a scan that is still running
- **THEN** its output keeps updating, and an active search keeps matching the new lines

#### Scenario: Reachable from every tab
- **WHEN** the selected row is a host, a service, a grouping or a scan
- **THEN** opening the detail full-screen shows that row's record

#### Scenario: Reading the next entry without leaving
- **WHEN** the user steps to the next entry from inside the reader
- **THEN** that entry's record is shown from its top, the list selection moves with it, and leaving the reader lands on it

#### Scenario: Stepping past the end of the list
- **WHEN** the user steps back from the first entry, or forward from the last
- **THEN** the reader stays on that entry rather than wrapping around

#### Scenario: A search carried between entries
- **WHEN** a search is active and the user steps to another entry
- **THEN** the term is kept and its matches are recounted against the new entry

#### Scenario: Jumping to the reader's own ends
- **WHEN** the user presses the jump-to-first or jump-to-last key while the reader is open
- **THEN** the reader scrolls to its own top or bottom and the list selection does not move
