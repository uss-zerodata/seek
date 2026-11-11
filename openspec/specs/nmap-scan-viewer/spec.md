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

### Requirement: Malformed input is reported and skipped
A file that cannot be parsed SHALL NOT abort the run. The system SHALL report
which files failed and continue with those that succeeded.

Whether a file can be parsed is only known once it has been read, and reading
now happens with the viewer already open, so the system SHALL decide from what
it can establish cheaply whether opening the viewer is worthwhile: whether any
candidate scan file was found, and whether a scan could be started. When neither
holds, the system SHALL say so and exit without opening the viewer, as before.

When candidate files were found but every one of them fails to parse, the system
SHALL report the failures in the viewer and SHALL say, where the rows would have
been, that nothing could be read and which files failed — rather than appearing
to be an engagement with no hosts in it.

#### Scenario: One bad file among several
- **WHEN** three files are given and one is truncated mid-document
- **THEN** the viewer opens with the other two and reports the file that failed

#### Scenario: A file that is not nmap output
- **WHEN** a well-formed XML file that is not an nmap run is given
- **THEN** it is reported as not an nmap scan and skipped

#### Scenario: Nothing parseable
- **WHEN** every given file fails to parse
- **THEN** the failures are reported and the viewer says that nothing could be read, naming the files that failed

#### Scenario: Nothing to read and nothing to run
- **WHEN** the given paths hold no candidate scan file and no scan can be started
- **THEN** the system reports that and exits without opening the viewer

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

#### Scenario: Each level has its own filter
- **WHEN** the host list is filtered and the user opens a host, filters its ports, opens one of those services and then goes back twice
- **THEN** the host's port list opened unfiltered and comes back with its own filter, the host list comes back with its filter, and each is shown at the row it was left on

### Requirement: Going back is not quitting
`q` SHALL do exactly what `Esc` does: leave the filter, then clear it, then go
back one level, and quit only from the first overview with nothing left to
unwind. A dialog or a full-screen reader SHALL close on `q` as it does on `Esc`,
unless the reader is typing into a text box. Quitting from anywhere SHALL be
`Ctrl+Q` or `Ctrl+C`, and SHALL go through the same guard as every other quit.

#### Scenario: `q` on a drill-down
- **WHEN** the user presses `q` on a host's record opened from the host overview
- **THEN** the host overview is shown and the application stays open

#### Scenario: `q` at the top
- **WHEN** the user presses `q` on the first overview with no filter and nothing opened
- **THEN** the application quits, asking first if a scan is running

#### Scenario: Quitting from a drill-down
- **WHEN** the user presses `Ctrl+Q` or `Ctrl+C` on a drill-down
- **THEN** the application quits, asking first if a scan is running

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

### Requirement: Fuzzy filtering
Each view SHALL provide a filter that narrows the listed rows as the user types,
using the same query grammar as the search session — space-separated terms
combined with AND, `'exact`, `^prefix`, `suffix$`, `!negate`, and smart-case —
matched against the row's fields and against what the row's screenshots say:
their page titles, URLs, technologies and HTTP status. Clearing the filter SHALL
restore the full list. The characters a row matched on SHALL be highlighted
where they appear in the list, so the user can see why a row survived the filter.

When some rows contain the filter's words as written, only those SHALL be
listed; rows that match only because the letters occur scattered SHALL be left
out, counted, and named as left out, and `~` in the filter SHALL list them too.
When no row contains the words, the fuzzy matches SHALL be listed as they are,
so a typo still finds something.

A complete address SHALL denote every address beginning with it, so that the
list narrows smoothly while it is typed (`10.10.10.1` lists `.1`, `.10`–`.19`
and `.100`–`.199`); `=10.10.10.1` or `10.10.10.1/32` SHALL denote that host
alone. A term with an explicit prefix (`10.10.10.32/26`) SHALL be an address
range. Addresses and ranges side by side SHALL be a union. An incomplete address
SHALL remain an ordinary fuzzy term. Address terms and fuzzy terms SHALL compose
in one expression, and an address term SHALL be negatable like any other. The
addresses actually being applied SHALL be visible.

A port SHALL be written as nmap and URLs write it: `:443`, `443/tcp`, `53/udp`
or `port:443` SHALL denote a port with that number whatever its state, and
`10.10.10.10:8080` SHALL denote that host with that port. `open:` and `closed:`
SHALL keep asking for the state as well.

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

#### Scenario: A complete address is a beginning
- **WHEN** the user filters with `10.10.10.5`
- **THEN** `10.10.10.5` and `10.10.10.50` are listed, and `10.10.10.6` is not

#### Scenario: One host exactly
- **WHEN** the user filters with `=10.10.10.5`
- **THEN** only the host `10.10.10.5` is listed

#### Scenario: A partial address still matches many
- **WHEN** the user has typed `10.10.10.` and not yet completed the address
- **THEN** every host under `10.10.10.` is still listed

#### Scenario: The applied range is visible
- **WHEN** a range term is active
- **THEN** the interface shows the range being applied

#### Scenario: A port by number
- **WHEN** the user filters the host list with `:443`
- **THEN** every host with a port 443 recorded is listed, whether it is open, closed or filtered

#### Scenario: A host and a port
- **WHEN** the user filters with `10.10.10.10:8080`
- **THEN** only `10.10.10.10` is listed, and only if it has a port 8080

#### Scenario: Words before letters
- **WHEN** the user filters with `synology` and one host's screenshot title says Synology while two other rows only contain those letters scattered
- **THEN** only that host is listed, the interface says two looser matches were left out, and `synology ~` lists all three

#### Scenario: A screenshot finds its host
- **WHEN** a host's only mention of Hektor is the title of its captured web page and the user filters with `hektor`
- **THEN** the host is listed

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

#### Scenario: A host's ports are listed by number wherever they are listed
- **WHEN** a host has `8080/tcp`, `80/tcp`, `22/tcp`, `8080/udp`, `443/tcp` and `53/udp`, from one scan or merged from several
- **THEN** its record, its port list before any column is chosen, and an export of it all give them as `22/tcp`, `53/udp`, `80/tcp`, `443/tcp`, `8080/tcp`, `8080/udp` - never every TCP port before every UDP one

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
The system SHALL provide a `nmap` subcommand taking any number of file paths and
directories, in any mix, and opening the viewer on all of them as one merged
model. With nothing given it SHALL read the working directory. A file reached
through more than one of the given directories SHALL be read once. The viewer is
a purpose-built interface for scan output and SHALL be reached this way; the
file-search session SHALL NOT carry nmap-specific actions or hints.

When the given paths hold no readable scan and scanning is available, the
subcommand SHALL open the viewer on an empty model with the scope editor rather
than exiting: a directory with nothing in it yet is the case for starting a
scan, not an error. When scanning is unavailable it SHALL explain what it
expects and exit as before.

The output directory for any scan or capture started in that session SHALL be
the first directory given, or the working directory when only files were given,
unless an output directory is configured. The system SHALL name that directory
before anything is written — in the review of a scan and in the confirmation of
a capture — so that with several directories the choice is visible rather than
inferred.

#### Scenario: Opening files directly
- **WHEN** the user runs the `nmap` subcommand with two scan files
- **THEN** the viewer opens on the merged model of both

#### Scenario: Opening several directories
- **WHEN** the user runs the `nmap` subcommand with three directories
- **THEN** the viewer opens on one merged model of the scans found in all three

#### Scenario: Overlapping directories
- **WHEN** the user names a directory and also a subdirectory of it
- **THEN** each scan below the subdirectory is read once

#### Scenario: The search session stays a file search
- **WHEN** the highlighted result in a search session is an nmap XML file
- **THEN** the search session offers no nmap-specific action for it

#### Scenario: No paths given
- **WHEN** the subcommand is run with no paths
- **THEN** the working directory is read, as if it had been named

#### Scenario: A directory with no scans, and nmap available
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is available
- **THEN** the viewer opens with the scope editor, and that directory is where a scan will write

#### Scenario: A directory with no scans, and no nmap
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is not available
- **THEN** the system reports that there is nothing to read and exits

#### Scenario: Output goes to the first directory, and says so
- **WHEN** the viewer was opened on `dir1 dir2` and the user starts a scan
- **THEN** the review names a location under `dir1` as where the scan will write

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

### Requirement: Stateless operation
The system SHALL hold everything it needs for a run in memory for the duration of
that run. It SHALL NOT require an import or indexing step before files can be
read, SHALL NOT create or depend on a database or any other persistent store *of
scan data*, and SHALL NOT write to the filesystem except when the user
explicitly exports, or explicitly updates the vulnerability database. Two
invocations over the same files SHALL produce the same result regardless of what
was run before them, given the same vulnerability database.

The vulnerability database is reference data about public software, not about
the scanned network. It SHALL be created and changed only by an update the user
asked for or confirmed, SHALL never contain anything read from a scan or a
capture, and the viewer SHALL be fully usable without it. Only the vulnerability
and support columns then say that no database is present.

#### Scenario: Files are read directly, with no import step
- **WHEN** the user opens scan files that have never been seen before
- **THEN** they are read and presented immediately, with no prior import required

#### Scenario: Nothing is left behind
- **WHEN** a session ends in which no update was run
- **THEN** no database, cache or index file has been created

#### Scenario: Repeat runs are identical
- **WHEN** the same files are opened twice with no change on disk
- **THEN** both runs present the same hosts, services and counts

#### Scenario: Removing a file removes its data
- **WHEN** a file is omitted from a subsequent invocation
- **THEN** nothing it contributed persists into that run

#### Scenario: The database holds nothing from the engagement
- **WHEN** the vulnerability database is updated during a session over a client's scans
- **THEN** it contains only data downloaded from the public sources, and no address, name, product list or finding from the session

#### Scenario: No database is not an error
- **WHEN** the viewer opens and no vulnerability database exists
- **THEN** every view works as before, and the support and vulnerability columns say the database is missing

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

### Requirement: List navigation
The system SHALL let the user move through a list with the up and down arrow
keys, page through it, and jump to its first and last row, so that a scan of
several hundred hosts can be traversed without holding a key down. Navigation
SHALL keep the selected row and its detail in step. The left and right arrow keys
SHALL move through the selected row's record, since a row-oriented list has no
horizontal cursor to move. Every arrow key SHALL have a vim equivalent that does
exactly the same thing - `k`/`j` for up/down, `h`/`l` for left/right - so either
set navigates the whole viewer. While the filter is being edited the arrow keys
SHALL move the text cursor as usual.

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

#### Scenario: Left and right move through the record
- **WHEN** the selected row's record is taller than the space for it and the user presses the right arrow, or `l`, repeatedly
- **THEN** the record's line cursor moves down and the record scrolls to follow it, and the selected row does not change

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

### Requirement: A long record is navigated by a line cursor
When the record for the selected row is taller than the space available, the user
SHALL be able to move through it without leaving the list or losing the selection.
The pane SHALL have a line cursor, as a text editor does: the left and right
arrow keys, and `h`/`l`, SHALL move it one line up and down, every line SHALL be
a stop, and the cursor line SHALL be visibly distinguished. The pane SHALL keep
the cursor in view, moving the record under it when the cursor reaches an edge
of the visible region. Where the cursor cannot move - a record that is one block
of text, or its last line - the same keys SHALL scroll the record a line instead.
Moving the list to another row SHALL return the cursor to the top of the new
record.

Lines that can be opened SHALL be styled as links, so they can be told apart
before the cursor reaches them, and the open key SHALL open the line under the
cursor when it is one.

The pane SHALL NOT step between rows or between scans itself: the previous and
next row are read in the full-screen reader, or by moving the list.

#### Scenario: Moving through a long record
- **WHEN** the selected row's record does not fit and the user presses the right arrow repeatedly
- **THEN** the cursor moves down a line per press, the record scrolls once the cursor reaches the edge, and the list selection is unchanged

#### Scenario: Moving back up
- **WHEN** the cursor is at the end of a long record and the user presses the left arrow repeatedly
- **THEN** the cursor moves up a line per press and the record scrolls once the cursor reaches the top edge

#### Scenario: Arrows and vim keys agree
- **WHEN** the user presses `l` or `h` instead of the right or left arrow
- **THEN** the cursor moves exactly as the arrow would move it

#### Scenario: Links are visible
- **WHEN** a record lists the scans that saw its subject
- **THEN** those lines are styled as links, and the open key opens one when the cursor is on it

#### Scenario: A new selection starts at the top
- **WHEN** the user moves the pane cursor down a record and then selects a different row
- **THEN** the new record is shown from its beginning with the cursor on its first line

#### Scenario: A record that is one block of text
- **WHEN** the record is a single block, such as a scan's report, and the user presses the right arrow
- **THEN** the record scrolls a line

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
address, hostname, operating system, recorded state, whether the host is up,
the scans a record was seen in — and service facts — port, protocol, service
name, product, version, and the URL where one applies. Field order in the output
SHALL be fixed by the catalogue, so that two exports of the same fields are
comparable.

The system SHALL write JSON, CSV and plain text. CSV SHALL carry a header row
naming the fields and SHALL quote values that need it; JSON SHALL be a list with
one object per record, keyed by field name; text SHALL write one record per
line. A record whose output row is identical to one already written SHALL be
written once. Values come from the scanned hosts, so a CSV cell that begins
like a spreadsheet formula (`=`, `+`, `-`, `@`, a tab or a carriage return)
SHALL be written inert, prefixed with `'`; the text and JSON forms SHALL keep
the value as written.

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

#### Scenario: A banner cannot become a formula
- **WHEN** a product string from a scanned host begins with `=` and the user exports as CSV
- **THEN** the cell is written with a leading `'`, and the same export as text or JSON keeps the string as written

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
including a scan's report in its current mode and, where the pane is showing a
record's scoped raw output, that output — so that reading the raw text
full-screen, searching it and paging through it need no separate way in. It
SHALL scroll like a pager and SHALL be dismissed back to the list.

The reader SHALL let the user search its content: entering a term SHALL
highlight every occurrence in place, and the user SHALL be able to move to the
next and previous occurrence without losing the surrounding context. The number
of matches SHALL be shown, and a search that matches nothing SHALL say so rather
than appearing to do nothing. Clearing the search SHALL remove the highlighting
and leave the reader open.

When the reader is showing a scan that is still running, its output SHALL
continue to update as the scan produces it, and an active search SHALL apply to
the new output as it arrives.

The reader SHALL have the same two levels as the pane, and its arrow keys SHALL
stay within the level on screen. On a record it SHALL have a line cursor that
the up and down keys move a line at a time, with the lines that open something
styled as links and the open key following the one under the cursor into that
scan's text. On a scan's text the up and down keys SHALL scroll, the left and
right keys SHALL show the previous and next scan's text about the same subject,
stopping at the ends, and leaving SHALL return to the record at the link it was
opened from rather than closing the reader. A reader opened on the text the pane
is showing SHALL likewise return to that row's record first.

On a record, the reader SHALL let the user read the previous and next entry of the list it
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

#### Scenario: Reading scoped raw output full-screen
- **WHEN** the pane is showing a record's scoped raw output and the user opens the detail full-screen
- **THEN** that same output is shown full-screen and can be searched and paged

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

#### Scenario: Following a link in the reader
- **WHEN** the reader shows a host's record and the user moves the cursor to a scan it lists and opens it
- **THEN** that scan's text about the host is shown in the reader, and the list selection is unchanged

#### Scenario: Stepping between scans stays in the text
- **WHEN** the reader shows one scan's text about a host that several scans saw, and the user presses the right arrow
- **THEN** the next scan's text about the same host is shown, not another row's record

#### Scenario: Leaving the text returns to the record
- **WHEN** the reader shows a scan's text and the user presses the key that leaves
- **THEN** the reader shows the record again with the cursor on that scan's link, and leaving again closes the reader

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

### Requirement: Reading an engagement does not block the viewer
An engagement of a hundred or more scan files takes seconds to read, and a
terminal application that shows nothing for that long is indistinguishable from
one that has hung. The system SHALL open the viewer before the scans have been
read and SHALL fill the model as they are read, so that the hosts already read
can be listed, filtered, sorted and drilled into while the rest is still
arriving.

The model SHALL grow only by addition during a read: a host or a service that
has been shown SHALL NOT disappear again, and the same file SHALL NOT be folded
in twice. What is shown SHALL always be a consolidated model of whole files, so
that a host is never displayed half-merged.

Additions SHALL be published on a throttled cadence rather than once per file,
on the same principle the search engine applies to its result snapshots: the
system SHALL leave a minimum interval between publications and SHALL publish
only when something new has been read. Re-projecting the overviews costs more
than reading one file, so publishing per file would spend the time it is trying
to save.

While a read is in progress the system SHALL say so and SHALL say how far it has
got, in files read out of files found, and the count of hosts known SHALL be
visible as it grows.

#### Scenario: The viewer opens before the reading finishes
- **WHEN** the viewer is opened on a directory of 120 scan files
- **THEN** the interface is on screen and answering input before all 120 have been read

#### Scenario: The list fills as scans are read
- **WHEN** 30 of 120 files have been read
- **THEN** the host list shows the hosts those 30 files recorded, and says that 30 of 120 have been read

#### Scenario: Additions are published on a cadence
- **WHEN** a hundred small files are read in under a second
- **THEN** the model is published on the throttled cadence rather than a hundred times

#### Scenario: What was shown stays shown
- **WHEN** a later scan file is folded into a model already on screen
- **THEN** every host already listed is still listed, with its services at least as complete as before

#### Scenario: The read finishes
- **WHEN** the last file has been read
- **THEN** the progress report is gone and the model is the same one a blocking read would have produced

### Requirement: Long work reports its progress and can be abandoned
Any work that keeps the user waiting SHALL say what it is doing, and SHALL say
how far it has got whenever the work can count itself — reading files, folding
them together, building the scan history, and projecting an overview all can.
Work that cannot count itself SHALL show that it is running rather than counting
nothing.

A determinate report SHALL name the units it counts, so that the figure can be
related to the work: files for a read, scans for the scan history, hosts for a
projection. The report SHALL appear in the region the awaited content will
occupy, under that content's own headings, so it is clear which part of the
interface is waiting.

Work that has kept the user waiting for longer than a moment SHALL be
abandonable from the keyboard, and abandoning it SHALL leave the interface in a
state that says what was given up and how to ask for it again. Abandoning SHALL
NOT discard anything already read.

Where the awaited content would replace content that is already on screen and
still true — a re-read after a scan finishes — the system SHALL leave that
content in place and report the progress outside the list, rather than replacing
a true list with a progress report.

#### Scenario: A countable wait shows a bar
- **WHEN** the scan history is being built from 120 scan files
- **THEN** the Scans tab shows a bar with the scans done out of the total

#### Scenario: Every overview reports, not just one
- **WHEN** an overview over 24 000 hosts is being projected
- **THEN** that tab reports its progress in hosts, under its own column headings

#### Scenario: An uncountable wait still says it is working
- **WHEN** work is running that cannot report a total
- **THEN** the interface shows that it is running, and does not show a bar at zero

#### Scenario: A wait is abandoned
- **WHEN** the user presses the key that leaves a state while an overview is being projected
- **THEN** the wait ends at once, the interface says what was abandoned and how to ask for it again, and nothing already read is lost

#### Scenario: A re-read keeps the list it is replacing
- **WHEN** a scan finishes and the whole engagement is re-read to fold it in
- **THEN** the rows already on screen stay, and the progress is reported outside the list

### Requirement: The interface stays responsive while work runs
Moving work off the interface's own thread is not enough on its own: the work
still competes for the interpreter, and a memory-management pause during it
stops everything. The system SHALL keep answering input while reading,
consolidating or projecting, and SHALL NOT pause the interface for longer than
a fifth of a second at a time on account of that work.

An overview SHALL be projected once for a given model. A sort, a filter
keystroke, a resize, or a return from a drill-down SHALL be answered from work
already done rather than by projecting the model again — the model has not
changed, so the projection cannot have.

A list too long to hand to the terminal at once SHALL be given to it in
instalments, so that the part the user can see is there immediately and the
remainder follows without blocking input. While a list is still being handed
over the system SHALL say how much of it has arrived.

#### Scenario: Keys are answered during a projection
- **WHEN** an overview over 24 000 hosts is being projected
- **THEN** keystrokes continue to be answered, with no pause longer than a fifth of a second

#### Scenario: A filter keystroke does not re-project
- **WHEN** the user types in the filter box over an overview that has already been projected
- **THEN** the list narrows without the overview being projected again

#### Scenario: A long list arrives in instalments
- **WHEN** a projection yields 24 000 rows
- **THEN** the first screenful is displayed at once, the rest follows without blocking input, and the interface says how many have arrived

#### Scenario: Returning from a drill-down
- **WHEN** the user opens a host's record and goes back to the overview
- **THEN** the overview is shown again without being projected a second time

### Requirement: A record can show the raw scan output for its own subject
Everything the viewer shows is derived from the XML, and a derived value can
only be trusted as far as the derivation is. The system SHALL therefore make
nmap's own text reachable from the record it describes, so that what was parsed
can be checked against what was written, and so that the things nmap reports
only in its text — the ports it did not list and why, the reason a port was
called open, the timing of the scan — are readable where they are relevant.

The output SHALL be scoped to the subject of the record. For a host, that is
what the scan wrote about that host; for a service, what it wrote about that
port on that host, together with the host line the port belongs to, so the
block says which host it is describing. The whole file SHALL NOT be shown: an
engagement's output runs to tens of thousands of lines and the record's subject
is a handful of them.

A record SHALL list every scan that recorded its subject, one entry per line,
each naming the scan and saying what it contributed, so that a subject seen by
three scans offers three separate pieces of output rather than a merged one.
The order SHALL be the order the scans ran.

When a scan's own output file is not present — an engagement handed over as XML
alone leaves none — the entry SHALL still be offered, showing a report
reconstructed from what was parsed and labelled as reconstructed, so that it is
never mistaken for what nmap wrote. When a file is present but cannot be read,
the entry SHALL say so rather than appearing empty.

Reading raw output SHALL NOT change the model: it is text to be read, never a
second source the parsed record is reconciled against.

#### Scenario: A host's record offers the scans that saw it
- **WHEN** the cursor is on a host recorded by three scans
- **THEN** its record lists three entries, one per scan, each naming the scan and what it found

#### Scenario: Raw output is scoped to the host
- **WHEN** the user opens the raw output of a scan from a host's record
- **THEN** what that scan wrote about that host is shown, and the rest of the file is not

#### Scenario: Raw output is scoped to the port
- **WHEN** the user opens the raw output of a scan from a service's record
- **THEN** what that scan wrote about that port is shown, together with the host line it belongs to

#### Scenario: Output nmap reports only in its text
- **WHEN** a scan's text records ports that were not listed individually, and the reason a port was called open
- **THEN** those lines are present in the scoped output, although no column or parsed field carries them

#### Scenario: A scan that left no output file
- **WHEN** the scan behind an entry has no output file beside its XML
- **THEN** the entry shows a report reconstructed from the parsed record, labelled as reconstructed

#### Scenario: A scan whose output file cannot be read
- **WHEN** the output file exists but cannot be read
- **THEN** the entry says so, rather than showing an empty report

### Requirement: The record pane shows either the record or one raw entry
The pane SHALL have two states for the row the cursor is on: the parsed record,
and the raw output of one scan of that record's subject. Opening an entry SHALL
replace the record with that entry's output in the same region, so that reading
it does not cost the list, the selection or the surrounding context.

While raw output is shown the pane SHALL say which scan it came from and what
it is scoped to, since the text itself does not identify either. The key that
leaves a state SHALL return from the raw output to the record it was opened
from, and the record SHALL be shown at the entry that was opened rather than
back at its top.

Moving the list cursor to another row SHALL return the pane to the record
state, because the raw output on screen belongs to the row that was left.

#### Scenario: Following an entry
- **WHEN** the user opens a scan entry from a record
- **THEN** the pane shows that scan's output for the record's subject, with a heading naming the scan and the subject

#### Scenario: Coming back
- **WHEN** the user leaves the raw output
- **THEN** the record is shown again, positioned at the entry that was opened

#### Scenario: Moving the list while raw output is shown
- **WHEN** the user moves the list cursor to another row while raw output is on screen
- **THEN** the pane shows the new row's record rather than output belonging to the row that was left

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

Where the user asks to look at the screenshot of a row that has several
captures, the choice SHALL offer to open all of them together in the web
interface - narrowed to that row - before offering each one alone.

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

#### Scenario: Several captures of the selected row
- **WHEN** the user asks to open the screenshot of a row with three captures
- **THEN** the choice offers all three side by side in the web interface first, and each one alone after it

#### Scenario: Both servers
- **WHEN** the user has opened the web interface and then starts gowitness's report server
- **THEN** both are running, each on its own port

### Requirement: A scan file that stops part-way keeps what it finished
A scan file whose XML stops part-way, as a cancelled or crashed scan leaves it, SHALL be read for every host it finished. The viewer SHALL name it as incomplete, with the number of hosts kept, and SHALL NOT report it as unreadable. A file that stops before any host is finished SHALL be reported as unreadable, as before.

#### Scenario: A cancelled scan
- **WHEN** a scan is cancelled after nmap finished two hosts
- **THEN** reading its file shows those two hosts and says the file is incomplete

#### Scenario: Nothing finished
- **WHEN** a scan file stops before its first host is complete
- **THEN** it is reported as unreadable

### Requirement: Scans are named unambiguously across directories
When two or more directories are given, a scan's file name alone no longer
identifies it: tools and presets write the same names into every directory. The
system SHALL then name every scan by its path relative to the common parent of
the given directories, and SHALL use that name everywhere a scan is named — the
provenance of hosts and services, a record's scan entries, the Scans tab, the
report of files that failed to parse, and the exported list of source scans.

Provenance SHALL be kept per file, so that a host seen in two files with the same
file name is recorded as seen in both.

With a single directory, or with only files given, scans SHALL keep being named
by their file name alone.

#### Scenario: Same file name in two directories
- **WHEN** the viewer is opened on `x` and `y`, each holding a `scan.xml` that records host `192.0.2.40`
- **THEN** the host is listed as seen in `x/scan.xml` and in `y/scan.xml`, not once as `scan.xml`

#### Scenario: Every scan is qualified once there are several directories
- **WHEN** the viewer is opened on two directories and one of them holds `sub/other.xml`
- **THEN** that scan is named `<directory>/sub/other.xml` in the Scans tab and in the records, even though no other scan shares its file name

#### Scenario: A single directory keeps bare names
- **WHEN** the viewer is opened on one directory
- **THEN** scans are named by their file name alone, as before

#### Scenario: A failure names the file unambiguously
- **WHEN** two directories each hold a truncated `scan.xml`
- **THEN** the failure report names both, each qualified by its directory

### Requirement: The filter accepts field terms and logical operators
Alongside fuzzy terms and address ranges, the filter SHALL accept field terms
that are tested against the scan model rather than the row's text:

- `open:PORT` and `open:PORT/PROTO` SHALL match a port the scan found open;
- `closed:PORT` and `closed:PORT/PROTO` SHALL match a port the scan recorded in
  any state other than open — closed, filtered or `open|filtered`;
- a port the scan never recorded SHALL match neither;
- `service:VALUE` SHALL match a port whose service name contains the value, and
  `product:VALUE` one whose detected product contains it, case-insensitively,
  with `^` and `$` anchoring as in the fuzzy grammar.

The port-state keys SHALL be `open:` and `closed:`, so that "up" keeps its one
meaning: the host rule.

Terms SHALL combine with `AND`, `OR` and `NOT` written in uppercase, with `|` for
OR, with `!` for NOT as today, and with parentheses; a space between terms SHALL
mean AND; NOT SHALL bind tighter than AND, and AND tighter than OR. Lowercase
`and`, `or` and `not` SHALL remain ordinary search words, and a `key:` that is
not one of the fields SHALL remain an ordinary search term.

Field terms joined by AND SHALL describe the same port: a row matches only if one
of its ports satisfies all of them. `NOT` applied to field terms SHALL mean that
none of the row's ports satisfies them. For a row that stands for several ports —
a host, a service across hosts, a grouping bucket — the row SHALL match when any
of its ports, or pairs, does.

A filter that uses none of this syntax SHALL behave exactly as before, including
the union of several address ranges, which SHALL also hold for ranges joined by
AND inside a structured filter.

Since the filter is applied on every keystroke, an incomplete expression SHALL
NOT empty the list: a missing closing parenthesis SHALL be implied, a trailing
operator and a field with no value SHALL be ignored, and a field value that
cannot be understood SHALL be ignored. The status line SHALL show how the filter
was understood, with its operators and grouping made explicit, and SHALL name
any term it ignored.

#### Scenario: A port that is open
- **WHEN** the user filters the host list with `open:22`
- **THEN** exactly the hosts with port 22 open are listed, and a host whose address contains `22` but has no open port 22 is not

#### Scenario: A port seen not open
- **WHEN** the user filters with `closed:443/tcp`
- **THEN** hosts on which 443/tcp was recorded closed or filtered are listed, and hosts on which it was never scanned are not

#### Scenario: Service and product
- **WHEN** the user filters with `service:http product:nginx`
- **THEN** hosts with a port whose service is http-like and whose product is nginx are listed

#### Scenario: AND ties field terms to one port
- **WHEN** a host runs http served by Apache on port 80 and ssh served by OpenSSH on port 22, and the user filters with `service:http AND product:openssh`
- **THEN** the host is not listed, because no single port is both; with `service:http AND product:apache` it is

#### Scenario: OR
- **WHEN** the user filters with `service:ssh OR service:telnet`
- **THEN** hosts offering either are listed

#### Scenario: NOT means none of the ports
- **WHEN** the user filters with `NOT service:ssh`
- **THEN** only hosts with no ssh port are listed, even if they have other ports

#### Scenario: Grouping
- **WHEN** the user filters with `service:http AND NOT (product:apache | product:iis)`
- **THEN** hosts with an http port and no port served by Apache or IIS are listed

#### Scenario: Structured and plain terms together
- **WHEN** the user filters with `10.0.0.0/24 open:445 !printer`
- **THEN** hosts in that range, with 445 open, and not fuzzy-matching `printer` are listed

#### Scenario: A plain filter is unchanged
- **WHEN** the user filters with `apache !ssl 10.0.0.0/8 192.168.0.0/16`
- **THEN** the result is exactly what it was before this change

#### Scenario: Port rows are filtered by their own port
- **WHEN** a host's port list is filtered with `service:ssh OR open:80`
- **THEN** only its ssh port, and port 80 if it is open, are listed

#### Scenario: Lowercase words are search words
- **WHEN** the user filters with `rock and roll`
- **THEN** it is three fuzzy terms, not an operator

#### Scenario: An unknown key is text
- **WHEN** the user filters with `http://intranet`
- **THEN** it is matched as text, not as a field

#### Scenario: Typing an incomplete query
- **WHEN** the user has typed `service:ssh OR (open:22` and not yet closed the parenthesis
- **THEN** the list shows what the completed expression would, and the status line shows the expression with the parenthesis closed

#### Scenario: A field without a value while typing
- **WHEN** the user has typed `service:`
- **THEN** the list is not emptied, and the status line says the term is being ignored

#### Scenario: An invalid port
- **WHEN** the user filters with `open:web`
- **THEN** the term is ignored and named in the status line as not understood

#### Scenario: Matches are still highlighted
- **WHEN** the user filters with `apache OR nginx`
- **THEN** the characters matching whichever term a row matched on are highlighted

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
