## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Derived lists can be exported
The output of this viewer is frequently the input to another command, so the
system SHALL let the user export derived lists: at least the host addresses, the
distinct open ports as a comma-separated list, `host:port` pairs, and HTTP/HTTPS
URLs constructed from the detected services including non-standard ports. Export
SHALL offer the same destinations as the search session — standard output, the
clipboard, or a file.

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

#### Scenario: Exports respect the filter
- **WHEN** a filter is active, nothing is marked, and the user exports any derived list
- **THEN** only the filtered rows contribute to it

#### Scenario: Marks win over the view
- **WHEN** records are marked and the user exports
- **THEN** the marked records are exported, whatever the current view is filtered to

#### Scenario: The source is stated
- **WHEN** the user starts an export
- **THEN** it says whether it will export the marked records or the rows on screen, and how many

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
