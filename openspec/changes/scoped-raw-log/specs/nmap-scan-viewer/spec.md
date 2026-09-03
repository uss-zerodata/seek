## ADDED Requirements

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

## MODIFIED Requirements

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
- **WHEN** the cursor is on a host whose `up` state came from `-Pn` and which shows no evidence
- **THEN** the detail says the state was asserted rather than observed

#### Scenario: The pane can be dismissed
- **WHEN** the user presses the detail-pane key
- **THEN** the pane is hidden and the list occupies the freed space

#### Scenario: The pane is dropped on a short terminal
- **WHEN** the terminal is too short to show both the list and the detail
- **THEN** the detail is hidden and the list stays usable

### Requirement: A long record is navigated by a line cursor
When the record for the selected row is taller than the space available, the user
SHALL be able to move through it without leaving the list or losing the selection.
The pane SHALL be navigated by a cursor that moves one line at a time and is
visibly distinguished from the rest of the record, rather than by scrolling with
no indication of position: the record contains lines that can be acted on, and
which line is current has to be answerable before one can be chosen.

The pane SHALL keep the cursor in view, moving the record under it when the
cursor reaches an edge of the visible region. Moving the list to another row
SHALL return the cursor to the top of the new record.

Most lines of a record cannot be acted on, so the system SHALL also let the user
move the cursor directly to the next and to the previous line that can be, and
SHALL make clear which lines those are. Reaching the end SHALL stop there rather
than wrapping.

The keys that move this cursor SHALL be distinct from those that move the list,
so that neither moves the other, and SHALL keep working when the record contains
no line that can be acted on — moving through it is how a long record is read.

#### Scenario: Moving through a long report
- **WHEN** the selected row's record does not fit and the user moves the pane cursor down
- **THEN** the cursor moves down a line, the record scrolls once the cursor reaches the edge, and the list selection is unchanged

#### Scenario: The current line is visible
- **WHEN** the pane cursor is on a line
- **THEN** that line is distinguished from the rest of the record

#### Scenario: A new selection starts at the top
- **WHEN** the user moves the pane cursor down a record and then selects a different row
- **THEN** the new record is shown from its beginning with the cursor on its first line

#### Scenario: Jumping to the next line that can be opened
- **WHEN** the record's openable entries are far below the cursor and the user presses the jump-to-next key
- **THEN** the cursor moves to the next such line rather than a line at a time

#### Scenario: Jumping past the last one
- **WHEN** the cursor is on the last line that can be opened and the user jumps forward again
- **THEN** the cursor stays where it is rather than wrapping to the first

#### Scenario: A record with nothing to open
- **WHEN** the record contains no line that can be opened
- **THEN** the cursor still moves through it a line at a time and the record can still be read to its end

#### Scenario: The two cursors are independent
- **WHEN** the user moves the pane cursor
- **THEN** the list selection does not move, and the keys that move the list do not move the pane cursor

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
