## ADDED Requirements

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

## MODIFIED Requirements

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
