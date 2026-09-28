## ADDED Requirements

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

## MODIFIED Requirements

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
- **WHEN** the reachable-only host list has no hosts with evidence
- **THEN** the message says so and names the key that lists every host

#### Scenario: Empty because the work is not finished
- **WHEN** the host list has no rows because the scans are still being read
- **THEN** the message says the reading is still going and how far it has got, and is distinct from the settled no-hosts message

#### Scenario: The empty state ends
- **WHEN** the filter is cleared and rows return
- **THEN** the message is gone and the record pane is shown again
