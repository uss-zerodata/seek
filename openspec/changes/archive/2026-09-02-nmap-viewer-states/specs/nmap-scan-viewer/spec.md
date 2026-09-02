## ADDED Requirements

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
