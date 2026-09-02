# onscreen-guidance Specification

## Purpose
A persistent, context-sensitive hint bar that keeps the keybindings and `Esc`
behaviour relevant to the user's current situation visible on screen at all
times, so a first-time user can operate the whole interface without opening the
help overlay or reading documentation.
## Requirements
### Requirement: Persistent hint bar

The system SHALL display a single-line hint bar as a permanent part of the main
interface, positioned immediately above the query input (between the status bar
and the query input, so the query input stays the bottom-most element). The hint
bar SHALL always be present while the main screen is shown (tree view, result
list, and no-match state alike) and SHALL be styled so it reads as guidance
rather than as another result region. The hint bar SHALL NOT be dropped to
reclaim space; when the terminal is too short to show the preview, the preview is
dropped first and the hint bar remains.

#### Scenario: Hint bar is always visible on the main screen

- **WHEN** the interface is open and no overlay, menu, or detail view is on top
- **THEN** a one-line hint bar is visible just above the query input, regardless
  of whether the tree view, the result list, or the no-match message is showing

#### Scenario: Hint bar survives a short terminal

- **WHEN** the terminal height is reduced until the preview pane is dropped
- **THEN** the hint bar is still shown and only the preview has been removed

### Requirement: Context-sensitive hint content

The hint bar SHALL show only the keybindings that are useful in the current
context, choosing between at least these contexts: the empty-query tree view,
the result list with a highlighted row, and the no-match state. Each hint SHALL
pair a key with a short verb for what it does. When the result list is showing,
the hint bar SHALL include the primary "view / open detail" key, at least one
"open" action key, the "copy path" key, the "mark" key, and the "action menu"
key. When the tree view is showing, the hint bar SHALL indicate that typing
starts a search and SHALL include the key that scrolls the tree and the key that
opens help. The hint bar SHALL NOT attempt to list every binding — the help
overlay remains the complete reference.

#### Scenario: Hints change when results appear

- **WHEN** the query box is empty and then the user types a query that produces
  results
- **THEN** the hint bar changes from tree-view hints (typing starts a search,
  scroll, help) to result hints (view, open, copy, mark, action menu)

#### Scenario: Hints reflect the no-match state

- **WHEN** a non-empty query has settled with zero matches
- **THEN** the hint bar shows keys for toggling the match modes and for opening
  help, rather than result-action keys

#### Scenario: Every hint names a key and an action

- **WHEN** the hint bar is shown in any context
- **THEN** each item consists of a key and a short label for what that key does

### Requirement: Hints reflect the user's configured keys

The hint bar SHALL display the actual key currently bound to each action,
resolved from the user's configuration, not a hard-coded default. Re-binding an
action in the config SHALL change the key shown in the hint bar for that action.

#### Scenario: Rebound key shown in the hint bar

- **WHEN** the user has rebound the "copy path" action to a non-default key in
  the config and opens the interface
- **THEN** the hint bar shows that configured key for the copy action

### Requirement: Hint bar shows the current `Esc` behaviour

The hint bar SHALL make the current meaning of `Esc` explicit, distinguishing at
least: `Esc` clears the query, `Esc` pops a breadcrumb level, and `Esc` quits.
The label SHALL match what `Esc` will actually do if pressed at that moment.

#### Scenario: Esc label tracks the query state

- **WHEN** the user has typed a non-empty query
- **THEN** the hint bar indicates that `Esc` clears the query

#### Scenario: Esc label at the top level

- **WHEN** the query box is empty and the breadcrumb is at the launch root
- **THEN** the hint bar indicates that `Esc` quits

