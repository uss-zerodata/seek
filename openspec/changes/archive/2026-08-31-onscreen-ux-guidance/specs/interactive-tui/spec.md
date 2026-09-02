## MODIFIED Requirements

### Requirement: Streaming result list with typed rows
The system SHALL display the current results above the query box, updating as the walk streams in and as the query changes. Each row SHALL show a marker for its match type (filename, directory, or content), and SHALL visually highlight the characters that matched the query. Content rows SHALL show `path:line` and the matching line's text. The path portion of a row and the matched content SHALL be rendered in distinct colours.

Whenever results are still arriving — during the initial walk, and during a query's content-search pass after the walk has finished — the system SHALL show an animated "working" indicator, and SHALL remove it once the current query's results have settled. The indicator SHALL appear both next to the query prompt (the prompt glyph animates) and on the status line, and on the status line SHALL name the phase: a running count of items found while walking, and a "searching" state during the content pass.

#### Scenario: Scanning indicator during the walk
- **WHEN** the initial walk is still running
- **THEN** the interface shows an animated indication that scanning is in progress together with a running count of items found

#### Scenario: Working indicator during a content search
- **WHEN** the walk has finished and a query's content-search pass is still producing results
- **THEN** the prompt glyph animates and the status line shows an animated "searching" indicator

#### Scenario: Indicator clears when results settle
- **WHEN** the current query's search has produced its final result set
- **THEN** the animated indicator is removed and the prompt glyph returns to its resting state

#### Scenario: Match count shown
- **WHEN** results are displayed and the engine reports more total matches than are shown
- **THEN** the interface shows both the number displayed and the total (for example `500 / 3418`)

### Requirement: Screen layout
The system SHALL arrange the interface top to bottom as: the preview pane, then the result list (or the empty-query tree view), then a status line, then a one-line hint bar, then the query input docked at the very bottom of the screen. The result list SHALL occupy the remaining vertical space and SHALL always be present and readable while a search is active. The status line SHALL carry the active match modes and the result count together. A visible divider SHALL separate the result area from the status / hint / query cluster below it; the divider SHALL be a thin rule rather than a filled background band, so that no interface text is rendered on a saturated fill. The hint bar SHALL sit between the status line and the query input and SHALL carry context-relevant keybinding guidance (see the `onscreen-guidance` capability).

#### Scenario: Query box is at the bottom
- **WHEN** the interface is open
- **THEN** the query input is the bottom-most element, with the hint bar directly above it and the status line directly above the hint bar

#### Scenario: Preview is above the list
- **WHEN** the preview pane is shown
- **THEN** it appears above the result list, not beside it

#### Scenario: Result area is fenced off by a rule, not a fill
- **WHEN** the interface is open
- **THEN** a thin rule divides the result area from the status / hint / query cluster, and none of the status, hint, or mode-indicator text sits on a filled background band

#### Scenario: Status bar groups modes and count
- **WHEN** results are shown
- **THEN** the active match modes and the `shown / total` count appear together on the status line, above the hint bar

### Requirement: Live match-mode toggles
The system SHALL let the user toggle each match mode (filename, directory, content) on or off during the session via a keybinding and via the action menu, and SHALL recompute results for the current query when a mode is toggled. The active modes SHALL be visible in the interface. The mode indicator in the status bar SHALL name each mode with a word (not only a single letter), SHALL show for each mode whether it is currently on or off, and SHALL show the key that toggles the modes. Each mode word SHALL begin with the same letter used as that kind's result-row marker, so a user can connect a row's marker to the mode that produced it. When a settled query returns no matches and a mode that could plausibly have matched is off, the interface SHALL point this out (see the no-match requirement).

#### Scenario: Mode indicator is self-describing
- **WHEN** the interface is showing results
- **THEN** the status bar names each match mode in words, shows which modes are on and which are off, and shows the key that toggles them

#### Scenario: Mode word matches the row marker letter
- **WHEN** the result list contains filename, directory, and content rows
- **THEN** each row's match-type marker is the first letter of the corresponding mode word in the status-bar indicator

#### Scenario: Toggling content mode on
- **WHEN** content mode is off and the user presses the content-toggle key with a non-empty query
- **THEN** content results appear in the list and the interface shows content mode as active

#### Scenario: Toggling a mode off
- **WHEN** directory mode is on and the user toggles it off
- **THEN** directory rows are removed from the list and no new ones appear until it is toggled back on

### Requirement: Empty-query tree view
When the query is empty the system SHALL replace the result list with a non-interactive tree view of the current search root (respecting the active scope and exclusions). Above the tree the system SHALL show a heading line that names the current search root and states the walk semantics currently in effect (whether hidden files are included, whether `.gitignore` is being honoured, and that noise directories are pruned) and prompts the user that typing starts a search. The tree SHALL be coloured: directory names, the branch glyphs, and file names (by type) SHALL each be rendered in distinct styles. Entering any query text SHALL switch to the ranked result list; clearing the query again SHALL return to the tree view.

#### Scenario: Tree shown at empty query
- **WHEN** the query box is empty
- **THEN** the results area shows a heading line naming the current root and the active walk semantics, above a coloured tree of that root, and does not accept row selection or marking

#### Scenario: Heading reflects gitignore state
- **WHEN** the session was started with `.gitignore` honouring enabled
- **THEN** the empty-state heading says that `.gitignore` is being honoured

#### Scenario: Typing leaves the tree view
- **WHEN** the user types a character into an empty query box
- **THEN** the results area switches to the ranked result list

### Requirement: Full-screen detail view
Pressing `Enter` on a row SHALL open a full-screen detail view of its target. For a file the detail view SHALL show the whole file (up to the size cap, then truncated with an indicator), syntax-highlighted, with every query match highlighted, opened scrolled to and marking the matched line for a content match. For a directory it SHALL show a scrollable tree. The view SHALL scroll like a pager — at least `↑`/`↓` line scrolling, `PageUp`/`PageDown`, half-page, and jump-to-top / jump-to-bottom — and query matches SHALL stay highlighted while scrolling. The detail view SHALL display its own controls on screen — at least the scroll keys, the back key, and the keys that open the target in an editor or the default application. Triggering an open action from the detail view SHALL run that action on the previewed target as if it had been triggered from the result list. `Esc` (or the back key) SHALL return to the result list.

#### Scenario: Detail view shows its controls
- **WHEN** the detail view is open
- **THEN** the scroll keys, the back key, and the open-in-editor / open-in-default-app keys are shown on screen

#### Scenario: Open the file from the detail view
- **WHEN** the user is in the detail view of a content match and presses the open-in-editor key
- **THEN** the editor opens that file at the matched line, exactly as if the action had been triggered from the result list

#### Scenario: Arrow keys scroll the file
- **WHEN** the user presses `Enter` on a file row and then `↓` several times
- **THEN** the detail view scrolls down line by line within the file

#### Scenario: Matches stay highlighted while scrolling
- **WHEN** the user scrolls the detail view so a different part of the file is visible
- **THEN** query matches in the newly visible text are still highlighted

#### Scenario: Content match positioned at the line
- **WHEN** the user opens the detail view for a content match at line 42
- **THEN** the view opens scrolled so line 42 is visible and marked

### Requirement: No-match indication
When the engine reports zero results for a non-empty query the system SHALL replace the result list with a centred message and SHALL show no preview, distinct from the empty-query tree view. While the initial walk is still running, the message SHALL state that scanning is still in progress and SHALL be visually distinct from the settled no-match message, so the user is not told a premature negative. When the walk has finished and the query still matches nothing, the message SHALL name the query and SHALL include a brief note that the query box uses fuzzy matching rather than regular expressions and points to the help overlay for the syntax; if a match mode that could plausibly have matched is currently off, the note SHALL mention the key that toggles it.

#### Scenario: No matches while still scanning
- **WHEN** the current non-empty query has no matches yet and the initial walk is still running
- **THEN** the results area shows a message stating that scanning is still in progress, visually distinct from the settled no-match message, and no rows and no preview

#### Scenario: Query with no matches
- **WHEN** the walk has finished and the current non-empty query matches nothing in scope
- **THEN** the results area shows a centred message naming the query, a note that matching is fuzzy rather than regex with a pointer to the help overlay, no rows, and no preview

#### Scenario: No-match note mentions a disabled mode
- **WHEN** content mode is off and a settled query matches no file or directory names
- **THEN** the no-match note mentions the key that toggles content mode

### Requirement: Help overlay
The system SHALL provide a keybinding that opens an overlay, dismissible with `Esc`, that serves as the complete reference for operating the interface. The overlay SHALL list every keybinding grouped by purpose (navigation, acting on a result, search scope, and miscellaneous) with each binding's action, and SHALL include a "Query syntax" section describing the query grammar: space-separated terms are combined with AND, `'text` is an exact substring match, `^text` is prefix-anchored, `text$` is suffix-anchored, `^text$` is a whole-string match, `!text` negates a term, and matching is smart-case (case-insensitive unless the term contains an uppercase letter).

#### Scenario: Open help
- **WHEN** the user presses the help key
- **THEN** an overlay lists the current keybindings grouped by purpose, each with its action

#### Scenario: Help documents the query syntax
- **WHEN** the help overlay is open
- **THEN** it contains a section describing AND terms, `'exact`, `^prefix`, `suffix$`, `!negate`, and smart-case

### Requirement: Quit
`Esc` (or the back key) SHALL resolve one level of state per press, in this order: close an open overlay, menu, or detail view; then, if the query box is non-empty, clear the query and return to the tree view; then pop one breadcrumb level; then quit the application. Quitting SHALL only occur when there is no overlay, detail view, or menu open, the query box is empty, and the breadcrumb is at the launch root. Quitting SHALL restore the terminal to its prior state and produce no result output unless an action requested it. The hint bar SHALL indicate which of these `Esc` will do next.

#### Scenario: Esc clears a non-empty query first
- **WHEN** the user has a non-empty query and presses `Esc` with nothing else open
- **THEN** the query box is cleared, the tree view returns, and the application does not exit

#### Scenario: Quit from the top level
- **WHEN** the user presses `Esc` at the top level with nothing else open, the query box empty, and the breadcrumb at the launch root
- **THEN** the application exits and the terminal is restored

#### Scenario: Esc pops a breadcrumb before quitting
- **WHEN** the user has re-rooted once, the query box is empty, and the user presses `Esc`
- **THEN** the search returns to the previous root and the application does not exit
