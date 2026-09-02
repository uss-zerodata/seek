## Purpose

Provides the persistent interactive terminal interface the user stays inside for an entire search session — the query box docked at the bottom, the streaming result list above it (best match nearest the query box), the empty-query tree view, keyboard and mouse navigation, live mode toggles, query history, multi-select, the preview pane above the list, and the full-screen detail view.

## ADDED Requirements

### Requirement: Screen layout
The system SHALL arrange the interface top to bottom as: the preview pane, then the result list (or the empty-query tree view), then a status bar, then the query input docked at the very bottom of the screen. The result list SHALL occupy the remaining vertical space and SHALL always be present and readable while a search is active. The status bar SHALL be a single visually distinct band that carries the active match modes and the result count together, separating the results above it from the input below it.

#### Scenario: Query box is at the bottom
- **WHEN** the interface is open
- **THEN** the query input is the bottom-most element and the result list is directly above the status bar

#### Scenario: Preview is above the list
- **WHEN** the preview pane is shown
- **THEN** it appears above the result list, not beside it

#### Scenario: Status bar groups modes and count
- **WHEN** results are shown
- **THEN** the active match modes and the `shown / total` count appear on the same status band, which is styled distinctly from the result list and the query input

### Requirement: Always-focused query input
The system SHALL keep keyboard text input directed at the query box at all times during a normal search session, so that typing printable characters always edits the query and never triggers an action. `←` and `→` SHALL move the cursor within the query text.

#### Scenario: Letters edit the query
- **WHEN** the result list is showing and the user presses a letter key
- **THEN** that character is inserted into the query at the cursor and no action is invoked

#### Scenario: Horizontal arrows move the query cursor
- **WHEN** the user presses `←` or `→`
- **THEN** the query text cursor moves one character and the result selection does not change

### Requirement: Streaming result list with typed rows
The system SHALL display the current results above the query box, updating as the walk streams in and as the query changes. Each row SHALL show a marker for its match type (filename, directory, or content), and SHALL visually highlight the characters that matched the query. Content rows SHALL show `path:line` and the matching line's text. The path portion of a row and the matched content SHALL be rendered in distinct colours.

#### Scenario: Scanning indicator during the walk
- **WHEN** the initial walk is still running
- **THEN** the interface shows an animated indication that scanning is in progress together with a running count of items found

#### Scenario: Match count shown
- **WHEN** results are displayed and the engine reports more total matches than are shown
- **THEN** the interface shows both the number displayed and the total (for example `500 / 3418`)

### Requirement: Result list is capped
The system SHALL display at most a configurable number of result rows (the highest-scoring), regardless of how many matched, so a broad query cannot stall the interface. The remaining count SHALL be visible (see the match-count scenario above).

#### Scenario: Broad query stays responsive
- **WHEN** a query matches far more candidates than the cap
- **THEN** the list shows at most the capped number of rows and the interface stays responsive to typing and navigation

#### Scenario: Match type is visible
- **WHEN** the list contains a mix of filename, directory, and content matches
- **THEN** each row visibly indicates which kind of match it is

#### Scenario: Matched characters highlighted
- **WHEN** a row is present because its name or content matched the query
- **THEN** the specific matched characters are rendered distinctly from the rest of the label

#### Scenario: Path and content are coloured differently
- **WHEN** a content row shows a path prefix followed by the matched source line
- **THEN** the path prefix and the source-line text are drawn in different colours

### Requirement: Rows do not wrap by default
By default the system SHALL render each result on a single line, shortening rows that are too wide to fit rather than wrapping them. When a row is shortened the system SHALL keep the matched characters visible, windowing a long content line around its match and eliding the hidden portion with an ellipsis. A configuration setting SHALL switch to wrapping long rows instead.

#### Scenario: Long content line is shortened, match still visible
- **WHEN** a content match occurs on a line far wider than the list
- **THEN** the row occupies a single screen line and the matched text is within the visible portion, with elision markers where text was removed

#### Scenario: Wrapping enabled by config
- **WHEN** the wrap-results setting is enabled and a row is wider than the list
- **THEN** that row wraps onto multiple screen lines instead of being shortened

### Requirement: Empty-query tree view
When the query is empty the system SHALL replace the result list with a non-interactive tree view of the current search root (respecting the active scope and exclusions). The tree SHALL be coloured: directory names, the branch glyphs, and file names (by type) SHALL each be rendered in distinct styles. Entering any query text SHALL switch to the ranked result list; clearing the query again SHALL return to the tree view.

#### Scenario: Tree shown at empty query
- **WHEN** the query box is empty
- **THEN** the results area shows a coloured tree of the current root and does not accept row selection or marking

#### Scenario: Typing leaves the tree view
- **WHEN** the user types a character into an empty query box
- **THEN** the results area switches to the ranked result list

### Requirement: Result ordering — best match nearest the query
The system SHALL order the result list so that the best-scoring match is at the bottom, immediately above the query box, and weaker matches are further up. When the query text changes the highlighted row SHALL start on the best match at the bottom. When the result set is updated for the *same* query — because the walk found more candidates or content matches streamed in — the system SHALL keep the highlighted row on the same result (by identity) rather than snapping the cursor back to the best match, so navigation is not disrupted mid-scan.

#### Scenario: Best match at the bottom
- **WHEN** a query produces several ranked results
- **THEN** the highest-scoring result is the bottom row of the list and the lowest-scoring is the top row

#### Scenario: Cursor starts on the best match for a new query
- **WHEN** the user changes the query text and results are computed
- **THEN** the highlighted row is the bottom (best) row

#### Scenario: Cursor held during a mid-scan update
- **WHEN** the user has moved the cursor off the best match and more results arrive for the unchanged query
- **THEN** the cursor stays on the result the user had highlighted (if it is still present)

### Requirement: Keyboard navigation of the result list
The system SHALL move the highlighted row with `↑` and `↓` (matching visual direction), and SHALL page the list with `PageUp` and `PageDown`. The currently highlighted row SHALL be visually distinguished from the other rows. Changing the highlighted row SHALL update the preview.

#### Scenario: Arrow navigation
- **WHEN** the user presses `↑`
- **THEN** the highlighted row moves one row up the screen and the preview updates to that row's target

#### Scenario: Highlighted row is visible
- **WHEN** the result list has focus of the cursor on some row
- **THEN** that row is rendered distinctly (for example reverse video) from every other row

#### Scenario: Paging
- **WHEN** the user presses `PageUp`
- **THEN** the highlighted row moves up by roughly one visible page

### Requirement: Live match-mode toggles
The system SHALL let the user toggle each match mode (filename, directory, content) on or off during the session via a keybinding and via the action menu, and SHALL recompute results for the current query when a mode is toggled. The active modes SHALL be visible in the interface.

#### Scenario: Toggling content mode on
- **WHEN** content mode is off and the user presses the content-toggle key with a non-empty query
- **THEN** content results appear in the list and the interface shows content mode as active

#### Scenario: Toggling a mode off
- **WHEN** directory mode is on and the user toggles it off
- **THEN** directory rows are removed from the list and no new ones appear until it is toggled back on

### Requirement: Query history recall
The system SHALL persist submitted queries across sessions and SHALL let the user step backward and forward through prior queries with `Alt+↑` and `Alt+↓`, replacing the query box contents with the recalled query.

#### Scenario: Recall a previous query
- **WHEN** the user presses `Alt+↑`
- **THEN** the query box is replaced with the most recent prior query and the results update for it

#### Scenario: History survives restart
- **WHEN** the user runs `seek` again in a later session and presses `Alt+↑`
- **THEN** a query from the earlier session is offered

### Requirement: Multi-select
The system SHALL let the user toggle selection of the highlighted row with `Tab` without leaving the list, and SHALL clear all selections with `Shift+Tab`. A selected item SHALL remain selected as long as it is still present in the filtered results, identified by its path (and line, for content matches).

#### Scenario: Toggle selection
- **WHEN** the user presses `Tab` on a highlighted row
- **THEN** that row's selected state flips and the selection is visibly marked

#### Scenario: Selection survives requery
- **WHEN** the user has selected a row and then edits the query such that the row still matches
- **THEN** the row remains marked as selected

#### Scenario: Clear all selections
- **WHEN** the user presses `Shift+Tab` with several rows selected
- **THEN** all rows become unselected

### Requirement: Preview pane above the list
The system SHALL show a preview pane above the result list for the highlighted row: for a file, a header line naming the file (and `:line` for a content match) plus a fixed window of its contents centered on the matched line (or from the top for a name match) with syntax highlighting and the matched line marked; for a directory, a depth-limited tree. Within the previewed text, every place the current query matches SHALL be highlighted on top of the syntax highlighting. The preview SHALL NOT be independently scrollable and SHALL update whenever the highlighted row changes. Reading the file and highlighting it SHALL NOT block the interface — navigating the list stays responsive even over large files or slow storage.

The result list takes priority over the preview: when the terminal is too short to show both comfortably (or there is nothing to preview), the system SHALL drop the preview pane so the result list stays visible and readable, and SHALL restore it when space allows.

#### Scenario: Preview names the file
- **WHEN** the preview shows a content match at line 88 of `src/app.py`
- **THEN** a header identifies `src/app.py:88` even if the matching row's path was shortened in the list

#### Scenario: Fast navigation over large files
- **WHEN** the user holds the down arrow to move through results that include multi-megabyte files
- **THEN** the cursor keeps moving and typing stays responsive; the preview catches up shortly after

#### Scenario: File glance centered on the match
- **WHEN** the highlighted row is a content match at line 200
- **THEN** the preview shows a window of the file with line 200 centred in the visible pane (as far as the file length allows) and that line marked

#### Scenario: Query match highlighted in the preview
- **WHEN** the previewed window contains text matching the current query
- **THEN** the matching characters are visually highlighted within the preview

#### Scenario: Directory glance
- **WHEN** the highlighted row is a directory
- **THEN** the preview shows that directory's depth-limited tree

#### Scenario: Preview dropped on a short terminal
- **WHEN** the terminal height is too small to show the preview and a usable result list at once
- **THEN** the preview pane is hidden and the result list occupies the freed space

#### Scenario: Preview truncated past the size cap
- **WHEN** the highlighted row targets a file larger than the configured size cap (default 5 MB)
- **THEN** the preview shows a bounded portion and indicates that the content is truncated, rather than hanging or failing

### Requirement: Full-screen detail view
Pressing `Enter` on a row SHALL open a full-screen detail view of its target. For a file the detail view SHALL show the whole file (up to the size cap, then truncated with an indicator), syntax-highlighted, with every query match highlighted, opened scrolled to and marking the matched line for a content match. For a directory it SHALL show a scrollable tree. The view SHALL scroll like a pager — at least `↑`/`↓` line scrolling, `PageUp`/`PageDown`, half-page, and jump-to-top / jump-to-bottom — and query matches SHALL stay highlighted while scrolling. `Esc` (or the back key) SHALL return to the result list.

#### Scenario: Arrow keys scroll the file
- **WHEN** the user presses `Enter` on a file row and then `↓` several times
- **THEN** the detail view scrolls down line by line within the file

#### Scenario: Matches stay highlighted while scrolling
- **WHEN** the user scrolls the detail view so a different part of the file is visible
- **THEN** query matches in the newly visible text are still highlighted

#### Scenario: Content match positioned at the line
- **WHEN** the user opens the detail view for a content match at line 42
- **THEN** the view opens scrolled so line 42 is visible and marked

### Requirement: Session state preserved across the detail view
Returning from the detail view to the result list SHALL restore the query text, the list scroll position, the highlighted row, and the current selection exactly as they were before `Enter` was pressed.

#### Scenario: Round trip preserves state
- **WHEN** the user opens the detail view for a row and then returns to the list
- **THEN** the query, scroll position, highlighted row, and selection are unchanged

### Requirement: Re-root the search from the detail view
From the detail view of a directory the system SHALL let the user re-root the search at that directory via a keybinding. Re-rooting SHALL push the previous root onto a breadcrumb stack, keep the current query, and recompute results against the new root. A keybinding SHALL pop one level off the stack, back toward the original launch root, which SHALL be the bottom of the stack.

#### Scenario: Re-root into a directory
- **WHEN** the user re-roots at `src/` from its detail view
- **THEN** subsequent results and the tree view are scoped to `src/` and the breadcrumb shows the path from the launch root

#### Scenario: Pop back up a level
- **WHEN** the user has re-rooted twice and presses the pop key
- **THEN** the search returns to the previous root and the breadcrumb loses its last segment

#### Scenario: Cannot pop past the launch root
- **WHEN** the breadcrumb stack is at the original launch root and the user presses the pop key
- **THEN** the root does not change

### Requirement: Manual refresh
The system SHALL provide a keybinding that re-walks the current root from scratch and re-runs the current query, so filesystem changes made during the session are picked up.

#### Scenario: Refresh picks up a new file
- **WHEN** a new file matching the current query is created after the walk finished and the user presses the refresh key
- **THEN** the new file appears in the results

### Requirement: No-match indication
When the engine reports zero results for a non-empty query the system SHALL replace the result list with a centred "no matches" message (naming the query) and SHALL show no preview, distinct from the empty-query tree view.

#### Scenario: Query with no matches
- **WHEN** the current non-empty query matches nothing in scope
- **THEN** the results area shows a centred "no matches" message, no rows, and no preview

### Requirement: Terminal-native presentation with mouse support
The interface SHALL render using the terminal's own color palette and SHALL be fully operable from the keyboard. It SHALL use colour to distinguish regions and information — at least: the result markers by match type, the matched characters, the path vs. the matched content in a row, the highlighted row, the tree view elements, and the status band. The mouse SHALL additionally be usable to scroll the result list and the detail view and to select (highlight) a row by clicking it. Colours SHALL be overridable via configuration where they style rendered text (rows, tree, preview).

#### Scenario: Click to highlight a row
- **WHEN** the user clicks a row in the result list
- **THEN** that row becomes the highlighted row and the preview updates

#### Scenario: Wheel scrolls the detail view
- **WHEN** the detail view is open and the user scrolls the mouse wheel over it
- **THEN** the detail view scrolls

### Requirement: Help overlay
The system SHALL provide a keybinding that opens an overlay listing every keybinding and its action, dismissible with `Esc`.

#### Scenario: Open help
- **WHEN** the user presses the help key
- **THEN** an overlay lists the current keybindings and their actions

### Requirement: Quit
`Esc` (or the back key) SHALL quit the application when pressed at the top level of the result list or tree view with no overlay, detail view, or menu open, and no breadcrumb level to pop. Quitting SHALL restore the terminal to its prior state and produce no result output unless an action requested it.

#### Scenario: Quit from the top level
- **WHEN** the user presses `Esc` at the top level with nothing else open and the breadcrumb at the launch root
- **THEN** the application exits and the terminal is restored
