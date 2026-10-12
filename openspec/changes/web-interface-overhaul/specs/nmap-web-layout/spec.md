## Purpose

How the nmap web interface is laid out and operated: the page shell, the visible
actions, list density, the key bar, where screenshots appear, and legibility in
both themes and on a narrow screen.

## ADDED Requirements

### Requirement: The page is a fixed shell with two scrolling panes
A viewer page SHALL fill the window with, from top to bottom, a top bar, the tab
strip, the list pane beside the record pane, and the key bar. The list pane and
the record pane SHALL each scroll on their own; the page itself SHALL NOT scroll
on a wide screen. The list's column headers, the list filter and the record's
title SHALL stay visible while their pane is scrolled.

#### Scenario: A long list is scrolled
- **WHEN** the host list holds more rows than fit and the user scrolls it to the end
- **THEN** the column headers, the filter box and the record pane are still on screen and the record pane has not moved

#### Scenario: A long record is scrolled
- **WHEN** the selected row's record is longer than its pane and the user scrolls it
- **THEN** the record's title stays visible and the list does not move

### Requirement: The tab strip never wraps
The tab strip SHALL stay on one line at every window width. Tabs that do not fit
SHALL be reachable by scrolling the strip, and the active tab SHALL be scrolled
into view when the page opens.

#### Scenario: A narrow window
- **WHEN** the window is too narrow for every tab
- **THEN** the tabs remain on one line, the top bar keeps its height and the active tab is visible

### Requirement: The top bar holds what is global
The top bar SHALL hold the application name, the search over everything, the
state of running scans and captures, the vulnerability database control and the
control that lists the keys. Nothing in it SHALL depend on the tab that is open.

#### Scenario: A run is in progress
- **WHEN** a scan is running and the user switches from Hosts to Services
- **THEN** the top bar shows the same run with its elapsed time on both tabs

### Requirement: Every list action is a visible control that names its key
Beside the list filter the interface SHALL show, as controls that can be clicked:
the list toggles that apply to the current view, mark, export and new scan. Each
control SHALL show the key that does the same thing, and clicking it SHALL have
exactly the effect of that key. A toggle SHALL show whether it is on. A control
whose action cannot run SHALL stay visible, disabled, with the reason shown
beside it rather than only in a tooltip.

#### Scenario: A toggle is clicked
- **WHEN** the user clicks "up" on the host list
- **THEN** the list shows up hosts only, the control reads as on, and the URL is the one the `u` key produces

#### Scenario: Export by mouse
- **WHEN** the user clicks Export with two rows marked
- **THEN** the export dialog opens for those two rows, as it does for `x`

#### Scenario: A toggle that does not apply
- **WHEN** the Services tab is open
- **THEN** the "up" toggle is not offered

#### Scenario: An action that cannot run
- **WHEN** nmap is not available and the user looks at the scan control
- **THEN** it is shown disabled and the reason is readable without hovering

### Requirement: The list states where it is and how many rows it shows
Above the list the interface SHALL show the drill path, the number of rows shown,
the total behind a filter when they differ, and the number of marked rows. The
last step of the path SHALL be the page's main heading. Under the filter it SHALL
state how the filter text was read.

#### Scenario: A filtered, partly marked list
- **WHEN** 9 of 254 hosts match the filter and 2 are marked
- **THEN** the list header reads 9 of 254 and 2 marked

### Requirement: Lists are dense and aligned
A list row SHALL be one line, 28 px high where it holds no taller content. Data
cells SHALL be set in a monospace face with digits of equal width, so addresses,
ports and versions align down a column. A cell too long for its column SHALL be
cut with an ellipsis and its whole value SHALL be available on hover and to
assistive technology.

#### Scenario: More rows per screen
- **WHEN** the host list is shown in a pane 560 px high
- **THEN** at least 18 rows are visible below the column headers

#### Scenario: A long value
- **WHEN** a product name is longer than its column
- **THEN** the row stays one line, the value ends in an ellipsis and the full value can be read from the cell

### Requirement: The selected row and the marked rows are unmistakable
The selected row SHALL be shown by a background tint and an accent edge on its
leading side, not by colour of text. A marked row SHALL carry a mark sign in its
own column, in the mark colour, with a text equivalent. Selection and mark SHALL
be distinguishable from each other and from a row under the pointer.

#### Scenario: A row is both selected and marked
- **WHEN** the selected row is also marked
- **THEN** it shows the selection tint, the accent edge and the mark sign together

### Requirement: Screenshots are shown in the data
A row whose subject has captures SHALL show their thumbnails in the list, each
linking to its capture page, with a count of the ones not shown. A capture that
failed SHALL be shown as failed, not as a missing image. The record SHALL show a
capture's picture directly under the last line about its URL. A row without
captures SHALL show nothing in that place.

#### Scenario: A host with four captures
- **WHEN** a host row has four captures and the row shows two thumbnails
- **THEN** the row shows two thumbnails and `+2`, and `+2` opens the gallery narrowed to that host

#### Scenario: A failed capture
- **WHEN** a row's only capture failed
- **THEN** the row shows a failure sign in the thumbnail's place, named as a failed capture of its URL

#### Scenario: The record of a service with a capture
- **WHEN** the selected service has a captured URL
- **THEN** the record shows the screenshot under that URL's line and clicking it opens the capture page

### Requirement: The record pane has a header with its actions
The record pane SHALL show the record's title and, as controls naming their keys,
the actions that apply to it: its views (see below), full width, and search
within the record. Before a row is selected the pane SHALL say how to select one.

#### Scenario: Full width by mouse
- **WHEN** the user clicks the full-width control
- **THEN** the record takes the whole width, the page heading stays visible, and clicking it again restores the two panes

### Requirement: A record's views are tabs, shown only when there is a choice
A record that can be read more than one way SHALL show its views as tabs in the
record header, with the one on screen marked: a run's three reports on the Scans
tab; elsewhere the record itself and nmap's own text about it. The text SHALL be
one tab however many scans have some; the other scans SHALL stay reachable from
the record's own lines and by stepping within the text. Clicking a tab SHALL
open that view. `o` SHALL step to the next view and
wrap around, unless the record's cursor is on a line that opens something, which
it then opens. Beside the tabs a control naming `o` SHALL do the same. When a
record has only one view, neither the tabs nor that control SHALL be shown.

#### Scenario: A host seen in two scans
- **WHEN** the selected host's record lists two scans with text
- **THEN** the header shows two tabs - the record and nmap's text - with the record marked

#### Scenario: Stepping with the key
- **WHEN** the user presses `o` twice on that record without moving the record cursor
- **THEN** the first scan's text and the record again are shown in turn, and the marked tab follows

#### Scenario: A scan chosen from the record
- **WHEN** the user clicks the second scan's line in the record
- **THEN** that scan's text is shown and the text tab is marked

#### Scenario: A record with nothing else to show
- **WHEN** the selected row's record has no scan text
- **THEN** no tabs and no next-view control are shown

#### Scenario: A run's reports
- **WHEN** a row of the Scans tab is selected
- **THEN** the tabs read overview, diff and raw output, and clicking one shows that report

### Requirement: A capture's page leads with its picture
A capture's page SHALL show the screenshot first and largest, with what was
recorded about the response beside it on a wide screen and below it on a narrow
one, grouped as response, technologies, TLS and source. The page SHALL use the
window's full width: on a screen wide enough for three columns the folded lists
SHALL sit beside the picture and the facts rather than under them. Its heading SHALL be the
URL with the response status, followed by the page title. Links to the capture's
host, its port, the other captures of that port and the target itself SHALL be
controls at the top of the page. Headers, cookies, console and network entries
SHALL each be a section with its count that can be folded; headers SHALL start
open. A capture without a picture SHALL say whether it failed, give the reason
and offer the target.

#### Scenario: A capture that belongs to a port
- **WHEN** the page of a capture of `https://192.0.2.30` is opened
- **THEN** the screenshot comes before the recorded facts, and the top of the page offers the host, port 443/tcp and the target

#### Scenario: A failed capture
- **WHEN** the capture failed
- **THEN** the picture's place says the capture failed, gives the reason and links to the target

#### Scenario: A very wide window
- **WHEN** the window is 2200 px wide
- **THEN** the picture, the facts and the lists are three columns that together fill the width

#### Scenario: Long lists
- **WHEN** the capture has headers and network entries
- **THEN** the headers are shown, the network entries are folded under a heading with their count, and opening it shows them

### Requirement: The new-scan dialog offers the screenshot capture
The dialog that starts a scan SHALL list the gowitness screenshot capture among
its presets. Choosing it SHALL replace the scope and command fields with what
would be captured - the number of HTTP(S) URLs of the marked rows, or of the
listed rows when nothing is marked, and the first of them - and SHALL start that
capture, the same one the export dialog starts. When gowitness is not available
the entry SHALL stay in the list, disabled, with the reason. When the selection
holds no HTTP or HTTPS service the dialog SHALL say so and the start control
SHALL be disabled.

#### Scenario: Capturing from the scan dialog
- **WHEN** the user opens the new-scan dialog on a list of hosts, chooses the gowitness entry and starts it
- **THEN** a capture of those hosts' HTTP(S) URLs starts and the Scans tab shows it

#### Scenario: gowitness is missing
- **WHEN** gowitness cannot be run
- **THEN** its entry is listed, cannot be chosen, and reads why

#### Scenario: Nothing to capture
- **WHEN** the listed rows have no HTTP or HTTPS service and the gowitness entry is chosen
- **THEN** the dialog says so and cannot be started

### Requirement: A key bar shows the keys for the current view
The bottom of a viewer page SHALL show the keys that apply to the current view,
in the terminal viewer's words, and the session's state: how many scans and
hosts are loaded and whether the connection to the session is alive. When the
bar is too narrow it SHALL keep the navigation keys and the key that lists every
key, and drop the rest.

#### Scenario: Keys follow the view
- **WHEN** the user moves from the host list to the Scans tab
- **THEN** the key bar no longer offers the host toggles and offers the keys of the Scans tab

#### Scenario: The session has gone
- **WHEN** the connection to the session is lost
- **THEN** the key bar says so in words, in the error colour, and keeps saying so until it returns

#### Scenario: A narrow bar
- **WHEN** the window is too narrow for every hint
- **THEN** the row keys, the record keys and `?` are still shown

### Requirement: One set of controls on every page
Buttons, toggles, text inputs, selects and dialogs SHALL look and behave the same
on the viewer, the gallery, the capture page and the search page. A choice among
alternatives SHALL be shown the same way wherever it occurs, including the
gallery's grouping. A view SHALL have at most one control styled as primary.

#### Scenario: The gallery's grouping
- **WHEN** the gallery is open
- **THEN** its grouping choices look and behave like the viewer's toggles and the current one reads as on

#### Scenario: A dialog
- **WHEN** any dialog is open
- **THEN** it has a title, exactly one primary action, a way to cancel, and states that Esc leaves

### Requirement: Colour means one thing
The interface SHALL use one accent colour, for position, focus and the primary
action only. Green, amber and red SHALL be used only for the condition of a
port, a response or a product; the mark colour only for marks. No fact SHALL be
conveyed by colour alone.

#### Scenario: Support status
- **WHEN** a product is past its end of life
- **THEN** the cell says so in words and is also red

### Requirement: Both themes are legible
The interface SHALL follow the system's light or dark setting. In both themes
body text, dimmed text, link text, status colours and every colour a record can
carry SHALL reach a contrast of at least 4.5:1 against the surface they are on,
and a control's text at least 4.5:1 against its fill.

#### Scenario: The primary button in the dark theme
- **WHEN** the system is set to dark
- **THEN** the primary button's label reaches 4.5:1 against its fill

#### Scenario: A terminal colour in a record
- **WHEN** a record holds text in each of the sixteen terminal colours, in either theme
- **THEN** each reaches 4.5:1 against the record's background

### Requirement: The interface is usable on a narrow screen
Below the width at which two panes fit, the record pane SHALL follow the list
pane in one column, the page SHALL scroll as a whole, and no content SHALL be
cut off or force the page to scroll sideways. A table wider than the screen SHALL
scroll sideways inside its own pane.

#### Scenario: A phone-width window
- **WHEN** the window is 400 px wide
- **THEN** the list is above the record, the toolbar wraps onto more lines, and the page does not scroll sideways

### Requirement: The mouse and the keyboard reach the same things
Every control SHALL be reachable with Tab, show a visible focus ring, and act on
Enter. The list's own keys SHALL NOT take Enter from a focused link or control.
Every action that has a key SHALL also have a visible control, and every visible
control in the viewer SHALL name its key.

#### Scenario: Enter on a focused control
- **WHEN** the Export control has focus and the user presses Enter
- **THEN** the export dialog opens and the selected row is not drilled into

#### Scenario: A key without a control
- **WHEN** the list of keys is compared with the controls on a viewer page
- **THEN** every action key is offered by a control or listed in the key overlay that `?` opens
