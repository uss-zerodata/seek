## Purpose

The browser front end of the nmap viewer at full parity with the terminal: every
overview, drill-down, record, raw output, search, mark, export and run the
terminal viewer offers, driven by the keyboard as well as the pointer.

## ADDED Requirements

### Requirement: Every overview is available
The web interface SHALL offer the same overviews as the terminal viewer - hosts,
services, statistics, grouping by service, by product and by port, names, and
scans - as tabs, with the same columns, the same default order for each, and the
same row counts for the same model and filter.

#### Scenario: The same statistics
- **WHEN** the user opens the statistics tab in the browser and in the terminal
- **THEN** both show the same sections, figures and order

#### Scenario: The same grouping
- **WHEN** the user opens grouping by product
- **THEN** each row shows the product, occurrences, hosts and ports as the terminal does

### Requirement: Drill-down and back behave as in the terminal
Opening a row SHALL go where it goes in the terminal viewer - a host to its
ports, a service to the hosts running it, a bucket to its members, a statistic to
what it counts - and the path SHALL chain without limit. Going back SHALL restore
the previous level's filter, sort and selected row, and the browser's own back
button SHALL do the same. The tab marked SHALL follow the level on screen as it
does in the terminal.

#### Scenario: Back restores the level
- **WHEN** the user filters the host list, opens a host, opens one of its services and goes back twice
- **THEN** the host list is shown with its filter, sort and the row it was left on

#### Scenario: The browser's back button
- **WHEN** the user drills into a host and presses the browser's back button
- **THEN** the host list is shown as it was left

### Requirement: Filtering, sorting and the list toggles match the terminal
Every list SHALL take the terminal viewer's filter grammar, including address
ranges, field terms and boolean operators, and SHALL show the same rows for the
same text. Every column SHALL be sortable, numbers and addresses as numbers. The
up-hosts and open-ports toggles SHALL narrow the host list, and a host's port
list, as they do in the terminal.

#### Scenario: A structured filter
- **WHEN** the user filters the host list with `open:443 AND NOT product:nginx`
- **THEN** the rows are the ones the terminal viewer lists for the same filter

### Requirement: A row's record is the terminal's record
Selecting a row SHALL show its full record - the same content the terminal
viewer's record pane and reader show, including scripts, vulnerabilities, names,
captures and the scans that saw it. The record SHALL be searchable in place, with
the number of matches and next / previous. A line that opens a scan's own text
SHALL be a link; that text SHALL be scoped to the record's host or port, SHALL
say which scan of how many it is, and SHALL step to the previous and next scan of
the same subject.

#### Scenario: The same record
- **WHEN** the user selects a host in the browser
- **THEN** the record lists the same ports, scripts, vulnerabilities, names and scans as the terminal's reader

#### Scenario: Following a scan's own text
- **WHEN** the user opens the scan link in a host's record
- **THEN** nmap's text for that host from that scan is shown, and the next scan's text is one step away

### Requirement: Marks and export
The user SHALL be able to mark and unmark rows - a multi-record row marks every
record in it - see how many are marked, list and clear them, and export. Export
SHALL offer the same recipes, fields and formats as the terminal viewer, from the
marks when there are any and otherwise from the rows the filter left, and SHALL
deliver the result as a downloaded file or text to copy.

#### Scenario: Exporting URLs of marked services
- **WHEN** the user marks two services and exports the HTTP/HTTPS URL recipe as text
- **THEN** the downloaded file holds the same URLs the terminal viewer would export

#### Scenario: A mark made elsewhere
- **WHEN** a host is marked in the terminal viewer
- **THEN** the same row shows as marked in the browser

### Requirement: The Scans tab
The Scans tab SHALL list every scan file in time order with what each added, and
every run started in the session, with its state and elapsed time. A running
run's output SHALL stream into the page as it is produced and follow the newest
line until the user scrolls away; the user SHALL be able to freeze the view
without pausing the run, cancel the run, and switch between the terminal's report
modes.

#### Scenario: Watching a scan
- **WHEN** a scan is running and the user opens it in the Scans tab
- **THEN** its output appears line by line as nmap writes it

#### Scenario: Cancelling from the browser
- **WHEN** the user cancels a running scan
- **THEN** the process ends, the run is recorded as cancelled with the output it produced, in both front ends

### Requirement: Scans and captures can be started from the browser
The user SHALL be able to start a scan exactly as in the terminal: choose a
preset, edit the scope and the command, and confirm a review that shows the
exact command, the targets, where output goes and whether it needs root. The same
command rules SHALL apply - no shell, nmap only, no user output flags - and a scan
that needs root SHALL run only through `sudo -n`, with the same explanation when
that is refused. The user SHALL be able to start a gowitness capture over the
marked or filtered URLs, with gowitness's absence explained as in the terminal.

#### Scenario: A preset scan from the browser
- **WHEN** the user chooses the top-1000 TCP preset for three marked hosts and confirms the review
- **THEN** the scan runs with the same argument vector the terminal would run, and its output is written where the terminal would write it

#### Scenario: A refused command
- **WHEN** the user edits the command to include `; rm -rf /`
- **THEN** the scan is not started and the reason is shown, naming the refused character

#### Scenario: Root without a cached sudo
- **WHEN** the chosen preset needs root and `sudo -n` is refused
- **THEN** the run ends with the same explanation the terminal gives, and no password is asked for

### Requirement: Updates arrive without reloading
While a page is open, run state, streamed output, a replaced model and changed
marks SHALL reach it as they happen. An open list SHALL keep the user's row,
filter and sort when the model it shows is replaced. When the server goes away,
the page SHALL say so rather than silently showing stale data.

#### Scenario: A scan finishes while a list is open
- **WHEN** the host list is open and a scan finishes adding two hosts
- **THEN** the list shows them without a reload and the selected row stays selected

#### Scenario: The viewer was closed
- **WHEN** the terminal viewer that serves the page quits
- **THEN** the page says the connection was lost

### Requirement: The keyboard does what it does in the terminal
The web interface SHALL be operable from the keyboard with the terminal viewer's
keys: `j`/`k` and the arrows move the list, `h`/`l` and the left and right arrows
move through the record, `Enter` drills, `Esc` backs out in the same stages, `/`
focuses the filter, digits sort by column, `v`/`V` switch tabs, `m`/`M` mark and
clear, `x` exports, `d` opens the record full-page and `?` lists the keys. Keys
SHALL NOT act while the user is typing into a field.

#### Scenario: Keyboard only
- **WHEN** the user presses `j`, `j`, `Enter`, `Esc` on the host list
- **THEN** the third host's ports are shown and then the host list again with the third host selected

#### Scenario: Typing is typing
- **WHEN** the filter box has focus and the user types `m`
- **THEN** an `m` is added to the filter and nothing is marked

### Requirement: State-changing requests come from the interface itself
Requests that change something - marking, starting or cancelling a run, freezing
- SHALL be accepted only when they come from the web interface's own origin. A
request carrying another origin SHALL be refused, so that a page on another site
open in the same browser cannot start a scan through it.

#### Scenario: Another site
- **WHEN** a request to start a scan arrives with an `Origin` of another site
- **THEN** it is refused and nothing is run

#### Scenario: The interface itself
- **WHEN** the web interface's own page starts a scan
- **THEN** the request is accepted
