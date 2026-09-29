## ADDED Requirements

### Requirement: The viewer shares its session with the web interface
The terminal viewer SHALL keep its model, its runs and its marks in the session
it shares with the web interface. A scan or capture started from the browser
SHALL be listed in the viewer's Scans tab and supervised exactly like one started
in the terminal - including the quit guard, which SHALL ask before quitting while
a browser-started run is still going. A mark made in the browser SHALL be shown
on the viewer's rows and counted in its status bar, and the viewer's own tab,
filter, sort and cursor SHALL NOT be moved by anything done in the browser.

#### Scenario: A run started in the browser shows in the terminal
- **WHEN** the user starts a capture in the browser
- **THEN** the terminal viewer's status bar counts it as running and its Scans tab lists it

#### Scenario: Quitting while a browser-started scan runs
- **WHEN** the user quits the terminal viewer while a scan started in the browser is running
- **THEN** the viewer asks first, as it does for a scan it started itself

#### Scenario: A mark from the browser
- **WHEN** the user marks a host in the browser
- **THEN** the terminal viewer shows the host's row as marked and its mark count goes up by one

#### Scenario: The cursor stays put
- **WHEN** the user drills into a host in the browser
- **THEN** the terminal viewer's list, tab and selected row do not change

## MODIFIED Requirements

### Requirement: Fuzzy filtering
Each view SHALL provide a filter that narrows the listed rows as the user types,
using the same query grammar as the search session — space-separated terms
combined with AND, `'exact`, `^prefix`, `suffix$`, `!negate`, and smart-case —
matched against the row's fields and against what the row's screenshots say:
their page titles, URLs, technologies and HTTP status. Clearing the filter SHALL
restore the full list. The characters a row matched on SHALL be highlighted
where they appear in the list, so the user can see why a row survived the filter.

When some rows contain the filter's words as written, only those SHALL be
listed; rows that match only because the letters occur scattered SHALL be left
out, counted, and named as left out, and `~` in the filter SHALL list them too.
When no row contains the words, the fuzzy matches SHALL be listed as they are,
so a typo still finds something.

A complete address SHALL denote every address beginning with it, so that the
list narrows smoothly while it is typed (`10.10.10.1` lists `.1`, `.10`–`.19`
and `.100`–`.199`); `=10.10.10.1` or `10.10.10.1/32` SHALL denote that host
alone. A term with an explicit prefix (`10.10.10.32/26`) SHALL be an address
range. Addresses and ranges side by side SHALL be a union. An incomplete address
SHALL remain an ordinary fuzzy term. Address terms and fuzzy terms SHALL compose
in one expression, and an address term SHALL be negatable like any other. The
addresses actually being applied SHALL be visible.

A port SHALL be written as nmap and URLs write it: `:443`, `443/tcp`, `53/udp`
or `port:443` SHALL denote a port with that number whatever its state, and
`10.10.10.10:8080` SHALL denote that host with that port. `open:` and `closed:`
SHALL keep asking for the state as well.

#### Scenario: Typing narrows the list
- **WHEN** the user types `apache` in the service view's filter
- **THEN** only rows matching `apache` remain listed

#### Scenario: The query grammar is honoured
- **WHEN** the user filters with `'http !443`
- **THEN** rows are those containing the exact substring `http` and not matching `443`

#### Scenario: Clearing restores everything
- **WHEN** the user clears a non-empty filter
- **THEN** every row is listed again

#### Scenario: Matched characters are highlighted
- **WHEN** a filter is active and a row is listed because one of its fields matched
- **THEN** the matching characters are visually marked within that field

#### Scenario: Filtering by an address range
- **WHEN** the user filters with `10.10.10.32/26`
- **THEN** only rows whose addresses fall in `10.10.10.0`–`10.10.10.63` are listed

#### Scenario: A range and a fuzzy term together
- **WHEN** the user filters with `10.10.10.0/24 apache`
- **THEN** rows must both fall in that range and fuzzy-match `apache`

#### Scenario: A complete address is a beginning
- **WHEN** the user filters with `10.10.10.5`
- **THEN** `10.10.10.5` and `10.10.10.50` are listed, and `10.10.10.6` is not

#### Scenario: One host exactly
- **WHEN** the user filters with `=10.10.10.5`
- **THEN** only the host `10.10.10.5` is listed

#### Scenario: A partial address still matches many
- **WHEN** the user has typed `10.10.10.` and not yet completed the address
- **THEN** every host under `10.10.10.` is still listed

#### Scenario: The applied range is visible
- **WHEN** a range term is active
- **THEN** the interface shows the range being applied

#### Scenario: A port by number
- **WHEN** the user filters the host list with `:443`
- **THEN** every host with a port 443 recorded is listed, whether it is open, closed or filtered

#### Scenario: A host and a port
- **WHEN** the user filters with `10.10.10.10:8080`
- **THEN** only `10.10.10.10` is listed, and only if it has a port 8080

#### Scenario: Words before letters
- **WHEN** the user filters with `synology` and one host's screenshot title says Synology while two other rows only contain those letters scattered
- **THEN** only that host is listed, the interface says two looser matches were left out, and `synology ~` lists all three

#### Scenario: A screenshot finds its host
- **WHEN** a host's only mention of Hektor is the title of its captured web page and the user filters with `hektor`
- **THEN** the host is listed
