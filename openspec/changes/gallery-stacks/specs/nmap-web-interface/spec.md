## MODIFIED Requirements

### Requirement: A gallery shows every screenshot
The interface SHALL provide a gallery of every capture from every database, each
shown as a thumbnail of its screenshot with its URL, response status and page
title, and linked to its full capture page and to the host and port it shows. A
capture that failed SHALL be shown as failed, with its reason, and no image. The
gallery SHALL be filterable across URL, title, host, port and database with the
viewer's own filter grammar, without reloading the page.

By default the gallery SHALL show one entry per host:port: when a port was
captured more than once (by its address, by each name it answers to, by
repeated runs), its captures SHALL be stacked behind the first in the
gallery's order, marked with how many there are, and the user SHALL be able to
expand the stack in place to see them all. A capture whose host is not in the
scans SHALL be stacked by the host and port of its URL. Showing every capture as
its own entry SHALL remain one choice away. A capture SHALL be placed on the
service its URL names, or - when nmap did not identify the port as a web
service - on the open port its host and port name.

The gallery SHALL be sortable, ascending or descending, by host address, host
name, port number, HTTP status, URL, page title, the time the capture was taken
and the database it came from; addresses and ports SHALL sort as numbers. A
capture without a value for the chosen order - a failure has no status - SHALL
be listed after every capture that has one, in either direction. The gallery
SHALL be able to show only the captures of one service on one host, of one port
across hosts, or of one host; wherever a service was captured more than once,
its entry SHALL offer to show all of that service's captures together. Sorting,
narrowing and paging SHALL keep one another: moving to the next page keeps the
order and the narrowing.

#### Scenario: Browsing screenshots
- **WHEN** the user opens the gallery
- **THEN** every capture is shown as a thumbnail with its URL, status and title

#### Scenario: A capture that failed
- **WHEN** a URL could not be captured
- **THEN** its entry says it failed and why, and shows no image

#### Scenario: Filtering the gallery
- **WHEN** the user types `'8443` (the exact form) into the gallery's filter
- **THEN** only captures whose URL, title, host, port or database contains `8443` remain

#### Scenario: Sorting by status
- **WHEN** the user sorts the gallery by HTTP status, descending
- **THEN** captures are ordered from the highest status down, and failed captures come last

#### Scenario: Sorting by address
- **WHEN** the user sorts by address
- **THEN** `10.0.0.9` comes before `10.0.0.10`

#### Scenario: One port captured several times
- **WHEN** port 80 of `192.0.2.1` was captured by address and by host name
- **THEN** the gallery shows one card for it, marked 2, and expanding it shows both captures

#### Scenario: Each capture on its own
- **WHEN** the user chooses to see every screenshot
- **THEN** every capture is its own entry, as before stacking

#### Scenario: Every capture of one service
- **WHEN** port 80 of `192.0.2.1` was captured by address and by host name, and the user follows the stack's offer to see them all
- **THEN** the gallery shows exactly those two captures, and says what it is narrowed to and how to see everything

#### Scenario: From a screenshot to its host
- **WHEN** the user follows a capture's host link
- **THEN** the host's page is shown
