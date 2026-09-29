## Purpose

A browser interface over what the nmap viewer knows - hosts, ports, services and
the screenshots of every gowitness capture found - so screenshots from several
capture databases can be looked at together with the hosts and ports they show.

## ADDED Requirements

### Requirement: The interface serves the viewer's own model
The web interface SHALL show the same hosts, services and captures the viewer
that started it holds: the scans it was opened on and every capture database it
found, merged exactly as the viewer merges them. It SHALL NOT read scan files or
capture databases of its own. Each request SHALL be answered from the model as
it stands at that moment, so a scan or capture that finishes while the interface
is open SHALL appear on the next page load, without restarting anything.

Captures from different databases SHALL appear together, each saying which
database it came from.

#### Scenario: Screenshots from several databases together
- **WHEN** the viewer was opened on two directories that each contain a gowitness database
- **THEN** the interface lists the captures from both, each labelled with the database it came from

#### Scenario: A finished capture appears
- **WHEN** a capture finishes while the interface is open and the user reloads the gallery
- **THEN** the new screenshots are listed

#### Scenario: The same hosts as the viewer
- **WHEN** the viewer lists a host as up with three open ports
- **THEN** the interface lists the same host with the same three open ports

### Requirement: The interface listens on the local machine only
The interface SHALL bind to a loopback address and a port taken from the
configuration. When the configured address is not a loopback address, the system
SHALL refuse to start the interface and say why, rather than exposing the
engagement's data on the network. When the port is already in use, the system
SHALL say so and name the setting that changes it.

#### Scenario: Default binding
- **WHEN** the interface is started with the default configuration
- **THEN** it is reachable at the loopback address and configured port and not on any other interface

#### Scenario: A non-loopback address is refused
- **WHEN** the configuration sets the interface's address to `0.0.0.0`
- **THEN** the interface is not started and the user is told it binds to loopback only

#### Scenario: The port is taken
- **WHEN** another program already listens on the configured port
- **THEN** the user is told the port is in use and which setting changes it

### Requirement: The interface works without internet access
Every page SHALL be complete with what the interface itself serves: no script,
stylesheet, font or image SHALL be loaded from another host.

#### Scenario: An offline network
- **WHEN** the machine has no route to the internet and the user opens any page
- **THEN** the page renders fully, with its styling and its filtering working

### Requirement: Every page's data is available as a versioned API
Every list and record the pages show SHALL also be available as JSON under a
path carrying an API version, so another front end or tool can read the same
data. Hosts SHALL be addressed by their address, services by host, protocol and
port, and captures by an identifier that is stable for as long as the interface
runs. A request for something the model does not contain SHALL be answered with
a not-found status and a JSON body saying what was not found.

#### Scenario: Reading hosts as JSON
- **WHEN** a client requests the host list from the versioned API
- **THEN** it receives every host with its address, names, state and open ports as JSON

#### Scenario: One host
- **WHEN** a client requests a host by its address
- **THEN** it receives that host's ports, services and the captures of each

#### Scenario: Something that is not there
- **WHEN** a client requests a host address the model does not contain
- **THEN** the response has a not-found status and a JSON body naming the address

### Requirement: A gallery shows every screenshot
The interface SHALL provide a gallery of every capture from every database, each
shown as a thumbnail of its screenshot with its URL, response status and page
title, and linked to its full capture page and to the host and port it shows. A
capture that failed SHALL be shown as failed, with its reason, and no image. The
gallery SHALL be filterable across URL, title, host, port and database with the
viewer's own filter grammar, without reloading the page.

#### Scenario: Browsing screenshots
- **WHEN** the user opens the gallery
- **THEN** every capture is shown as a thumbnail with its URL, status and title

#### Scenario: A capture that failed
- **WHEN** a URL could not be captured
- **THEN** its entry says it failed and why, and shows no image

#### Scenario: Filtering the gallery
- **WHEN** the user types `'8443` (the exact form) into the gallery's filter
- **THEN** only captures whose URL, title, host, port or database contains `8443` remain

#### Scenario: From a screenshot to its host
- **WHEN** the user follows a capture's host link
- **THEN** the host's page is shown

### Requirement: Hosts are listed and each has a page
The interface SHALL list the hosts with their address, names, reachability and
open ports, filterable by text. Each host SHALL have a page listing its ports and
services - port, protocol, state, service, product and version - with the
screenshots captured for each port shown beside it, and the host's names and
vulnerabilities as the viewer records them.

#### Scenario: A host's page
- **WHEN** the user opens the page of a host with web servers on ports 80 and 8443
- **THEN** its ports are listed and the screenshots of ports 80 and 8443 are shown beside them

#### Scenario: A host with nothing captured
- **WHEN** the user opens the page of a host no capture covers
- **THEN** its ports and services are listed and the page says nothing was captured

### Requirement: Services are listed across hosts
The interface SHALL list services across all hosts - port, protocol, service,
product, version and how many hosts run it - ordered by port number, filterable
by text. Each service SHALL lead to the hosts running it, with each host's
screenshot of that service.

#### Scenario: One service everywhere
- **WHEN** the user opens `443/tcp https nginx` from the service list
- **THEN** every host running it is listed with that host's screenshot of port 443

#### Scenario: Port order
- **WHEN** the service list holds `8080/tcp`, `80/tcp` and `443/tcp`
- **THEN** they are listed as `80/tcp`, `443/tcp`, `8080/tcp`

### Requirement: A capture has a page of its own
Each capture SHALL have a page showing its screenshot at full size together with
everything the capture recorded: the URL asked for, the final URL when it was
redirected, status, title, the time it was taken, technologies, response
headers, cookies, console messages and the names from its TLS certificate, and
the database it came from. Nothing recorded SHALL be left out.

#### Scenario: Reading a capture
- **WHEN** the user opens a capture that was redirected and set cookies
- **THEN** its page shows the screenshot full size, the original and final URL, and its cookies

### Requirement: Only screenshots the model refers to are served
Screenshot files SHALL be served only for captures in the model, addressed by
the capture rather than by a file path. No request SHALL be able to read any
other file on the machine. A capture whose screenshot file is missing SHALL be
answered with a not-found status.

#### Scenario: A screenshot is served by its capture
- **WHEN** the gallery requests the image of a capture
- **THEN** the screenshot file that capture refers to is returned as an image

#### Scenario: A path is not a way in
- **WHEN** a client requests an image with a path such as `../../etc/passwd`
- **THEN** the request is answered with a not-found status and no file is read

#### Scenario: A screenshot that is gone
- **WHEN** a capture's screenshot file has been deleted from disk
- **THEN** its image request is answered with a not-found status and the page still renders

### Requirement: The interface only reads
The interface SHALL NOT change the model, write to disk, or start scans or
captures. It is a way of looking at what the viewer holds.

#### Scenario: No side effects
- **WHEN** the user browses every page of the interface
- **THEN** no file is created or modified and the viewer's model is unchanged
