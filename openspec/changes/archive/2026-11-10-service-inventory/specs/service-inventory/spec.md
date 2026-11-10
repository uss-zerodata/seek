## Purpose

A software inventory of every open service: which products and versions run on
which host and port, from every source the viewer already reads, with the
evidence behind each entry. It exists so that vulnerabilities can later be
looked up automatically.

## ADDED Requirements

### Requirement: Every open service has a list of software components
The system SHALL give every open service a list of software components. A
component SHALL have a product name, an optional version, an optional CPE
identifier, a kind (application, operating system or hardware), a confidence,
and the observations it was built from. A service MAY have several components,
because one port often serves a whole stack (a reverse proxy, a web server, a
language runtime, an application, client libraries). Components that describe
the host rather than one port (the operating system, the hardware) SHALL belong
to the host. The inventory SHALL be built only from data already read (scan
files and capture databases). Building it SHALL NOT contact any host or
service.

#### Scenario: A web port lists its stack
- **WHEN** nmap identifies port 80 as `nginx 1.16.1` and a capture of that port detects `PHP:7.4.33` and `jQuery:2.1.3`
- **THEN** the service has three components: nginx 1.16.1, PHP 7.4.33 and jQuery 2.1.3

#### Scenario: The operating system belongs to the host
- **WHEN** a scan with OS detection reports an OS match for a host
- **THEN** the host has an operating-system component, and no service lists it

#### Scenario: A closed port has no components
- **WHEN** a port is closed or filtered
- **THEN** it contributes nothing to the inventory

#### Scenario: Nothing is sent over the network
- **WHEN** the inventory is built
- **THEN** no connection is made to any scanned host or to any external service

### Requirement: nmap's identification and CPEs are read
The system SHALL read the CPE identifiers nmap records for a service and for
each OS match, in addition to the product, version, extra information,
detection method and confidence it already reads. A service identified by a
real version probe SHALL give a component with the product, version and CPEs
reported. A service named only from nmap's port table SHALL NOT give a product
component; its name stays the service name, as today. When scans are merged,
the CPEs of a service SHALL travel with the identification that wins, as
`method` and `conf` do.

#### Scenario: A probed service with a CPE
- **WHEN** nmap reports `product="Samba smbd" version="4.6.2"` with `<cpe>cpe:/a:samba:samba:4.6.2</cpe>`
- **THEN** the service has a Samba component at version 4.6.2 with that CPE

#### Scenario: A CPE without a version
- **WHEN** nmap reports `nginx` with no version and `cpe:/a:igor_sysoev:nginx`
- **THEN** the component carries that CPE and is marked unversioned

#### Scenario: A port-table guess is not a product
- **WHEN** a scan without version detection names port 3128 `squid-http`
- **THEN** no Squid component is created from that name alone

#### Scenario: OS matches carry their CPEs
- **WHEN** the best OS match is `Linux 4.15 - 5.8` with CPEs for kernel versions 4 and 5
- **THEN** the host's operating-system component names that match and carries both CPEs, with no single version asserted

### Requirement: Software named in script output is recognised
The system SHALL recognise software named by NSE scripts and SHALL add it as
components of the service or host the script ran against. It SHALL recognise at
least these: `http-server-header`; the `Server`, `X-Powered-By` and
`X-AspNet-Version` lines in `fingerprint-strings` responses; SSH, FTP and SMTP
greeting banners in `fingerprint-strings` and `banner`; `http-generator`;
`smb-os-discovery` (operating system and Samba/LAN manager); and the CPE keys of
`vulners` results. A recogniser SHALL read only text that states the software
of *this* service. A product named in an advisory link, a page body or another
service's quoted output SHALL NOT become a component.

#### Scenario: A server header script
- **WHEN** `http-server-header` reports `pve-api-daemon/3.0`
- **THEN** the service has a pve-api-daemon component at version 3.0, sourced to that script

#### Scenario: A banner from an unrecognised service
- **WHEN** nmap could not identify a service but `fingerprint-strings` shows `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`
- **THEN** the service has an OpenSSH component at version 8.9p1

#### Scenario: A header several products share
- **WHEN** `http-server-header` reports `Python/3.8 websockets/8.1`
- **THEN** the service has two components, Python 3.8 and websockets 8.1

#### Scenario: Advisory text is not software
- **WHEN** an `http-vuln-*` script's output links to a vendor advisory naming a product
- **THEN** that product does not become a component

### Requirement: Capture data is joined to its service
The system SHALL join each capture to the service whose URL it captured, by the
same rule a record uses to list a service's URLs (the address and every name
the host answers to). The system SHALL add as components: the capture's
technology detections, split into name and version when detected as
`Name:version`; the `Server`, `X-Powered-By`, `X-AspNet-Version` and
`X-Generator` response headers; and the `<meta name="generator">` of the
captured page. Header names SHALL be matched case-insensitively. A capture that
failed SHALL contribute nothing. When a capture's URL is not one the record
lists for any service (nmap did not identify the port as a web service, so no
URL is built for it), the capture SHALL be placed by its host and port: the
host it names, by address or by any name the host is known by, and that host's
open TCP port. A capture that still belongs to no service SHALL NOT be dropped
silently: the Inventory tab SHALL say how many captures could not be placed and
name them.

#### Scenario: A versioned technology detection
- **WHEN** a capture of a service detects `Nginx:1.16.1`
- **THEN** that service has an nginx component at version 1.16.1, sourced to the capture

#### Scenario: A header names the runtime
- **WHEN** a capture's response carries `X-Powered-By: PHP/7.4.33`
- **THEN** that service has a PHP component at version 7.4.33

#### Scenario: A capture by host name
- **WHEN** a capture was taken of `https://portal.example.test/` and that name belongs to a host's 443/tcp service
- **THEN** its components are added to that service

#### Scenario: A web page on a port nmap did not call http
- **WHEN** nmap reports port 8000 as `tcpwrapped` and a capture of `http://10.0.0.5:8000/app/` detects `jQuery:3.4.1`
- **THEN** that service has a jQuery component at version 3.4.1

#### Scenario: An unplaced capture is counted and named
- **WHEN** a capture's URL matches no open port of any host in the model
- **THEN** the Inventory tab says that one capture could not be placed, and names its URL

### Requirement: Observations of one product are reconciled, never discarded
Observations that name the same product on the same service or host SHALL
become one component. Product names SHALL be compared after normalisation, so
that `Nginx`, `nginx` and nmap's `nginx` (CPE `igor_sysoev:nginx`) are one
product. The version shown SHALL be the one from the most trusted source that
gave any version, in this order: an nmap version probe, a script banner or
header, a captured response header, a technology detection. Every observation
SHALL remain part of the component with its source. When two sources give
different versions of the same product, the component SHALL be marked
conflicting and SHALL list each version with its source. Versions that come
only from captures' technology detection and headers SHALL instead be separate
components, one per version: the pages a port serves (the address, each virtual
host) may each load their own copy of a library. A version that only
refines another (`8.9` and `8.9p1`, `1.16` and `1.16.1`) SHALL NOT be a
conflict, and the more specific one SHALL be shown.

#### Scenario: Two sources agree
- **WHEN** nmap and a capture both identify nginx 1.16.1 on one service
- **THEN** there is one nginx component at 1.16.1 with both sources listed, and it is not conflicting

#### Scenario: A version fills in a gap
- **WHEN** nmap reports nginx with no version and a capture's `Server` header says `nginx/1.16.1`
- **THEN** the component shows version 1.16.1, sourced to the header, and nmap's observation is still listed

#### Scenario: Two sources disagree
- **WHEN** nmap's probe reports OpenSSH 8.2p1 and a banner on the same service reports OpenSSH 8.9p1
- **THEN** the component shows 8.2p1, is marked conflicting, and lists both versions with their sources

#### Scenario: A refinement is not a conflict
- **WHEN** one source reports PHP 7.4 and another PHP 7.4.33
- **THEN** the component shows 7.4.33 and is not conflicting

#### Scenario: Two versions of a library on one port
- **WHEN** a capture of a port's address detects jQuery 2.1.3 and a capture of one of its virtual hosts detects jQuery 3.4.1
- **THEN** the service has two jQuery components, 2.1.3 and 3.4.1, and neither is conflicting, because pages on one port may each load their own copy

#### Scenario: Different products on one port stay apart
- **WHEN** nmap reports Traefik on 443/tcp and a capture's `Server` header says nginx
- **THEN** the service has two components, Traefik and nginx, and neither is conflicting

### Requirement: CPEs are given only when they are known
A component SHALL carry the CPEs its nmap observations reported. For a product
nmap did not give a CPE for, the system SHALL derive one only from a curated
alias table that maps a normalised product name to a CPE vendor and product,
and SHALL fill in the component's version. A product not in the table SHALL
have no CPE and SHALL be visibly marked as such. A CPE SHALL NOT be derived by
guessing the vendor from the product name. Each CPE SHALL be available both in
the CPE 2.2 URI form nmap writes and in the CPE 2.3 formatted-string form.

#### Scenario: A mapped name
- **WHEN** a capture detects `PHP:7.4.33` and the alias table maps PHP to `php:php`
- **THEN** the component carries `cpe:/a:php:php:7.4.33` and `cpe:2.3:a:php:php:7.4.33:*:*:*:*:*:*:*`

#### Scenario: An unmapped name
- **WHEN** a capture detects `Synology DiskStation` and the alias table has no entry for it
- **THEN** the component has no CPE and is shown as having none

#### Scenario: nmap's CPE is kept
- **WHEN** nmap reports a CPE whose vendor differs from the alias table's entry for the same product
- **THEN** the component carries nmap's CPE, and the alias table is not consulted for that component

### Requirement: The inventory is an overview
The viewer SHALL offer the inventory as an overview, listed with the other
tabs. It SHALL list one row per distinct product and version, with its kind,
CPE, how many hosts and services run it, its best confidence, and whether any
of its components is conflicting. Unversioned products SHALL be listed as their
own rows, not hidden. Opening a row SHALL show the services (for host-level
components, the hosts) running that product and version, and from there the
records, as other drill-downs do. The overview SHALL be filterable, sortable,
markable and exportable like every other overview. Filtering SHALL also match
a component's sources, so that a filter such as `gowitness` or
`http-server-header` finds what a source contributed.

#### Scenario: The inventory tab
- **WHEN** the viewer is open over scans with identified services
- **THEN** an Inventory tab lists each product and version with its host and service counts

#### Scenario: Drilling into a version
- **WHEN** the user opens the `nginx 1.16.1` row
- **THEN** the services running nginx 1.16.1 are listed, each opening its record

#### Scenario: The gaps are visible
- **WHEN** some nginx components have no version
- **THEN** `nginx` is listed as its own unversioned row, next to the versioned nginx rows

#### Scenario: Conflicts can be found
- **WHEN** the user sorts or filters by the conflict column
- **THEN** the products with a conflicting component can be brought together

### Requirement: Records show their software
A service's record SHALL include a Software block that lists its components:
each component's product, version, CPE (or that it has none) and, dimmed below
it, every observation with its source and the version that source gave. A host's
record SHALL list the host-level components and a summary of its services'
components. A conflicting component SHALL be marked in the block. The
full-screen reader and the web record SHALL show the same block, built by the
same function.

#### Scenario: A service record lists its stack
- **WHEN** the user selects a service whose port runs nginx and PHP
- **THEN** the record pane lists both components with their versions, CPEs and sources

#### Scenario: A conflict in a record
- **WHEN** a service's OpenSSH component is conflicting
- **THEN** the Software block marks it and shows each version with the source that reported it

### Requirement: The inventory can be exported in a stable, versioned shape
The export dialog SHALL offer the inventory as a recipe, acting on the marked
records or on the current view like every other export. It SHALL produce one
entry per component per service (or per host, for host-level components), with
at least: address, host names, port, protocol, service name, product, version,
kind, CPE (both forms), confidence, whether it is conflicting, and each
observation's source and version. It SHALL be available as CSV and JSON. The
JSON document SHALL carry a schema version. A change to the meaning or the name
of an existing field SHALL increase it, and adding a field SHALL NOT. The same
document SHALL be available from the web interface's versioned API.

#### Scenario: Export the inventory as JSON
- **WHEN** the user exports the inventory of the current view as JSON
- **THEN** the document states its schema version and lists every component of the listed services, each with its address, port and observations

#### Scenario: Export marked services
- **WHEN** three services are marked and the user exports the inventory
- **THEN** only those services' components are exported, and the dialog says so

#### Scenario: The API serves the same document
- **WHEN** a client requests the inventory from the web interface's API
- **THEN** it receives the same document the JSON export produces for the whole model

### Requirement: The inventory is the same in every front end
The terminal viewer and the web interface SHALL show the same inventory rows
for the same model and filter. The web interface SHALL offer the Inventory
overview, its drill-down, the Software block and the export, with the same key
bindings as the terminal where the terminal has one.

#### Scenario: Browser and terminal agree
- **WHEN** the same filter is applied to the Inventory tab in the terminal and in the browser
- **THEN** both list the same products and versions

### Requirement: Unversioned services can be scanned for versions
The viewer SHALL offer an action that drafts a version-detection scan of
exactly the open ports that have no versioned component. The draft SHALL be
based on the marked records when any exist, and on the current view when none
do. Because one nmap command applies one port list to every target, the draft
SHALL be a single scan: its targets are the hosts with at least one unversioned
open port, and its ports are the union of those ports. It SHALL use nmap's most
thorough version detection. The review SHALL state how many host and port pairs
the union adds beyond the unversioned ones, so the cost is visible before the
scan runs. The draft SHALL go through the
same scope, editable command and review as any other scan, and SHALL NOT run
without confirmation. When every port in scope already has a versioned
component, the action SHALL say so and draft nothing. When nmap is unavailable,
the action SHALL be shown as unavailable, with the reason.

#### Scenario: Scan only what is missing
- **WHEN** host A has 22/tcp versioned and 8080/tcp unversioned, host B has 443/tcp unversioned, and the user invokes the action
- **THEN** one scan is drafted against A and B on ports 443 and 8080 with version detection at full intensity, host A's 22/tcp is not in it, the review says the union adds two pairs, and it waits for confirmation

#### Scenario: Nothing to do
- **WHEN** every open port in scope has a versioned component
- **THEN** the viewer says that nothing is unversioned and no scan is drafted

#### Scenario: The result joins the inventory
- **WHEN** the drafted scan finishes
- **THEN** it is read like any other scan and the inventory shows the versions it found

### Requirement: Building the inventory does not block the viewer
The inventory SHALL be built off the event loop, and SHALL be rebuilt only when
the model or the captures change. While it builds, it SHALL report progress the
way other long steps do. The rest of the viewer SHALL stay usable meanwhile.

#### Scenario: A large engagement
- **WHEN** the viewer is open over an engagement of tens of thousands of hosts and the user opens the Inventory tab
- **THEN** the tab reports its progress while it builds, and switching to another tab stays responsive
