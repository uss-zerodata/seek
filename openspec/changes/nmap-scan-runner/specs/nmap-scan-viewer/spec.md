## MODIFIED Requirements

### Requirement: Entry point
The system SHALL provide a `nmap` subcommand taking one or more file paths, or a
directory, and opening the viewer on them. The viewer is a purpose-built
interface for scan output and SHALL be reached this way; the file-search session
SHALL NOT carry nmap-specific actions or hints.

When the given paths hold no readable scan and scanning is available, the
subcommand SHALL open the viewer on an empty model with the scope editor rather
than exiting: a directory with nothing in it yet is the case for starting a
scan, not an error. When scanning is unavailable it SHALL explain what it
expects and exit as before. The output directory for any scan started in that
session SHALL be the directory given, or the working directory when individual
files were given.

#### Scenario: Opening files directly
- **WHEN** the user runs the `nmap` subcommand with two scan files
- **THEN** the viewer opens on the merged model of both

#### Scenario: The search session stays a file search
- **WHEN** the highlighted result in a search session is an nmap XML file
- **THEN** the search session offers no nmap-specific action for it

#### Scenario: No paths given
- **WHEN** the subcommand is run with no file paths
- **THEN** the system explains what it expects and exits without opening the viewer

#### Scenario: A directory with no scans, and nmap available
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is available
- **THEN** the viewer opens with the scope editor, and that directory is where a scan will write

#### Scenario: A directory with no scans, and no nmap
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is not available
- **THEN** the system reports that there is nothing to read and exits

### Requirement: Derived lists can be exported
The output of this viewer is frequently the input to another command, so the
system SHALL let the user export derived lists: at least the host addresses, the
distinct open ports as a comma-separated list, `host:port` pairs, and HTTP/HTTPS
URLs constructed from the detected services including non-standard ports. Export
SHALL offer the same destinations as the search session — standard output, the
clipboard, or a file — and, when scanning is available, scanning the selected
records as a further destination, which SHALL carry their addresses into the
scan flow as the scope.

An export SHALL act on the marked records when any exist, and on the current
(filtered) view when none do. Which of the two is being exported SHALL be stated
before the user commits to it, so that the source is never inferred.

The unit of an export SHALL be a record — a host, together with one of its
services where the row stood for a service — so that a service's own facts can
be exported rather than collapsed to the host's address. A derived list that
names hosts SHALL name each host once, however many of its services are
selected.

#### Scenario: Export a host list
- **WHEN** the user exports host addresses from a filtered host view
- **THEN** the addresses of the filtered hosts are produced, one per line

#### Scenario: Export a port list
- **WHEN** the user exports the port list
- **THEN** the distinct open ports of the current view are produced as a comma-separated list

#### Scenario: Export URLs
- **WHEN** the user exports URLs and a host offers HTTP on a non-standard port
- **THEN** a URL including that port is produced, with the scheme reflecting whether the service is TLS-wrapped

#### Scenario: Exports respect the filter
- **WHEN** a filter is active, nothing is marked, and the user exports any derived list
- **THEN** only the filtered rows contribute to it

#### Scenario: Marks win over the view
- **WHEN** records are marked and the user exports
- **THEN** the marked records are exported, whatever the current view is filtered to

#### Scenario: The source is stated
- **WHEN** the user starts an export
- **THEN** it says whether it will export the marked records or the rows on screen, and how many

#### Scenario: Scanning the selection
- **WHEN** the user chooses to scan the selected records and nmap is available
- **THEN** their addresses become the scope of a new scan, reviewed and confirmed like any other

#### Scenario: Scanning is offered only when it can be done
- **WHEN** nmap is unavailable
- **THEN** the export dialog does not offer scanning as a destination
