## Purpose

Screenshotting and fingerprinting the web servers a scan found: running
gowitness over a supplied list of URLs, supervising and cancelling that run,
writing its output where an externally run capture would write it, and reading
the results back so they can be shown against the hosts and services they
belong to.

## ADDED Requirements

### Requirement: gowitness is detected and its absence is visible

The system SHALL determine at start up whether a capture can be run, by looking
for a usable container runtime carrying the gowitness image and for a gowitness
binary on `PATH`. Detection SHALL prefer the container backend and fall back to
the native binary, and the configuration SHALL be able to change that order or
pin a single backend.

Detection SHALL NOT block the viewer from starting, and SHALL NOT run a
capture. When neither backend is available the capture feature SHALL be
disabled rather than failing at the moment it is invoked, and the interface
SHALL show that it is unavailable. When a backend is available the interface
SHALL show which one is in use, so that a capture running in a container is
never mistaken for one running natively.

#### Scenario: Neither backend available

- **WHEN** the viewer starts with no container runtime and no gowitness binary
- **THEN** the capture feature is shown as unavailable and invoking it explains what is missing instead of reporting a failed run

#### Scenario: Both backends available

- **WHEN** both a usable container runtime and a gowitness binary are present
- **THEN** the container backend is used, and the interface shows which backend that is

#### Scenario: Only the native binary available

- **WHEN** no container runtime is usable but gowitness is on `PATH`
- **THEN** the capture feature is enabled and reports that it will run natively

#### Scenario: The configured backend is unavailable

- **WHEN** the configuration pins a backend that is not present
- **THEN** the feature is disabled and says which backend was pinned, rather than silently using the other one

### Requirement: A capture runs over a supplied list of URLs

The system SHALL run a capture over a list of URLs derived from what the viewer
is currently showing, honouring the same selection rules the export recipes
honour, so that the marks and the active filter decide what is captured.

Every URL SHALL be supplied fully qualified, carrying both a scheme and an
explicit port, and the capture SHALL be instructed not to derive further
candidates from it. A scan already knows which ports are open and which names a
host answers to; expanding a bare name across guessed scheme and port
combinations would both waste probes and produce results that cannot be
attributed to a known service.

The system SHALL refuse to start a capture when the selection contains no HTTP
or HTTPS URL, and SHALL say so rather than starting a run that captures
nothing.

#### Scenario: Capturing the current selection

- **WHEN** the user starts a capture with rows marked
- **THEN** the URLs of the marked rows' HTTP services are captured, and unmarked rows are not

#### Scenario: One result per supplied URL

- **WHEN** a capture is run over a list of fully qualified URLs
- **THEN** each URL produces exactly one result, and no additional scheme or port variants are probed

#### Scenario: Nothing to capture

- **WHEN** the user starts a capture and the selection contains no HTTP or HTTPS service
- **THEN** the system says there is nothing to capture and no run is started

### Requirement: A capture is supervised like a scan

The system SHALL supervise a capture the way it supervises a scan: its output
SHALL stream while it runs, its progress SHALL be reported as results arrive,
it SHALL be cancellable at any time, and its outcome SHALL be recorded as
finished, failed or cancelled with a one-line result.

The command SHALL be executed as an argument vector and SHALL NOT be
interpreted by a shell.

One capture SHALL run at a time. A capture and a scan MAY run concurrently:
they contend for different resources, and a capture that had to wait for a long
port scan to finish would be useless in the workflow it exists to serve. The
system SHALL warn before quitting while either is running.

#### Scenario: Output streams while the capture runs

- **WHEN** a capture is running
- **THEN** its output is shown as it arrives, and the number of URLs captured so far is reported

#### Scenario: Cancelling a capture

- **WHEN** the user cancels a running capture
- **THEN** the process is ended, the run is recorded as cancelled, and the viewer stays usable

#### Scenario: A capture runs alongside a scan

- **WHEN** a scan is running and the user starts a capture
- **THEN** both run, and each is listed separately with its own progress and outcome

#### Scenario: A second capture is refused

- **WHEN** a capture is running and the user starts another
- **THEN** the system says one is already running rather than starting a second

#### Scenario: Quitting with work in flight

- **WHEN** the user tries to quit while a capture or a scan is running
- **THEN** the system warns and asks for confirmation before quitting

### Requirement: A finished capture is written where an external one would be

A capture SHALL write the same artefacts an externally run capture writes - a
results database, machine-readable results, and the screenshot images - into a
dedicated capture subdirectory of the configured output directory, so that the
files remain usable by gowitness's own tooling and are not a private format
only this application can read.

The output location SHALL follow the same rule the scan output already follows:
the directory the viewer was opened on, or the configured output directory.

#### Scenario: Artefacts are written for external use

- **WHEN** a capture finishes
- **THEN** its database, its machine-readable results and its screenshots are written under the capture subdirectory, in gowitness's own formats

#### Scenario: A cancelled capture

- **WHEN** a capture is cancelled part way through
- **THEN** the results captured before cancellation remain readable, and the run says it was cancelled

### Requirement: Capture results are read back

The system SHALL read the results of a capture and make them available against
the URL each result was produced for. For each result the system SHALL carry
the URL probed, the final URL after redirects, the HTTP status code and reason,
the page title, the detected technologies, the server as reported in the
response headers, a TLS summary where the probe was over TLS, and the path of
the screenshot image.

A result that failed SHALL be carried too, with its reason: knowing that a
service did not answer is a finding, and silently dropping it would make the
capture look incomplete rather than informative.

The system SHALL read capture results produced outside the application from the
capture directory on start up, on the same principle the scan history already
follows - what is on disk is used, whoever produced it.

#### Scenario: A successful capture result

- **WHEN** a URL is captured successfully
- **THEN** its status, title, technologies, server, TLS summary and screenshot path are available for that URL

#### Scenario: A failed capture result

- **WHEN** a URL could not be captured
- **THEN** the result is kept and reports why it failed, rather than being omitted

#### Scenario: Results from an external run

- **WHEN** the viewer is opened on a directory containing a capture produced outside the application
- **THEN** those results are read and shown

#### Scenario: Malformed results are skipped

- **WHEN** a results file contains a line that cannot be parsed
- **THEN** that line is skipped and reported, and the remaining results are still read

### Requirement: A screenshot can be looked at

Because a terminal cannot display an image, the system SHALL provide a way to
open a capture's screenshot in the environment's own image viewer, and a way to
start gowitness's report server against the capture's database and open its
gallery in a browser.

The report server SHALL bind to a loopback address and port from the
configuration, SHALL be started only when the user asks for it, and SHALL be
stopped when the application exits so that no server is left running.

#### Scenario: Opening one screenshot

- **WHEN** the user opens the screenshot of a selected capture
- **THEN** the image is opened in the environment's image viewer

#### Scenario: Browsing every capture

- **WHEN** the user starts the report server
- **THEN** it serves the capture's own database on the configured loopback address and port, and the gallery is opened in a browser

#### Scenario: A screenshot that was never taken

- **WHEN** the user opens the screenshot of a result that failed
- **THEN** the system says there is no screenshot rather than opening nothing

#### Scenario: The server is not left behind

- **WHEN** the application exits while the report server is running
- **THEN** the server is stopped

### Requirement: Capture results are shown where the service is

Capture results SHALL be shown in the record of the host or service they belong
to, so that what a web server actually served is visible in the same place as
the port that carries it, without the operator having to hold two lists side by
side. A service's record SHALL show the results for its URLs; a host's record
SHALL summarise the results across its HTTP services in one line each.

A result SHALL be attributed to a service by the URL it was captured for, and
results captured for a name the host answers to SHALL be shown against that
host's service as well as the name they were requested under - virtual hosting
means one port can serve several sites, and collapsing them would hide exactly
the difference the capture was run to find.

Where the terminal cannot show every captured URL for a record, the record
SHALL remain readable in full in the full-screen reader.

#### Scenario: A service's captures

- **WHEN** the cursor is on an HTTP service that has been captured
- **THEN** its status, title, technologies, server and screenshot path are shown in its record

#### Scenario: A host's captures

- **WHEN** the cursor is on a host with several captured HTTP services
- **THEN** each captured URL is summarised in that host's record

#### Scenario: Several names on one port

- **WHEN** a port was captured under more than one name the host answers to
- **THEN** each name's result is shown separately rather than merged into one

#### Scenario: A record with no captures

- **WHEN** the cursor is on a host or service that has not been captured
- **THEN** the record shows what it always shows, without an empty capture section
