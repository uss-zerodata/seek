# gowitness-capture Specification

## Purpose
Screenshotting and fingerprinting the web servers a scan found: running
gowitness over a supplied list of URLs, supervising and cancelling that run,
writing its output where an externally run capture would write it, and reading
the results back so they can be shown against the hosts and services they
belong to.

## Requirements

### Requirement: gowitness is detected and its absence is visible
The system SHALL determine at start up whether a capture can be run, by looking
for a usable container runtime carrying the gowitness image and for a gowitness
binary on `PATH`. Detection SHALL prefer the container backend and fall back to
the native binary, and the configuration SHALL be able to change that order or
pin a single backend.

Detection SHALL NOT block the viewer from starting, and SHALL NOT run a
capture. When neither backend is available, starting a capture SHALL be
unavailable rather than failing at the moment it is invoked, and the interface
SHALL show that it is unavailable. The capture review SHALL still open and SHALL
offer to copy the capture for another machine. When a backend is available the
interface SHALL show which one is in use, so that a capture running in a
container is never mistaken for one running natively.

#### Scenario: Neither backend available
- **WHEN** the viewer starts with no container runtime and no gowitness binary
- **THEN** starting a capture is shown as unavailable, and the capture review explains what is missing and offers only the copy for another machine

#### Scenario: Both backends available
- **WHEN** both a usable container runtime and a gowitness binary are present
- **THEN** the container backend is used, and the interface shows which backend that is

#### Scenario: Only the native binary available
- **WHEN** no container runtime is usable but gowitness is on `PATH`
- **THEN** the capture feature is enabled and reports that it will run natively

#### Scenario: The configured backend is unavailable
- **WHEN** the configuration pins a backend that is not present
- **THEN** starting a capture is unavailable and says which backend was pinned, rather than silently using the other one

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

Before a capture runs, the system SHALL show a review with the exact command,
the number of URLs and the first of them, where the capture is written, and the
backend. The capture SHALL start only on an explicit confirmation at that step.
Cancelling SHALL run nothing and write nothing.

The system SHALL refuse to start a capture when the selection contains no HTTP
or HTTPS URL, and SHALL say so rather than starting a run that captures
nothing.

#### Scenario: Capturing the current selection
- **WHEN** the user starts a capture with rows marked and confirms the review
- **THEN** the URLs of the marked rows' HTTP services are captured, and unmarked rows are not

#### Scenario: Backing out of the capture review
- **WHEN** the user opens the capture review and cancels it
- **THEN** no capture starts and the URL file is not written

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
the first directory the viewer was opened on, or the configured output
directory. The confirmation that starts a capture SHALL name that location.

#### Scenario: Artefacts are written for external use
- **WHEN** a capture finishes
- **THEN** its database, its machine-readable results and its screenshots are written under the capture subdirectory, in gowitness's own formats

#### Scenario: The destination is named before the capture starts
- **WHEN** the viewer was opened on `dir1 dir2` and the user starts a capture
- **THEN** the confirmation names the capture directory under `dir1`

#### Scenario: A cancelled capture
- **WHEN** a capture is cancelled part way through
- **THEN** the results captured before cancellation remain readable, and the run says it was cancelled

### Requirement: Capture results are read back

The system SHALL read the results of a capture from the capture's own results
database and make them available against the URL each result was produced for.
The database is what an externally run capture leaves behind and what the
application already writes for the report server, so it is the one source that
is present however the capture was produced.

For each result the system SHALL carry the URL probed, the final URL after
redirects, the HTTP status code and reason, the page title, the detected
technologies, the complete set of response headers, the cookies and console
messages recorded, the TLS detail including the certificate's subject
alternative names where the probe was over TLS, the path of the screenshot
image, and the identifier by which the report server knows that result.

A result that failed SHALL be carried too, with its reason: knowing that a
service did not answer is a finding, and silently dropping it would make the
capture look incomplete rather than informative.

The system SHALL read capture results produced outside the application from the
capture directory on start up, on the same principle the scan history already
follows - what is on disk is used, whoever produced it.

A capture SHALL be found wherever it is, not only in the capture subdirectory
beside the scans: the system SHALL search every directory the viewer was opened
on, at any depth and by the same rules as the scan search, for results
databases under any file name, and SHALL read a results database named directly
on the command line as a capture rather than as a scan. A file SHALL count as a
results database only if it is a database holding gowitness's results; any other
database SHALL be passed over silently. All captures found SHALL be presented as
one set, each listed as a run of its own; a capture reached twice SHALL be read
once, and a directory with no capture SHALL be passed over silently.

A results database names each screenshot by file name only, so the system SHALL
resolve it from where the database is: the screenshot directory beside the
database first, then the database's own directory, then anywhere below the
database, then anywhere below the directories given. Where the same file name
exists in several places, the copy nearest the database SHALL be used.

The results database is written by a third-party tool and its layout is not a
published interface, so the system SHALL read it defensively: it SHALL tolerate
a database whose tables or columns differ from those it expects, SHALL read
whatever it can rather than rejecting the whole capture, and SHALL report what
it could not read instead of failing silently.

#### Scenario: A successful capture result
- **WHEN** a URL is captured successfully
- **THEN** its status, title, technologies, headers, TLS detail and screenshot path are available for that URL

#### Scenario: A capture written without a results file
- **WHEN** the viewer is opened on a capture directory holding only the results database and its screenshots
- **THEN** its results are read, because the database alone is enough

#### Scenario: A failed capture result
- **WHEN** a URL could not be captured
- **THEN** the result is kept and reports why it failed, rather than being omitted

#### Scenario: Results from an external run
- **WHEN** the viewer is opened on a directory containing a capture produced outside the application
- **THEN** those results are read and shown

#### Scenario: An unreadable or foreign database
- **WHEN** the results database is corrupt, or was written by a version whose layout differs
- **THEN** what can be read is read, what cannot is reported, and the viewer still starts

#### Scenario: Captures in several directories
- **WHEN** the viewer is opened on `dir1 dir2` and only `dir2` holds a capture
- **THEN** that capture's results are shown against their URLs, as if it had been the only directory

#### Scenario: A capture anywhere below
- **WHEN** the viewer is opened on a directory whose results database is `targets/web/shots.sqlite3`
- **THEN** that capture's results are read and shown against their URLs

#### Scenario: Another database is not a capture
- **WHEN** a directory holds a database that is not gowitness's
- **THEN** it is passed over and nothing is reported about it

#### Scenario: A database named on the command line
- **WHEN** the user names a results database alongside the scan directories
- **THEN** it is read as a capture and not reported as a scan that failed to parse

#### Scenario: Screenshots moved away from the database
- **WHEN** a results database sits in one directory and its screenshots in another below the directories given
- **THEN** each result's screenshot is found and can be opened

#### Scenario: No capture at all
- **WHEN** the capture directory holds no results database
- **THEN** the viewer starts with no captures and reports no error, because a project that was never captured is the ordinary case

### Requirement: A screenshot can be looked at

Because a terminal cannot display an image, the system SHALL provide a way to
open a capture's screenshot in the environment's own image viewer, and a way to
start gowitness's report server against the capture's database and open it in a
browser.

Where the selected record identifies one captured result, the report server
SHALL be opened at that result rather than at its front page, so that the
browser shows the thing the cursor was on. Where it does not, the gallery
SHALL be opened as before.

The report server SHALL bind to a loopback address and port from the
configuration, SHALL be started only when the user asks for it, and SHALL be
stopped when the application exits so that no server is left running.

#### Scenario: Opening one screenshot
- **WHEN** the user opens the screenshot of a selected capture
- **THEN** the image is opened in the environment's image viewer

#### Scenario: Opening the selected result in the browser
- **WHEN** the user opens the report for a record identifying one captured result
- **THEN** the browser is opened at that result, not at the gallery front page

#### Scenario: Browsing every capture
- **WHEN** the user starts the report server with no single result selected
- **THEN** it serves the capture's own database on the configured loopback address and port, and the gallery is opened in a browser

#### Scenario: A result the report server cannot address
- **WHEN** the selected result carries no identifier from the database
- **THEN** the gallery is opened rather than a link that would not resolve

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

Collected metadata SHALL be shown at two depths. The record SHALL show inline
the few facts that identify what is running - the server, what it declares
itself powered by, the content type - and SHALL show inline where a security
header that was looked for is absent, since an absence is itself a finding and
cannot be seen by scrolling a list of what is present. The complete set of
headers, cookies and console messages SHALL be available in the full-screen
reader, laid out as structured detail in the way script output already is.
Nothing collected SHALL be discarded to make the pane fit.

Where the technologies gowitness detected do not name the system, the system
SHALL derive a candidate from the page title and the server and powered-by
headers, and SHALL say what that candidate was derived from rather than
presenting it as a detection.

#### Scenario: A service's captures
- **WHEN** the cursor is on an HTTP service that has been captured
- **THEN** its status, title, technologies, server and screenshot path are shown in its record

#### Scenario: The identifying headers are inline
- **WHEN** a captured result carries a server or powered-by header
- **THEN** it is shown in the record without the operator having to open anything

#### Scenario: Every header is reachable
- **WHEN** the operator opens a captured record in the full-screen reader
- **THEN** every header, cookie and console message collected for it is laid out there

#### Scenario: A missing security header is visible
- **WHEN** a captured result does not carry a security header the system looks for
- **THEN** its absence is shown, because it cannot be noticed among the headers that are present

#### Scenario: The system is named from the title
- **WHEN** no technology was detected but the page title or server header names a product
- **THEN** that name is shown as a candidate, labelled with where it came from

#### Scenario: A host's captures
- **WHEN** the cursor is on a host with several captured HTTP services
- **THEN** each captured URL is summarised in that host's record

#### Scenario: Several names on one port
- **WHEN** a port was captured under more than one name the host answers to
- **THEN** each name's result is shown separately rather than merged into one

#### Scenario: A record with no captures
- **WHEN** the cursor is on a host or service that has not been captured
- **THEN** the record shows what it always shows, without an empty capture section

### Requirement: How much a capture collects is configurable

The system SHALL let the configuration decide whether a capture records the
per-request network logs, cookies and response bodies that gowitness can
collect, and SHALL default to not recording them.

The default is off because the tool's own documentation warns that recording
response content can make the capture directory grow without a useful bound,
and because nothing the viewer shows by default needs it. Turning it on SHALL
change only what is collected; reading SHALL show whatever a given database
happens to hold, so a database recorded with the setting on remains fully
readable with it off, and the reverse.

#### Scenario: The default capture stays small
- **WHEN** a capture is run with the setting at its default
- **THEN** it does not record per-request network logs or response bodies

#### Scenario: Full collection is asked for
- **WHEN** the setting is turned on and a capture is run
- **THEN** the network logs, cookies and response bodies are recorded and become readable in the record

#### Scenario: Reading does not depend on the setting
- **WHEN** a database recorded with full collection is read while the setting is off
- **THEN** everything it holds is still shown
