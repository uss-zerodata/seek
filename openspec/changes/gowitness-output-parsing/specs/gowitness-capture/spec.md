## MODIFIED Requirements

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

#### Scenario: No capture at all
- **WHEN** the capture directory holds no results database
- **THEN** the viewer starts with no captures and reports no error, because a project that was never captured is the ordinary case

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

## ADDED Requirements

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
