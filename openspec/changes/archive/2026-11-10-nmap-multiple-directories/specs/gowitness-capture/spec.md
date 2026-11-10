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
