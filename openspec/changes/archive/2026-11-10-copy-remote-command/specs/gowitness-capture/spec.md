## MODIFIED Requirements

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
