## ADDED Requirements

### Requirement: A screenshot is taken when the page has settled
A capture SHALL take each screenshot once the page has finished loading, every
image in it has arrived, and nothing in the page has changed and no resource has
finished downloading for the configured quiet time (default two seconds). It
SHALL take the screenshot anyway once the configured upper limit (default twenty
seconds) has passed, so one page cannot hold a capture. The page timeout given
to gowitness SHALL never be shorter than that upper limit. Setting the quiet time
to zero SHALL restore a fixed delay of three seconds with gowitness's default
driver.

A page that stays entirely unchanged for longer than the quiet time before a
single late response draws it MAY be captured before that response; the quiet
time is the setting that covers such pages.

#### Scenario: A page whose content arrives late
- **WHEN** a page finishes loading after four seconds and renders its content one and a half seconds later
- **THEN** the screenshot shows the rendered content

#### Scenario: A fast page is not held up
- **WHEN** a static page is complete at once
- **THEN** its screenshot is taken about one quiet time later, not after the upper limit

#### Scenario: A page that never settles
- **WHEN** a page keeps changing without end
- **THEN** its screenshot is taken at the upper limit and the capture goes on to the next target

#### Scenario: The wait is switched off
- **WHEN** the quiet time is configured as zero
- **THEN** the capture runs with a fixed three-second delay and no script

#### Scenario: A target that cannot be reached
- **WHEN** one target refuses the connection
- **THEN** it is reported as failed with its reason, as before
