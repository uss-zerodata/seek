## ADDED Requirements

### Requirement: A running scan's finished hosts are in the model
While a scan runs, the hosts nmap has already written to its output SHALL be
read into the model, by the same loading path as any scan file, so that every
view, filter, record, export and the browser include them before the scan ends.
They SHALL be attributed to the running scan.

#### Scenario: A long scan's first host group
- **WHEN** a scan of a /23 has finished its first host group and is still running
- **THEN** the hosts of that group appear in the overviews, attributed to that scan, while the run is still listed as running

#### Scenario: A scan started outside seek
- **WHEN** nmap runs outside seek and writes into a directory the viewer reads
- **THEN** its hosts appear only when the viewer next reads its sources, as before

### Requirement: Reading a running scan never takes the list away
A re-read for a running scan SHALL keep the rows on screen, the cursor, the
marks and the filter, and SHALL report on the status line only. It SHALL happen
only after nmap reported finished hosts, no more than once a minute, never
while another read runs, and only if the output file has grown.

#### Scenario: A quiet refresh
- **WHEN** a running scan's new hosts are read in while the user is reading a record
- **THEN** the list and the record stay where they were, and the status line says how many hosts the scan has added

#### Scenario: Nothing new
- **WHEN** a minute passes and nmap has reported no finished host
- **THEN** nothing is read

### Requirement: A running scan's file is named as running
The output file of a running scan SHALL be shown as running, not as cut off or
incomplete, and the Scans tab SHALL list it once, as the running run. When the
run ends, the final read SHALL replace the partial one, and the run's summary
SHALL count everything the scan added since it started.

#### Scenario: No false warning
- **WHEN** a running scan's partial file is read
- **THEN** no warning calls it incomplete, and the Scans tab lists the run once

#### Scenario: The summary covers the whole run
- **WHEN** a scan whose hosts were read in three times while it ran finishes
- **THEN** its summary counts every host and port it added since it started
