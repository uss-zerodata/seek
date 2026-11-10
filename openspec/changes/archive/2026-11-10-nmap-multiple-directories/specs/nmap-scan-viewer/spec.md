## ADDED Requirements

### Requirement: Scans are named unambiguously across directories
When two or more directories are given, a scan's file name alone no longer
identifies it: tools and presets write the same names into every directory. The
system SHALL then name every scan by its path relative to the common parent of
the given directories, and SHALL use that name everywhere a scan is named — the
provenance of hosts and services, a record's scan entries, the Scans tab, the
report of files that failed to parse, and the exported list of source scans.

Provenance SHALL be kept per file, so that a host seen in two files with the same
file name is recorded as seen in both.

With a single directory, or with only files given, scans SHALL keep being named
by their file name alone.

#### Scenario: Same file name in two directories
- **WHEN** the viewer is opened on `x` and `y`, each holding a `scan.xml` that records host `192.0.2.40`
- **THEN** the host is listed as seen in `x/scan.xml` and in `y/scan.xml`, not once as `scan.xml`

#### Scenario: Every scan is qualified once there are several directories
- **WHEN** the viewer is opened on two directories and one of them holds `sub/other.xml`
- **THEN** that scan is named `<directory>/sub/other.xml` in the Scans tab and in the records, even though no other scan shares its file name

#### Scenario: A single directory keeps bare names
- **WHEN** the viewer is opened on one directory
- **THEN** scans are named by their file name alone, as before

#### Scenario: A failure names the file unambiguously
- **WHEN** two directories each hold a truncated `scan.xml`
- **THEN** the failure report names both, each qualified by its directory

## MODIFIED Requirements

### Requirement: Entry point
The system SHALL provide a `nmap` subcommand taking any number of file paths and
directories, in any mix, and opening the viewer on all of them as one merged
model. With nothing given it SHALL read the working directory. A file reached
through more than one of the given directories SHALL be read once. The viewer is
a purpose-built interface for scan output and SHALL be reached this way; the
file-search session SHALL NOT carry nmap-specific actions or hints.

When the given paths hold no readable scan and scanning is available, the
subcommand SHALL open the viewer on an empty model with the scope editor rather
than exiting: a directory with nothing in it yet is the case for starting a
scan, not an error. When scanning is unavailable it SHALL explain what it
expects and exit as before.

The output directory for any scan or capture started in that session SHALL be
the first directory given, or the working directory when only files were given,
unless an output directory is configured. The system SHALL name that directory
before anything is written — in the review of a scan and in the confirmation of
a capture — so that with several directories the choice is visible rather than
inferred.

#### Scenario: Opening files directly
- **WHEN** the user runs the `nmap` subcommand with two scan files
- **THEN** the viewer opens on the merged model of both

#### Scenario: Opening several directories
- **WHEN** the user runs the `nmap` subcommand with three directories
- **THEN** the viewer opens on one merged model of the scans found in all three

#### Scenario: Overlapping directories
- **WHEN** the user names a directory and also a subdirectory of it
- **THEN** each scan below the subdirectory is read once

#### Scenario: The search session stays a file search
- **WHEN** the highlighted result in a search session is an nmap XML file
- **THEN** the search session offers no nmap-specific action for it

#### Scenario: No paths given
- **WHEN** the subcommand is run with no paths
- **THEN** the working directory is read, as if it had been named

#### Scenario: A directory with no scans, and nmap available
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is available
- **THEN** the viewer opens with the scope editor, and that directory is where a scan will write

#### Scenario: A directory with no scans, and no nmap
- **WHEN** the subcommand is run on a directory holding no readable scan and nmap is not available
- **THEN** the system reports that there is nothing to read and exits

#### Scenario: Output goes to the first directory, and says so
- **WHEN** the viewer was opened on `dir1 dir2` and the user starts a scan
- **THEN** the review names a location under `dir1` as where the scan will write
