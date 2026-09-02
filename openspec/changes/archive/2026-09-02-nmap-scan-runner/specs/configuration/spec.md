## ADDED Requirements

### Requirement: nmap scan presets are configured
The commands a scan can be started from SHALL be defined in the configuration
file as named presets, each mapping a name shown to the user to the nmap
arguments it stands for. The order they are written in SHALL be the order they
are offered in.

The system SHALL ship a working default set, and a user's set SHALL replace it
rather than being merged with it, so that a curated list is exactly what is
offered.

A preset SHALL NOT declare whether it needs elevated privileges: that SHALL be
derived from its arguments, so that a command the user writes is classified as
correctly as a shipped one.

The configuration SHALL also expose where scan output is written, when the user
wants somewhere other than the directory the viewer was opened on.

A preset whose arguments cannot be parsed, or which carries its own output
arguments, SHALL be reported like any other configuration error: named, with the
reason, without preventing the rest of the configuration from loading.

#### Scenario: Presets are offered in the order written
- **WHEN** the configuration defines four presets
- **THEN** they are offered in that order, under the names given

#### Scenario: A user's set replaces the default
- **WHEN** the configuration defines any preset
- **THEN** only those presets are offered, not the shipped ones as well

#### Scenario: Privilege is derived
- **WHEN** a preset's arguments include a scan type that requires root
- **THEN** it is treated as needing elevation without being marked as such

#### Scenario: A malformed preset
- **WHEN** a preset's arguments cannot be parsed
- **THEN** that preset is reported with the reason and the rest of the configuration still loads

#### Scenario: The default file documents them
- **WHEN** the shipped example configuration is read
- **THEN** it contains the default presets with a comment explaining what each is for
