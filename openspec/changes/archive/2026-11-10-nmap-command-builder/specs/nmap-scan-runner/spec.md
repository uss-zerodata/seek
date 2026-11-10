## MODIFIED Requirements

### Requirement: A scan runs from a reviewed command
A scan SHALL be started only from a command the user has seen in full. The
system SHALL offer the configured presets by name, beside the guided builder
and the recently and frequently used commands; choosing any of them SHALL
produce the complete command as editable text, which the user MAY change
before running.

Before anything runs, the system SHALL present a confirmation showing the exact
arguments to be executed, the number of targets and the first of them, the file
the output will be written to, and whether the command will be run with elevated
privileges. The scan SHALL start only on an explicit confirmation at that step,
and cancelling at any step SHALL run nothing.

The confirmation SHALL state that the targets must be ones the user is
authorised to scan.

#### Scenario: Preset to command
- **WHEN** the user selects a preset
- **THEN** the full command, including the targets and the output path, is shown as editable text

#### Scenario: Builder to command
- **WHEN** the user finishes the builder and picks the fast or the reliable command
- **THEN** that command, with the targets, is shown as editable text, followed by the same review

#### Scenario: The second step
- **WHEN** the user confirms the command
- **THEN** a review of the exact arguments, the scope size, the output path and the privilege level is shown, and nothing runs until that is confirmed too

#### Scenario: Backing out
- **WHEN** the user cancels at the preset, the command or the review step
- **THEN** no process is started and nothing is written
