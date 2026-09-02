## Purpose

Defines the `seek init <shell>` subcommand and the shell wrapper function it installs, which lets a directory chosen inside the interactive session change the working directory of the user's interactive shell.

## ADDED Requirements

### Requirement: `seek init` emits shell integration code
The system SHALL provide a `seek init <shell>` subcommand that prints, to standard output, shell code suitable for `eval "$(seek init <shell>)"` in a shell startup file. `<shell>` SHALL accept `bash` and `zsh` in this version; an unsupported value SHALL cause a non-zero exit with an error naming the supported shells.

#### Scenario: Emit zsh integration
- **WHEN** the user runs `seek init zsh`
- **THEN** valid zsh code is printed to stdout and the process exits zero

#### Scenario: Unsupported shell
- **WHEN** the user runs `seek init powershell`
- **THEN** the process exits non-zero with a message listing `bash` and `zsh` as supported

#### Scenario: init does not launch the interface
- **WHEN** the user runs `seek init bash`
- **THEN** no interactive session is started

### Requirement: The wrapper function runs the real command and applies a directory change
The emitted code SHALL define a `seek` shell function that invokes the underlying `seek` program for the user's arguments, and, when the session ends with a "go to directory" request, SHALL change the shell's working directory to the chosen directory. For all other outcomes the function SHALL behave as if the program were run directly, preserving its exit status.

#### Scenario: Directory selection changes the shell directory
- **WHEN** the user runs `seek -d`, navigates to a directory, and triggers "go to directory"
- **THEN** after the command returns, the interactive shell's working directory is that directory

#### Scenario: Non-directory outcome leaves the directory unchanged
- **WHEN** the user runs `seek`, opens a file in an editor, and the editor exits
- **THEN** the shell's working directory is unchanged

#### Scenario: Exit status preserved
- **WHEN** the underlying program exits non-zero (for example an invalid regex)
- **THEN** the `seek` function returns that same non-zero status

### Requirement: Directory hand-off channel does not corrupt the interface
The mechanism by which the chosen directory path is passed from the program to the wrapper function SHALL NOT interfere with the full-screen interface while it is running, and SHALL work for directory paths that contain spaces or other shell-significant characters.

#### Scenario: Path with spaces
- **WHEN** the chosen directory path contains a space
- **THEN** the wrapper `cd`s into exactly that directory without word-splitting it

#### Scenario: Interface still renders normally
- **WHEN** the wrapper function is in use
- **THEN** the interactive interface displays and behaves the same as when the program is run without the wrapper

### Requirement: Safe to evaluate unconditionally
The emitted code SHALL be safe to `eval` in a startup file even when the `seek` program is not on `PATH` at eval time: evaluation SHALL define the function without error, and the failure SHALL surface only when the function is actually called.

#### Scenario: seek not yet installed
- **WHEN** `eval "$(seek init zsh)"` is in `.zshrc` but the program is later removed from `PATH`
- **THEN** starting a shell produces no error from the integration, and calling `seek` reports that the program was not found
