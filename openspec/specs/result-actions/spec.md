# result-actions Specification

## Purpose
Defines what the user can do with the highlighted result or the current multi-selection from inside the interactive session — open them in external programs, copy their paths, or export the whole selection — and how those actions are triggered and how their output is formatted.
## Requirements
### Requirement: Action targets
An action SHALL operate on the current multi-selection when at least one row is selected, and otherwise on the highlighted row. When an action would operate on more than one target, the system SHALL first prompt the user to confirm acting on all of them or only the highlighted row.

#### Scenario: Action with no selection
- **WHEN** the user triggers an action with no rows selected
- **THEN** the action operates on the highlighted row without a prompt

#### Scenario: Action with multiple selected
- **WHEN** the user triggers an action with three rows selected
- **THEN** the system asks whether to act on all three or just the highlighted row, and proceeds according to the answer

#### Scenario: Nothing to act on
- **WHEN** the user triggers an action with no selection and no highlighted row (for example in the no-match state)
- **THEN** the system performs nothing and shows a brief "nothing selected" message

### Requirement: Action invocation
Each action SHALL be reachable both from an action menu (opened with a dedicated keybinding and listing every action with its shortcut) and, for the common actions, from a direct keybinding. Keybindings SHALL be modifier-based or non-printable so they do not conflict with typing in the query box.

#### Scenario: Open the action menu
- **WHEN** the user presses the action-menu key
- **THEN** a menu lists every action and its keybinding, and choosing one runs it

#### Scenario: Direct key runs an action
- **WHEN** the user presses the direct keybinding for "copy path"
- **THEN** the copy action runs without opening the menu

### Requirement: Open in OS default application
The system SHALL open the target(s) with the operating system's default application, using the platform opener (`xdg-open` on Linux, `open` on macOS, `start` on Windows), detached from the session. The session SHALL stay open and unchanged.

#### Scenario: Open a file in the default app
- **WHEN** the user triggers "open in default application" on a file row
- **THEN** the system launches the platform opener for that file and the session stays open, with the query, the highlighted row and the marks as they were

### Requirement: Open via the editor table
The system SHALL open the target(s) in an editor resolved from the configurable editor table, substituting the file path and, for a content match, the matched line number into that editor's command template. When the target is a content match and the editor template has a line placeholder, the editor SHALL be told to jump to that line. Opening an editor SHALL lend the terminal to the editor without ending the session: the interface is suspended while the editor runs and SHALL resume when the editor exits, with the query, the highlighted row, the marks and - when the action was triggered there - the detail view as they were. File contents read before the editor ran SHALL be read again afterwards. Only where the terminal cannot be lent (the interface cannot be suspended) MAY the system fall back to replacing the process with the editor.

#### Scenario: Open a content match at its line
- **WHEN** the user triggers "open in editor" on a content match at line 42 and the resolved editor template is `nvim +{line} {file}`
- **THEN** `nvim +42 <path>` is executed

#### Scenario: Open a filename match
- **WHEN** the user triggers "open in editor" on a filename row
- **THEN** the editor opens the file with no line argument

#### Scenario: Returning from the editor
- **WHEN** the user opens a result in the editor and then quits the editor
- **THEN** the interface is back on screen with the same query and the same row highlighted, and the application has not exited

#### Scenario: Multiple targets to one editor
- **WHEN** the user confirms "open in editor" for three selected files
- **THEN** all three paths are passed to a single editor invocation

### Requirement: Open in `code`
The system SHALL provide a dedicated "open in code" action that opens the target(s) in `code`, using `code --goto {file}:{line}` for a content match and `code {file}` otherwise, then ends the session.

#### Scenario: Open content match in code
- **WHEN** the user triggers "open in code" on a content match at line 10
- **THEN** `code --goto <path>:10` is executed

### Requirement: Copy path(s) to clipboard
The system SHALL copy the formatted path(s) of the action target(s) to the system clipboard and remain in the session. Clipboard access SHALL use a cross-platform mechanism with a fallback to a platform clipboard utility (`wl-copy`, `xclip`, `pbcopy`, or `clip.exe`) when the primary mechanism is unavailable.

#### Scenario: Copy a single path
- **WHEN** the user triggers "copy" with no selection
- **THEN** the highlighted row's formatted path is placed on the clipboard and the session continues

#### Scenario: Copy multiple paths
- **WHEN** the user confirms "copy" for two selected rows
- **THEN** both formatted paths are placed on the clipboard, one per line

#### Scenario: Clipboard unavailable
- **WHEN** no clipboard mechanism is available
- **THEN** the system shows an error message and stays in the session without crashing

### Requirement: Export the selection
The system SHALL provide a single "export" action that writes the formatted path(s) of the target(s) to a destination chosen at export time: standard output (ending the session), the clipboard (staying in the session), or a file at a path the user supplies (staying in the session). A file export SHALL refuse a path that already exists rather than replace the file; the same rule applies to every file export in the application.

#### Scenario: Export to stdout
- **WHEN** the user runs "export" and chooses standard output
- **THEN** the session ends and each target's formatted path is written to stdout, one per line

#### Scenario: Export to a file
- **WHEN** the user runs "export", chooses "file", and supplies a destination path
- **THEN** each target's formatted path is written to that file, one per line, and the session continues

#### Scenario: Export to a file that exists
- **WHEN** the user runs "export", chooses "file", and supplies the path of an existing file
- **THEN** the file is left as it was and a message says it exists and asks for another name

#### Scenario: Export with nothing selected
- **WHEN** the user runs "export" with no selection and no highlighted row
- **THEN** nothing is written and a "nothing selected" message is shown

### Requirement: Output path format
When paths are written to stdout, the clipboard, or a file, each SHALL be the path relative to the search root, with `:<line>` appended for a content match. A configuration setting SHALL switch this to absolute paths.

#### Scenario: Relative path for a file
- **WHEN** a filename result at `<root>/src/app.py` is exported
- **THEN** the output line is `src/app.py`

#### Scenario: Content match includes the line
- **WHEN** a content result at `<root>/src/app.py` line 88 is exported
- **THEN** the output line is `src/app.py:88`

#### Scenario: Absolute paths configured
- **WHEN** the absolute-path setting is enabled and the same file is exported
- **THEN** the output line is the file's absolute path

### Requirement: Directory results and the shell wrapper
For a directory target the system SHALL support copy, export, and (as the primary action) emitting the directory's path so the installed shell wrapper can `cd` into it. Triggering the "go to directory" action SHALL end the session and communicate the chosen directory path back to the shell wrapper. When the highlighted result is a file (not a directory), "go to directory" SHALL use that file's parent directory.

#### Scenario: Go to a directory
- **WHEN** the user triggers "go to directory" on a directory row and the shell wrapper is installed
- **THEN** the session ends and the shell changes its working directory to that directory

#### Scenario: Go to a file's directory
- **WHEN** the user triggers "go to directory" on a file result at `src/app.py`
- **THEN** the target directory is `src/` (the file's parent)

#### Scenario: Go to directory without the wrapper
- **WHEN** the user triggers "go to directory" but no shell wrapper is installed
- **THEN** the directory's path is printed to stdout on exit so it can still be used

### Requirement: Restore the terminal before external programs
Before handing the terminal to an external program, and before writing action output to stdout, the system SHALL restore the terminal from the full-screen interface state.

#### Scenario: Editor gets a clean terminal
- **WHEN** an "open in editor" action runs
- **THEN** the interface is suspended and the terminal restored before the editor starts, so the editor renders correctly

#### Scenario: stdout output is not mixed with UI escape codes
- **WHEN** an action that prints to stdout runs
- **THEN** the printed lines contain only the formatted paths, with no leftover interface control sequences

