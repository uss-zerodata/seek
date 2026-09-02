# search-cli Specification

## Purpose
Provides the `seek` command-line entry point: it parses invocation arguments, resolves which match modes and paths are in scope, configures the file-tree walk, and launches the interactive session.
## Requirements
### Requirement: Default match modes
When invoked with no mode flags, the system SHALL start the session with filename, directory-name, and file-content matching all active.

#### Scenario: Bare invocation
- **WHEN** the user runs `seek` with no flags or arguments
- **THEN** the interactive session opens with filename, directory, and content matching all active, rooted at the current working directory

### Requirement: Mode selection flags
The system SHALL accept `-f`/`--file`, `-d`/`--directory`, and `-c`/`--content` flags, individually or combined, to set which match modes are active at launch.

#### Scenario: Single mode selected
- **WHEN** the user runs `seek -f`
- **THEN** the session starts with only filename matching active

#### Scenario: Multiple modes combined
- **WHEN** the user runs `seek -f -d`
- **THEN** the session starts with filename and directory matching active and content matching inactive

### Requirement: Path scoping via glob patterns
The system SHALL accept one or more positional glob patterns that restrict the walk to matching paths. A pattern containing no `/` SHALL match against the basename of a path at any depth; a pattern containing `/` SHALL match against the path relative to the search root.

#### Scenario: Basename glob
- **WHEN** the user runs `seek *.md`
- **THEN** only paths whose basename matches `*.md` are eligible to appear as results, at any depth

#### Scenario: Path glob
- **WHEN** the user runs `seek 'logs/2026-*.log'`
- **THEN** only paths whose root-relative path matches `logs/2026-*.log` are eligible to appear as results

#### Scenario: Multiple patterns are OR-ed
- **WHEN** the user runs `seek *.txt *.md`
- **THEN** a path is eligible if it matches at least one of the given patterns

#### Scenario: No patterns given
- **WHEN** the user runs `seek` with no positional patterns
- **THEN** every path under the search root is eligible, subject to the default exclusions

### Requirement: Regex pattern mode
The system SHALL accept a `-r`/`--regex` flag that interprets each positional pattern as a regular expression matched against the root-relative path (an unanchored, partial match) instead of as a glob.

#### Scenario: Regex path filter
- **WHEN** the user runs `seek -r '2026-.*\.log$'`
- **THEN** only paths whose root-relative path matches the regular expression are eligible to appear as results

#### Scenario: Invalid regex
- **WHEN** the user runs `seek -r` with a pattern that is not a valid regular expression
- **THEN** the system SHALL exit with a non-zero status and an error message identifying the invalid pattern, without opening the interactive session

### Requirement: Smart-case pattern matching
Positional glob and regex patterns SHALL be matched case-insensitively when the pattern contains no uppercase character, and case-sensitively when it contains at least one uppercase character.

#### Scenario: Lowercase pattern is case-insensitive
- **WHEN** the user runs `seek readme*`
- **THEN** a file named `README.md` is eligible to appear as a result

#### Scenario: Pattern with uppercase is case-sensitive
- **WHEN** the user runs `seek README*`
- **THEN** a file named `readme.txt` is not eligible to appear as a result

### Requirement: Default traversal behavior
When walking the file tree the system SHALL, by default: include hidden files and directories; follow symbolic links while detecting and breaking traversal cycles; exclude `.git` directories and a built-in set of common noise directories (`node_modules`, `.venv`, `__pycache__`, `target`, `dist`); and NOT apply `.gitignore` or `.ignore` rules.

#### Scenario: Hidden files included by default
- **WHEN** the search root contains a dotfile and the user runs `seek` with no additional flags
- **THEN** the dotfile is eligible to appear as a filename or content result

#### Scenario: gitignored file still appears
- **WHEN** the search root has a `.gitignore` listing `build/` and a file exists at `build/app.js`
- **THEN** `build/app.js` is eligible to appear as a result

#### Scenario: Noise directory excluded
- **WHEN** the search root contains a `node_modules` directory
- **THEN** paths inside `node_modules` are not eligible to appear as results unless the user overrides the exclusion

#### Scenario: Symlink cycle does not hang
- **WHEN** the tree contains a symbolic link that points to one of its own ancestor directories
- **THEN** the walk completes without revisiting the cycle and without unbounded recursion

### Requirement: Honor-gitignore opt-in
The system SHALL accept a flag that makes the walk honor `.gitignore` and `.ignore` files for that session, and this behavior SHALL also be settable as a default in the configuration file.

#### Scenario: Flag enables gitignore filtering
- **WHEN** the user runs `seek` with the honor-gitignore flag and the search root has a `.gitignore` listing `build/`
- **THEN** paths under `build/` are excluded from results

### Requirement: Exclusion overrides
The system SHALL accept configuration-supplied additional exclude globs and SHALL let the built-in noise-directory exclusions be overridden so that those directories are walked.

#### Scenario: Extra exclude glob from config
- **WHEN** the configuration file adds `*.min.js` to the exclude globs
- **THEN** files matching `*.min.js` are not eligible to appear as results

### Requirement: Interactive-only operation
The system SHALL always launch the interactive session for a normal invocation and SHALL NOT provide a non-interactive results-to-stdout mode in this version. Subcommands that do not perform a search (such as `init`) are exempt.

#### Scenario: Output is not a TTY
- **WHEN** the user runs `seek` with stdout redirected to a pipe or file
- **THEN** the system either attaches the interface to the controlling terminal or exits with a clear message that `seek` requires an interactive terminal, and it does not emit a plain result list as its primary behavior

### Requirement: Launch the interactive session with resolved configuration
The system SHALL pass the resolved match modes, path scope, and walker settings to the interactive session so that the session operates within exactly those constraints.

#### Scenario: Scope carried into the session
- **WHEN** the user runs `seek -c 'src/**'`
- **THEN** the interactive session only ever considers candidates whose path is under `src/` and starts with only content matching active

