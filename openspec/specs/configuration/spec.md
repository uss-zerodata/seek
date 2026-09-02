# configuration Specification

## Purpose
Defines how `seek` loads its optional TOML configuration file, which settings it exposes, and how those settings combine with the built-in defaults and command-line flags.
## Requirements
### Requirement: Configuration file location
The system SHALL read configuration from a TOML file at a per-platform user configuration path: `~/.config/seek/config.toml` on Linux (honoring `XDG_CONFIG_HOME` when set), the platform-appropriate equivalent on macOS and Windows. The path SHALL be reported by `seek` (for example via `--help` or a dedicated subcommand/flag).

#### Scenario: Config path is discoverable
- **WHEN** the user asks `seek` where its config file is
- **THEN** the system reports the absolute path it reads

#### Scenario: XDG override respected
- **WHEN** `XDG_CONFIG_HOME` is set to `/custom/cfg`
- **THEN** the system reads `/custom/cfg/seek/config.toml`

### Requirement: Missing or malformed config
When the configuration file does not exist the system SHALL run entirely on built-in defaults without error. When the file exists but cannot be parsed as TOML, or contains an unknown key or a value of the wrong type, the system SHALL exit non-zero before launching the interface with an error identifying the file and the offending key or line.

#### Scenario: No config file
- **WHEN** no config file exists at the resolved path
- **THEN** `seek` starts normally using default settings

#### Scenario: Invalid TOML
- **WHEN** the config file is not valid TOML
- **THEN** `seek` exits non-zero with an error naming the file, and does not open the interface

#### Scenario: Unknown key
- **WHEN** the config file sets a key that `seek` does not recognize
- **THEN** `seek` exits non-zero identifying that key

### Requirement: Overridable settings
The configuration file SHALL be able to override at least: individual keybindings (action name to key), theme colors, the preview size cap, the detail-view size cap, the per-file content-search size cap, the minimum interval between streamed partial-result updates, the content-search debounce interval, the minimum query length for content matching, the in-memory content-cache budget, whether `.gitignore` is honored by default, additional exclude globs, whether the built-in noise-directory exclusions apply, whether output paths are absolute, whether long result rows wrap instead of being shortened, the maximum number of result rows shown, and the editor table (name to command template with `{file}` and `{line}` placeholders, plus which entry is the default).

#### Scenario: Override a keybinding
- **WHEN** the config maps the "copy path" action to a different key
- **THEN** that key triggers "copy path" in the session and the old key does not

#### Scenario: Override the preview size cap
- **WHEN** the config sets the preview size cap to 1 MB
- **THEN** files larger than 1 MB are truncated in the side preview

#### Scenario: Override the content-search size cap
- **WHEN** the config sets the content-search size cap to 1 MB
- **THEN** at most 1 MB of any one file is read and searched for content matches

#### Scenario: Override the streamed-update interval
- **WHEN** the config sets the minimum partial-result interval to 1000 ms
- **THEN** streamed progress snapshots during a long search are at least 1 s apart

#### Scenario: Define an editor entry
- **WHEN** the config adds `helix = "hx {file}:{line}"` and makes it the default editor
- **THEN** "open in editor" runs `hx <path>:<line>` for a content match

### Requirement: Precedence
For any setting, an explicit command-line flag SHALL take precedence over the configuration file, which SHALL take precedence over the built-in default. Positional path patterns and mode flags given on the command line set the session's initial state regardless of config.

#### Scenario: Flag beats config
- **WHEN** the config sets honor-gitignore to true and the user passes the flag that disables it
- **THEN** the session does not honor `.gitignore`

#### Scenario: Config beats default
- **WHEN** the config sets the debounce interval to 300 ms and no related flag is given
- **THEN** the engine waits 300 ms of idle time before recomputing

### Requirement: Shipped default configuration reference
The project SHALL ship a documented example configuration file listing every supported key with its default value and a short comment, so users can copy and edit it.

#### Scenario: Example file present
- **WHEN** the user looks in the project for a sample configuration
- **THEN** a commented example `config.toml` with every key at its default is available

