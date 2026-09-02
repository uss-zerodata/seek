## MODIFIED Requirements

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
