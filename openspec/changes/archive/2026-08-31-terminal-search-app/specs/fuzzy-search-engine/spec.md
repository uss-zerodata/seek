## Purpose

Matches the user's typed query against filenames, directory names, and file contents at once, in real time, and returns a single score-ranked result set in which every entry is tagged with the kind of match it represents.

## ADDED Requirements

### Requirement: Debounced real-time filtering
The system SHALL recompute the result set after the query text changes, without a separate submit action, and SHALL wait for a short idle period (default 150 ms, configurable) after the last keystroke before starting the recomputation.

#### Scenario: Result set follows the query
- **WHEN** the user stops typing and the idle period elapses
- **THEN** the result set is recomputed to reflect the current query text

#### Scenario: Rapid typing coalesces
- **WHEN** the user types several characters faster than the idle period
- **THEN** only one recomputation runs, for the final query text, rather than one per keystroke

### Requirement: Cancellable recomputation
When a new query supersedes an in-progress recomputation, the system SHALL abandon the superseded work and SHALL NOT let its partial results reach the result set.

#### Scenario: Stale results discarded
- **WHEN** a content search for query `alpha` is still running and the user changes the query to `beta`
- **THEN** results produced by the `alpha` search never appear in the list shown for `beta`

### Requirement: fzf extended query syntax
The system SHALL interpret the query using fzf-style extended syntax: space-separated terms are combined with AND; a bare term is a fuzzy (non-contiguous, in-order) match; `'term` (leading single quote) is an exact substring match; `^term` anchors to the start; `term$` anchors to the end; `!term` negates (excludes matches of `term`).

#### Scenario: AND of two fuzzy terms
- **WHEN** the query is `main test`
- **THEN** a candidate is included only if it fuzzy-matches both `main` and `test`

#### Scenario: Negation excludes
- **WHEN** the query is `config !test`
- **THEN** a candidate that matches `test` is excluded even if it matches `config`

#### Scenario: Anchored term
- **WHEN** the query is `^src`
- **THEN** only candidates whose matched text begins with `src` are included

#### Scenario: Exact term
- **WHEN** the query is `'readme`
- **THEN** only candidates containing the contiguous substring `readme` are included

### Requirement: Smart-case matching
Each query term SHALL match case-insensitively when it contains no uppercase character, and case-sensitively when it contains at least one uppercase character.

#### Scenario: Lowercase term matches any case
- **WHEN** the query term is `readme`
- **THEN** names or content containing `README`, `Readme`, or `readme` match

#### Scenario: Mixed-case term is case-sensitive
- **WHEN** the query term is `Readme`
- **THEN** only names or content containing the exact case `Readme` match

### Requirement: Typed results
Every result the engine produces SHALL be tagged with its match type — filename, directory name, or file content — and a content result SHALL carry the 1-based line number and the byte/character span of the match within that line.

#### Scenario: Content result carries a line number
- **WHEN** the query matches text inside a file on line 42
- **THEN** the result is tagged as a content match and reports line 42

#### Scenario: Name and content match on the same file are separate results
- **WHEN** the query matches both a file's name and a line inside its content
- **THEN** the engine returns two separate results, one tagged filename and one tagged content

### Requirement: One result per matching content line
For content matches the system SHALL emit one result per matching line, with no cap on the number of content results per file.

#### Scenario: Many matches in one file
- **WHEN** a query matches 500 distinct lines in a single file
- **THEN** the engine emits 500 content results for that file

### Requirement: Single score-ranked result set
The system SHALL return one result set ordered by match score, with filename, directory, and content results interleaved by score rather than grouped by type. Closer, more contiguous, and more complete matches SHALL score higher than scattered fuzzy matches.

#### Scenario: Contiguous match outranks scattered match
- **WHEN** one candidate matches the query as a contiguous substring and another matches only as scattered in-order characters
- **THEN** the contiguous match is ordered ahead of the scattered match

#### Scenario: Types are interleaved
- **WHEN** a strong content match and a weak filename match are both in the result set
- **THEN** the content match may be ordered ahead of the filename match

### Requirement: Bounded result set
The engine SHALL return at most a configurable number of results (the highest-scoring ones), and SHALL report the total number of matches found so the interface can indicate how many were withheld.

#### Scenario: More matches than the cap
- **WHEN** 5000 candidates match the query and the result cap is 500
- **THEN** the engine returns the 500 highest-scoring results and reports a total of 5000

### Requirement: Progressive results during a search
When given a progress callback, the engine SHALL deliver ranked, capped snapshots of the results found so far as the content pass proceeds, in addition to the final result set.

#### Scenario: Content matches stream in
- **WHEN** a content search over many files is running and a progress callback was supplied
- **THEN** the callback receives one or more ranked partial result sets before the final set is returned

### Requirement: Match spans for highlighting
Each result SHALL expose the positions within its displayed label that matched the query, so the interface can highlight exactly those characters.

#### Scenario: Highlight positions available
- **WHEN** a candidate `main_helper.py` is returned for query `mnh`
- **THEN** the result reports the positions of `m`, `n`, and `h` within the label

### Requirement: Empty-query behavior
When the query is empty the engine SHALL NOT produce content results, and SHALL treat the request as "no ranked results" so the interface can show its tree view instead.

#### Scenario: Clearing the query
- **WHEN** the user deletes all characters from the query field
- **THEN** the engine produces no content results and reports an empty ranked result set

### Requirement: Minimum length for content matching
The engine SHALL begin producing content results only once the effective content-matching portion of the query is at least 2 characters (configurable), to bound work on very short queries.

#### Scenario: One-character query
- **WHEN** the query is a single character
- **THEN** the engine produces filename and directory results but no content results

### Requirement: No-match state
When no candidate satisfies the current non-empty query, the system SHALL report an empty result set distinctly from the empty-query state, so the interface can show a "no matches" indication rather than stale results.

#### Scenario: Query matches nothing
- **WHEN** a non-empty query matches no name, directory, or content line in scope
- **THEN** the engine reports zero results with a flag distinguishing this from the empty-query state

### Requirement: Respect active modes and scope
The engine SHALL only produce results consistent with the currently active match modes and with the path scope resolved for the session, and SHALL react when the interface toggles a mode.

#### Scenario: Content mode inactive
- **WHEN** content matching is not active
- **THEN** the engine produces no content results regardless of the query

#### Scenario: Mode toggled on mid-session
- **WHEN** the user activates content matching during the session with a non-empty query
- **THEN** the next recomputation includes content results

#### Scenario: Scope restricts candidates
- **WHEN** the session scope is `logs/**`
- **THEN** the engine only considers candidates under `logs/`

### Requirement: Name index and budgeted content cache
The system SHALL hold the set of walked file and directory paths in memory for the session, and SHALL cache file contents in memory up to a configurable total budget; files whose contents do not fit the budget SHALL be read from disk during each content search instead.

#### Scenario: Cached file is not re-read
- **WHEN** a file's contents are within the cache budget and the user issues successive queries
- **THEN** the file's contents are read from disk at most once for the session

#### Scenario: Overflow file is rescanned from disk
- **WHEN** total file contents exceed the cache budget
- **THEN** the files that do not fit are searched by reading them from disk on each content search, and results for them are still correct

### Requirement: Binary file handling
The system SHALL detect binary files (for example by the presence of a NUL byte in an initial chunk) and SHALL exclude them from content matching while still allowing them to match by name.

#### Scenario: Binary file skipped for content
- **WHEN** a file in scope contains NUL bytes
- **THEN** it produces no content results, but it can still appear as a filename result

### Requirement: Incremental candidates during streaming walk
While the initial walk is still running, the engine SHALL match against the candidates discovered so far and SHALL incorporate later-discovered candidates into subsequent recomputations.

#### Scenario: Results grow as the walk proceeds
- **WHEN** the user types a query before the walk has finished
- **THEN** results are computed from the candidates found so far, and re-running the query after more of the walk completes can return additional results
