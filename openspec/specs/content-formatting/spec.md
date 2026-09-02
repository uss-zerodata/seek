# content-formatting Specification

## Purpose
Re-indents over-long structured content — minified JSON, XML, HTML and their
bundled neighbours — into short lines before it is indexed, so that such files
are readable in the interface and no longer match every query by virtue of one
line being long enough to contain any subsequence.
## Requirements
### Requirement: Over-long structured content is re-indented before indexing
When content formatting is enabled, the system SHALL re-indent a file's contents
into shorter lines before matching against them, provided the file's extension is
in the configured set and the file actually contains a line longer than the
configured threshold. A file that fails either test SHALL be indexed exactly as
it is stored. Lines already at or below the threshold SHALL be passed through
unchanged even within a file that is otherwise reformatted.

#### Scenario: Minified JSON becomes many short lines
- **WHEN** a `.json` file holds its whole document on one 50,000-character line and formatting is enabled
- **THEN** it is indexed as many short indented lines rather than one long one

#### Scenario: An already-formatted file is left alone
- **WHEN** a `.json` file's longest line is shorter than the threshold
- **THEN** its contents are indexed exactly as stored and its line numbers are unchanged

#### Scenario: An unlisted extension is not reformatted
- **WHEN** a `.py` file contains a 50,000-character line and `.py` is not in the configured extension set
- **THEN** the file is indexed as stored

#### Scenario: Short lines survive intact in a reformatted file
- **WHEN** a file mixes ordinary short lines with one over-long line
- **THEN** the short lines appear in the index unchanged and only the over-long line is broken up

### Requirement: Formatting never fails on malformed input
Formatting SHALL NOT require the content to be valid in its notation, and SHALL
NOT raise or discard content when it is not. Truncated documents, concatenated
documents, comments, and unclosed markup SHALL each produce a reasonable split
rather than an error or an empty result. If formatting cannot improve a file, the
system SHALL fall back to indexing it as stored.

#### Scenario: Truncated JSON still yields content
- **WHEN** a `.json` file ends mid-document, for example `{"a": [1,2,3`
- **THEN** it is broken into lines without error and its content is still searchable

#### Scenario: Unclosed markup still yields content
- **WHEN** an `.html` file contains unclosed tags
- **THEN** it is broken into lines without error and its content is still searchable

#### Scenario: A structural character inside a string is not a break
- **WHEN** a JSON string value itself contains `,` or `{`, as in `{"s":"a,b{c}d"}`
- **THEN** that value is not split at those characters and appears intact on one line

#### Scenario: A `>` inside an attribute value does not end the tag
- **WHEN** markup contains an attribute such as `title="a>b"`
- **THEN** the tag is not split at the `>` inside the quoted value

### Requirement: Line numbers refer to the file on disk
Every formatted line SHALL record which line of the stored file it came from. The
line number the system reports for a content match — in the result row, in
exports, and when handing a file to an editor — SHALL be that original line
number, so it always identifies a real location in the file as stored. The
position within the formatted text SHALL be tracked separately, and used for
positioning the preview and the detail view.

#### Scenario: Editor opens at a real line
- **WHEN** the user opens a match found in a reformatted minified file in an editor
- **THEN** the editor is given a line number that exists in the file as stored

#### Scenario: Exported paths carry the original line
- **WHEN** matches from a reformatted file are exported as `path:line`
- **THEN** the line numbers are those of the file as stored, not positions in the formatted text

#### Scenario: Distinct matches remain distinct
- **WHEN** several matches in a reformatted file share one original line number
- **THEN** they are still separate rows, and marking one does not mark the others

### Requirement: The interface shows the formatted content
When a file has been reformatted for indexing, the result row, the preview pane
and the full-screen detail view SHALL all show that same formatted text, so the
text that was searched is the text the user sees. The preview and detail view
SHALL position on the matched line within the formatted text.

#### Scenario: Preview shows the formatted text
- **WHEN** the highlighted row is a match inside a reformatted minified file
- **THEN** the preview shows short indented lines centred on the match, not the original long line

#### Scenario: Detail view shows the formatted text
- **WHEN** the user opens the detail view for such a match
- **THEN** the whole file is shown reformatted, positioned at the matched line

### Requirement: Formatting is configurable and can be toggled during a session
The system SHALL provide configuration for whether formatting is applied, which
file extensions it applies to, and the line length above which a file is
considered to need it. The user SHALL additionally be able to turn formatting on
and off during a session, via a keybinding and via the action menu. Toggling
SHALL re-index the affected content and recompute the current query, and the
active state SHALL be visible in the interface.

#### Scenario: Disabled in configuration
- **WHEN** content formatting is disabled in the config file
- **THEN** every file is indexed exactly as stored, whatever its extension or line lengths

#### Scenario: Toggled off during a session
- **WHEN** formatting is on, results are showing, and the user presses the formatting-toggle key
- **THEN** the affected files are re-indexed as stored and the results for the current query are recomputed

#### Scenario: Toggled back on
- **WHEN** the user toggles formatting on again with a query active
- **THEN** the affected files are re-indexed reformatted and the results are recomputed

#### Scenario: The active state is visible
- **WHEN** the interface is showing results
- **THEN** whether content formatting is currently applied can be seen in the interface

#### Scenario: Extension set is configurable
- **WHEN** the configured extension set is changed to include a further extension
- **THEN** files with that extension are considered for formatting

