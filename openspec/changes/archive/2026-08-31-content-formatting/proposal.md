## Why

Structured files are frequently stored with no line breaks — minified JSON, XML,
HTML, and their bundled JS/CSS neighbours. A single line of tens of thousands of
characters breaks the app in two ways.

**It is unreadable.** The result row, the preview and the detail view all show
one enormous line; the match may be 40,000 characters into it.

**It matches everything.** `seek`'s content query is a fuzzy *subsequence* test,
and a long enough line contains every character in every order. Measured on the
project's own dependency tree (16 lines longer than 2,000 characters):

| query | lines matched |
|---|---|
| `asyncio` | 5 / 16 |
| `zzqq` | 5 / 16 |
| `xyzzy` | 5 / 16 |
| `qqqq` | 5 / 16 |

Nonsense queries match *identically* to real ones. These lines are pure noise
that crowds out real results, and they score well because a long line
accumulates score.

## What Changes

- **Structured files are re-indented before they are indexed.** A file whose
  extension is in a configurable list and which actually contains an over-long
  line is broken into short, indented lines at its structural boundaries.
- **Two formatters, chosen by extension, both single-pass and parser-free:** a
  brace/bracket re-indenter (JSON, JS, CSS, YAML flow sequences) that is aware of
  string literals so a `,` or `{` inside a string is never a break, and a tag
  re-indenter (XML, HTML, SVG) that splits at tag boundaries and indents by
  nesting depth.
- **No new runtime dependency, and no parse step.** Measured against the
  alternatives: `xml.dom.minidom` is 2.3× slower, and both `json.loads` and
  `minidom` raise on 4 of 7 malformed-input cases where the re-indenters simply
  produce a reasonable split. Truncated JSON, JSONL, unclosed HTML and `>` inside
  an attribute value are all handled.
- **Formatted text is what the app shows.** The result row, the preview and the
  detail view all render the formatted lines, so what was searched is what is
  seen.
- **Line numbers stay truthful to the file on disk.** Every formatted line
  records the original line it came from. `path:line` in rows and exports, and
  "open in editor", still point at a real location in the real file.
- **Only files that need it are touched.** Formatting is gated on the file
  actually containing a line longer than a configurable threshold, and lines
  already short enough are passed through untouched, so an already-pretty file
  costs nothing and keeps exact line numbers.
- **Configurable both ways:** `format_content`, `format_extensions` and
  `format_min_line` in the config file, plus a keybinding and an action-menu
  entry that toggle formatting during a session and re-index immediately.

## Capabilities

### New Capabilities
- `content-formatting`: re-indenting over-long structured content before it is
  indexed — which files it applies to, what the resulting line numbers mean, how
  it degrades on malformed input, and how it is configured and toggled.

### Modified Capabilities
<!-- none: the new capability owns its own configuration and toggle
     requirements, so no existing spec's requirements change. -->

## Impact

- New `src/seek/engine/format.py` (the two re-indenters and the extension /
  long-line gate).
- `src/seek/engine/content.py`: `ContentCache` stores formatted lines plus the
  original-line map, and the cache key accounts for whether formatting is on.
- `src/seek/models.py`: `Result` gains the formatted-view line index; identity
  and the row id switch to it, since many formatted lines can share one original
  line number.
- `src/seek/engine/engine.py`: carries both line numbers onto results.
- `src/seek/tui/preview.py`: renders the same formatted text as the index,
  rather than reading and splitting the file itself.
- `src/seek/config.py`: three new keys; `config.example.toml` regenerated.
- `src/seek/tui/app.py` + `actions_mixin.py`: the runtime toggle, its keybinding,
  its action-menu entry, and the cache invalidation it triggers.
- No new runtime dependency. No CLI flag changes.
