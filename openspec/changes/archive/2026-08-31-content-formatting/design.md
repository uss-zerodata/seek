## Context

See `proposal.md` — Why. Constraints that shape the approach:

- Runtime dependencies are deliberately minimal and must be justified.
- `ContentCache.lines()` is the single source of indexed content, and it is on
  the hot path: `engine.search` calls it per candidate. Formatting must be done
  once per file and cached with it, never per search.
- `preview.py` currently reads and splits the file *itself*, independently of
  `ContentCache`. If only the index were formatted, the preview would show
  different text with different line numbers.
- `Result.line_no` feeds six consumers: the row label, the detail title, preview
  centring, detail centring, `editor +{line}` / `code --goto`, export
  `path:line`, and `Result.identity()` for marks. Formatting decouples "position
  in the text we searched" from "line in the file on disk", so those consumers
  split into two groups.
- The unarchived `search-performance` change already modifies `configuration`'s
  "Overridable settings"; a second delta against the same requirement would lose
  content whichever order they archive in.

## Goals / Non-Goals

**Goals:**

- Kill the "long line matches everything" failure, which is the actual bug.
- Never fail on malformed input — real trees are full of truncated and
  non-conforming files.
- Cost nothing for files that do not need it.
- Keep `path:line` and editor hand-off pointing at the real file.

**Non-Goals:**

- Not a formatter people should use to *write* files with. Output only has to be
  readable and searchable, not canonical.
- No new runtime dependency, so no PyYAML and no HTML parser. YAML is
  line-oriented and rarely minified; its long-line case is inline flow sequences,
  which the brace re-indenter already covers.
- No syntax validation, and no error reporting for malformed files.
- Not reformatting source code (`.py`, `.rs`, …). Long lines there are rare and
  the file is meant to be read as written.

## Decisions

### 1. Single-pass re-indenters, not parsers

Measured on 0.14 MB of minified JSON and 0.20 MB of minified XML:

| approach | time | malformed input (7 cases) |
|---|---:|---|
| **char-loop re-indenter** | **16.4 ms** / **25.5 ms** | handles all 7 |
| regex-tokenised variant | 21.7 ms | handles all 7, but slower |
| `json.loads` + `dumps(indent=2)` | 14.7 ms | raises on 4 |
| `xml.dom.minidom` + `toprettyxml` | 58.7 ms | raises on 4 |

The parser-based routes are not meaningfully faster (JSON) or are 2.3× slower
(XML), and they raise on truncated JSON, JSONL, JSON with comments, and unclosed
HTML — all of which occur constantly in a real tree. A `try/except` fallback
would work but means the common malformed case pays a full failed parse first.

The regex-tokenised variant was measured because the C engine doing the scanning
usually wins. It does not here: in minified content nearly every token *is* a
structural character, so per-match overhead exceeds the saving. (It was also
checked for catastrophic backtracking on a long unterminated string — linear, but
still slower.)

So: two hand-written single-pass scanners in `engine/format.py`.

- `reflow_braces` — tracks nesting depth over `{ [ ] }` and breaks at `,`, while
  tracking quote state with backslash escaping so a structural character inside a
  string literal is never a break point. Covers JSON, JS, CSS, YAML flow
  sequences.
- `reflow_tags` — breaks at `<` and `>`, tracks whether it is inside a tag so a
  `>` inside a quoted attribute value does not end it, and indents by depth,
  decrementing on `</…>` and not incrementing for `<…/>`, `<!…>` or `<?…?>`.
  Covers XML, HTML, SVG.

Neither validates anything, so neither can fail; the worst case for garbage input
is an unhelpful but harmless split.

### 2. Gate on extension *and* on an actually-long line

Formatting runs only when the extension is configured **and**
`max(len(line)) > format_min_line`. Two reasons: a file that does not need it
costs one `max()` over its lines, and — more importantly — an already-pretty file
keeps its exact line numbers rather than being re-derived.

Within a file that is being reformatted, a line already at or under the threshold
is emitted unchanged rather than pushed through a scanner. So a 3,000-line JSON
with one pathological line pays for that one line.

### 3. The line map, and splitting `Result.line_no` in two

`ContentCache` stores `(lines, origin)` where `origin[i]` is the 1-based line of
the stored file that formatted line `i` came from. When a file is not reformatted
`origin` is `None` and the identity mapping is implied.

`Result` gains `view_line`, the index into the formatted text:

- `line_no` stays the **original** file line — row label, detail title, export
  `path:line`, `editor +{line}`, `code --goto`. All keep pointing at the real
  file.
- `view_line` positions the **preview** and the **detail view** inside the
  formatted text.
- `identity()` and `ResultsList._oid` switch to `view_line`, because many
  formatted lines can share one original line number (a minified file maps
  everything to line 1) and `(path, line_no)` would collide — marking one match
  would mark its neighbours.

When nothing is reformatted `view_line == line_no`, so all existing behaviour is
unchanged.

### 4. The preview must read through the same path

`preview.py` reads the file itself. It moves to the shared formatter so the
preview, the detail view and the index cannot disagree. `build_preview` takes the
formatted lines and positions on `view_line`.

This is what makes the feature actually solve the readability half of the
problem; formatting the index alone would leave the preview showing the original
long line.

### 5. Cache invalidation on toggle

Formatted and unformatted content cannot coexist in one `ContentCache` entry, and
the runtime toggle flips which one is wanted. Rather than key entries by mode,
toggling clears the cache — it is a deliberate, infrequent user action, and the
files are re-read lazily. The toggle then re-runs the current query. The engine's
narrowing pool is also dropped, since it holds line numbers into the old text.

### 6. Config keys live in the new capability's spec

`configuration`'s "Overridable settings" requirement is already being modified by
the unarchived `search-performance` change. Two full-text `MODIFIED` blocks
against one requirement lose content whichever order they archive in. Since that
requirement says the config "SHALL be able to override **at least**" its list,
adding keys does not contradict it, so this change states its own configurability
as a requirement of `content-formatting` and touches no existing capability. That
also keeps everything about formatting in one spec.

## Risks / Trade-offs

- **Output is not canonical formatting.** A pretty-printer would produce nicer
  JSON. The output only has to be readable and searchable; the measured speed and
  the total absence of failure modes are worth more than exact indentation.
- **A pathological file is slower to first index** (~115 ms per MB of content
  that actually needs reformatting) → it is cached for the session, gated to
  files that need it, and bounded by the existing `content_size_cap`.
- **Formatted content uses more cache budget** — many short strings carry more
  per-object overhead than a few long ones, so the byte accounting will admit
  fewer files. That is the budget doing its job, but it means a formatted tree
  caches less than an unformatted one.
- **`view_line` is a second line number to keep straight.** Mitigated by making
  `line_no` mean exactly one thing (the file on disk) everywhere it is
  user-visible, and confining `view_line` to preview/detail positioning and
  identity.
- **Toggling clears the whole content cache**, so the next query re-reads. The
  alternative — keying cache entries by mode — doubles memory for a rare action.

## Migration Plan

Additive. Three new config keys with defaults; existing config files stay valid.
`config.example.toml` is regenerated. Formatting defaults to on, which changes
what the app shows for minified files — that is the point of the change, and the
toggle plus `format_content = false` are the ways back.
