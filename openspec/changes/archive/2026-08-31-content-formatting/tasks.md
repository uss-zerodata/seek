## 1. The re-indenters

- [x] 1.1 Create `src/seek/engine/format.py` with `reflow_braces(text, indent)`: single-pass, depth-tracking over `{ [ ] }`, breaking at `,`, with quote-state tracking (both quote characters, backslash escaping) so structural characters inside string literals are never break points.
- [x] 1.2 Add `reflow_tags(text, indent)`: breaks at `<` / `>`, tracks in-tag state so a `>` inside a quoted attribute does not end the tag, indents by depth, decrements on `</…>`, does not increment for `<…/>`, `<!…>`, `<?…?>`.
- [x] 1.3 Add `format_lines(raw_lines, path, config) -> (lines, origin | None)`: picks the re-indenter by extension, returns `(raw_lines, None)` when formatting is off, the extension is unlisted, or no line exceeds `format_min_line`; passes through lines already at or under the threshold unchanged; builds the 1-based `origin` map.
- [x] 1.4 Unit tests: minified JSON/XML shrink to short lines; a `,`/`{` inside a JSON string is not split; `>` inside an attribute does not end a tag; truncated JSON, JSONL, JSON-with-comment, unclosed HTML and empty input all return without raising; short lines pass through byte-identical; the `origin` map is correct for a mixed short/long file.

## 2. Configuration

- [x] 2.1 Add `format_content: bool = True`, `format_min_line: int = 500`, and `format_extensions: list[str]` (json, yaml, yml, xml, html, htm, svg, css, js) to `Config`, with the scalar/list key tables and example comments.
- [x] 2.2 Regenerate `config.example.toml`.
- [x] 2.3 Tests: defaults; overriding each key; an unlisted extension is not formatted; `format_content = false` disables everything.

## 3. Cache stores formatted lines and the line map

- [x] 3.1 `ContentCache` takes the `Config` (or the three settings) and applies `format_lines` after decoding, storing `(lines, origin, size)`.
- [x] 3.2 Add `ContentCache.content(path) -> (lines, origin) | None` for callers that need the map; keep `lines()` returning just the lines.
- [x] 3.3 Add `ContentCache.clear()` for the runtime toggle, dropping entries and the binary-negative set.
- [x] 3.4 Account the formatted lines in the byte budget (they are what is retained).
- [x] 3.5 Tests: a reformatted file caches its formatted lines and map; `clear()` empties the cache; the budget still bounds retained bytes.

## 4. Results carry both line numbers

- [x] 4.1 Add `view_line: int | None` to `Result`; `line_no` keeps meaning the line in the file as stored.
- [x] 4.2 `Result.identity()` and `ResultsList._oid` key on `view_line` so matches sharing an original line stay distinct.
- [x] 4.3 `engine.search` sets `line_no` from the `origin` map and `view_line` from the position in the formatted text; the narrowing pool stores `view_line` positions.
- [x] 4.4 Tests: marks on two matches sharing one original line are independent; `format_output` and the editor argv use the original line; narrowing over a reformatted file matches a full rescan.

## 5. Preview and detail render the formatted text

- [x] 5.1 `build_preview` takes the formatted lines (via the shared formatter or the cache) instead of reading and splitting the file itself.
- [x] 5.2 Position the preview window and the detail view on `view_line`.
- [x] 5.3 Keep the header showing `rel:line_no` — the real file location.
- [x] 5.4 Tests: the preview of a match in a minified file shows short lines centred on the match; the detail view shows the formatted document.

## 6. Runtime toggle

- [x] 6.1 Add a `toggle_format` action to `DEFAULT_KEYS` with a non-conflicting binding, plus an action-menu entry.
- [x] 6.2 The toggle flips the effective setting, clears the content cache, drops the narrowing pool, and re-runs the current query.
- [x] 6.3 Show the active state in the status line and add it to the help overlay.
- [x] 6.4 Tests: toggling off re-indexes as stored and recomputes results; toggling on re-indexes formatted; the state is visible; the menu entry works.

## 7. Finalisation

- [x] 7.1 `uv run ruff check` clean.
- [x] 7.2 `uv run pytest -q` green.
- [x] 7.3 `benchmarks/bench_search.py` re-run: confirm no regression on a tree with no long lines, and record the cost on one that has them.
- [x] 7.4 Update README (what formatting does, the keybinding, the config keys) and AGENTS.md (the two line numbers, the cache invariant, the preview path).
- [x] 7.5 `openspec validate content-formatting --strict` passes.
