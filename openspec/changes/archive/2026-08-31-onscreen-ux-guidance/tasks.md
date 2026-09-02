## 1. Shared key-name helper

- [x] 1.1 Extract a `pretty_key(spec: str) -> str` helper (e.g. in `tui/keyhints.py` or `config.py`) mapping Textual key names to compact display forms (`ctrl+e`→`^E`, `alt+up`→`⌥↑`, `tab`→`⇥`, `shift+tab`→`⇧⇥`, `question_mark`→`?`, `ctrl+underscore`→`^_`).
- [x] 1.2 Add a `resolve_keys(action_ids, keys) -> list[tuple[str, str]]` helper that maps action ids through `config.keys` and `pretty_key`.
- [x] 1.3 Unit-test both helpers, including a rebound key and every `DEFAULT_KEYS` action.
- [x] 1.4 Fix latent crash in `on_mount`: `App.bind()` in this Textual version has no `priority=`; register config key overrides via `self._bindings.bind(..., priority=True)` instead (any rebind previously crashed startup).

## 2. Rename the no-match Static

- [x] 2.1 Rename `Static(id="hint")` → `id="nomatch"` in `app.py` `compose()`, `_set_middle()`, `_apply_results()`, and any test that queries `#hint`.
- [x] 2.2 Run `uv run pytest -q -k tui` to confirm nothing else referenced `#hint`.

## 3. Persistent hint bar (`onscreen-guidance`)

- [x] 3.1 Add `Static(id="hint-bar")` between `#status` and `#prompt-row` in `compose()`; CSS `height: 1; color: $text-muted; padding: 0 1;` and `no_wrap`/ellipsis rendering.
- [x] 3.2 Add `_hint_context() -> str` returning `tree | results | no_match_scanning | no_match_settled` from `_tree_mode`, `_no_match`, `store.scanning`, query emptiness.
- [x] 3.3 Add `_esc_hint_label()` encoding the staged-Esc precedence (clear query / pop breadcrumb / quit) — single source of truth shared with task 6.
- [x] 3.4 Add `_refresh_hints()` building the per-context `Text` from `resolve_keys` + literal keys (`↵`, arrows, `esc`), ordered by importance with the action-menu key last; append the `_esc_hint_label()` segment.
- [x] 3.5 Call `_refresh_hints()` everywhere `_refresh_status()` is already called, plus on `on_input_changed` (empty/non-empty transition) and `on_mount`.
- [x] 3.6 Ensure `_apply_responsive_layout()` never hides `#hint-bar` (only `#preview`).
- [x] 3.7 Update the `QueryInput` placeholder to drop `(? for help)` redundancy or keep it minimal.

## 4. Self-describing mode indicator

- [x] 4.1 In `_refresh_status()`, render each mode as a word (`files`/`dirs`/`content`), `bold` when on / `dim` when off. (Colour-matching the row markers was dropped — the row-marker colours are invisible on the blue `$primary` status band; see design.md decision 3.)
- [x] 4.2 Append the toggle keys (`toggle_file`/`toggle_dir`/`toggle_content`) resolved via `pretty_key`.
- [x] 4.3 The learnable link to the row markers is the shared initial letter (`files`↔`f`, …); test asserts `MatchKind.*.marker` equals each mode word's first letter.
- [x] 4.4 Optional: `self.notify(...)` on each mode toggle for a transient confirmation.

## 5. Scanning-aware / rescue no-match message

- [x] 5.1 In `_apply_results()` `NO_MATCH` branch, split on `rs.scanning`: scanning → "scanning… no matches yet" in the scan-spinner style; settled → existing `no matches for 'q'`.
- [x] 5.2 Settled message gains a second dim line: `fuzzy match, not regex — <help key> for syntax`.
- [x] 5.3 When content mode is off in the settled case, append `· <toggle-content key> searches file contents`.
- [x] 5.4 Tests: no-match while `_settle`-ing vs. after settle; content-off variant.

## 6. Staged Esc

- [x] 6.1 Rework `action_seek_back()`: if query non-empty → clear it (return to tree); elif breadcrumb depth > 1 → pop; else `exit(0)`.
- [x] 6.2 Verify `_esc_hint_label()` (task 3.3) matches this precedence exactly.
- [x] 6.3 Update `openspec/specs`-facing behaviour is already in the delta; update README `Esc` row.
- [x] 6.4 Tests: Esc clears a non-empty query without exiting; Esc quits from empty/at-root; Esc pops a breadcrumb before quitting.

## 7. Help overlay: grouping + query syntax

- [x] 7.1 Regroup `_ACTIONS` in `help.py` into sections (Navigate / Act on a result / Search scope / Misc) with headings.
- [x] 7.2 Use the shared `pretty_key`/`resolve_keys` helper so overlay and hint bar agree.
- [x] 7.3 Add a "Query syntax" section: AND terms, `'exact`, `^prefix`, `suffix$`, `^whole$`, `!negate`, smart-case.
- [x] 7.4 Test: overlay text contains the syntax tokens and a rebound key appears in it.

## 8. Act from the detail view

- [x] 8.1 In `DetailScreen`, add `show=True` bindings (or a visible controls line) for scroll keys, back, and the editor / default-app / code actions using `config.keys`.
- [x] 8.2 Action handlers `dismiss(<action_id>)` for the open actions; keep `dismiss(None)` for plain back.
- [x] 8.3 In `action_seek_detail()`, dispatch a returned action id through the same path as `ActionsMixin._dispatch_menu()`.
- [x] 8.4 Tests: opening editor from the detail view of a content match runs the same argv as from the list; plain `q`/`Esc` still returns with no action.

## 9. Empty-state heading

- [x] 9.1 Prepend a heading `Text` to `#tree-body` in `_render_tree()` (or wrapper): `root: <name> · hidden shown · .gitignore <on|off> · noise pruned · type to search`.
- [x] 9.2 Source `.gitignore` state from session/config; rebuild on re-root and refresh (existing `_render_tree()` call sites).
- [x] 9.3 Test: heading names the root and reflects the `--gitignore` flag.

## 11. Drop the filled status band (follow-up)

- [x] 11.1 Remove `#status { background: $primary }`; render `#status` / `#hint-bar` on the terminal background.
- [x] 11.2 Add `border-bottom: solid $primary` to `ResultsList` / `#tree` / `#nomatch` so a thin blue rule still fences off the bottom cluster (matches the existing `#preview` rule).
- [x] 11.3 Update the AGENTS.md "Colour under ANSI themes" note, README layout paragraph, and the `interactive-tui` "Screen layout" delta.
- [x] 11.4 Test: result area has a border-bottom rule; `#status` / `#hint-bar` have no background fill.

## 12. Streaming indicator during the search pass (follow-up)

- [x] 12.1 Add a `_searching` flag: set in `_trigger_search`, cleared in `_apply_results` on a non-partial `ResultSet` and on an empty query.
- [x] 12.2 `_on_tick` animates + refreshes whenever `store.scanning or _searching`; drop the tick interval 0.3s → 0.1s.
- [x] 12.3 `_refresh_status` right side: `{spin} scanning {n}` while walking, `{spin} searching…` during the content pass.
- [x] 12.4 `_update_prompt_glyph`: swap `❯` for the spinner frame while streaming; guard with a cached last-glyph so idle ticks are free.
- [x] 12.5 Tests: `searching…` shows while `_searching` and the prompt glyph animates; both clear once results settle.

## 13. Cancel the in-flight search on a query change (follow-up)

- [x] 13.1 Verify the 150 ms idle debounce: `on_input_changed` stops the pending timer and sets a fresh one; `_trigger_search` runs only after the query goes idle. Add a test with `debounce_ms=150` asserting no search runs during a fast keystroke burst and one runs after the pause.
- [x] 13.2 In `on_input_changed`, on any change to a non-empty query, bump `_generation` and clear `_searching` so the running worker is abandoned at once (its `is_stale()` trips; `_apply_results` drops its output).
- [x] 13.3 Test: with a search marked in-flight, one keystroke changes `_generation` immediately and clears `_searching`.

## 10. Docs + finalisation

- [x] 10.1 Update `README.md`: keybinding table (detail-view actions), `Esc` behaviour, Layout section (hint bar), placeholder text.
- [x] 10.2 If `DEFAULT_THEME` gained keys, regenerate `config.example.toml` via the AGENTS.md command.
- [x] 10.3 `uv run ruff check` clean.
- [x] 10.4 `uv run pytest -q` green.
- [x] 10.5 `openspec validate onscreen-ux-guidance --strict` passes.
