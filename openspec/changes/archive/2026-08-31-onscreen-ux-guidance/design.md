## Context

See `proposal.md` — Why. Current constraints that shape the approach:

- `SeekApp.compose()` yields, top to bottom: `#preview`, `ResultsList`, `#tree`,
  `#hint` (the centred no-match message — note the name clash to avoid), `#status`,
  and `#prompt-row` (`❯` + `QueryInput`). `_refresh_status()` rebuilds the status
  band on every state change.
- All bindings are declared with `show=False` in `_default_bindings()`, so
  Textual's `Footer` widget would render nothing useful without reworking every
  binding. Keys are user-configurable via `config.keys` (`DEFAULT_KEYS`), and the
  help overlay already resolves action→key through that dict.
- The app runs under the `ansi-dark` theme where `$panel`/`$surface`/`$boost`
  collapse to the terminal background; separation comes from the blue status
  band and blue rules. Rendered text is styled with explicit Rich colours from
  `config.theme` (`DEFAULT_THEME`).
- `action_seek_back()` currently does: pop breadcrumb if deep, else `exit(0)`.
  Modal screens intercept `escape` themselves, so the app-level handler only ever
  runs on the main screen.
- `_apply_results()` already receives `rs.scanning` via the `ResultSet`; the
  no-match branch just doesn't use it.
- `DetailScreen` is typed `ModalScreen[str | None]` and its docstring promises an
  "action id to run after closing", but `action_back()` always `dismiss(None)`
  and `action_seek_detail()` ignores the return value.

## Goals / Non-Goals

**Goals:**

- One reusable hint-rendering path that reads `config.keys`, mirroring how
  `help.py` resolves bindings, so hints and help never disagree.
- Context selection driven by the same state the status bar already tracks
  (`_tree_mode`, `_no_match`, `store.scanning`, breadcrumb depth, query
  emptiness) — no new state machine.
- Keep the query input the bottom-most focusable element; the hint bar is
  non-interactive.

**Non-Goals:**

- No change to which actions exist or their key defaults.
- No live/inline query-syntax decoder in the hint bar (help overlay + no-match
  note are sufficient for discoverability).
- No config schema or CLI flag changes. New `theme` keys are additive and the
  `theme` table is already free-form string→string.
- Not switching to Textual's `Footer`.

## Decisions

### 1. Hand-rolled `#hint-bar` Static, not Textual `Footer`

`Footer` renders `Binding`s with `show=True` and offers little control over
grouping, width, or per-context content. The status bar is already a hand-rolled
`Static` rebuilt by `_refresh_status()`; the hint bar follows the same pattern: a
`Static(id="hint-bar")` placed between `#status` and `#prompt-row`, updated by a
new `_refresh_hints()` called from the same places `_refresh_status()` is called
(results applied, mode toggled, breadcrumb changed, walk finished, query
changed/cleared). Height 1, `color: $text-muted`, no background.

Alternative considered: reworking every binding to `show=True` + `Footer`.
Rejected — loses the "only the relevant few" property the spec requires and
couples key visibility to Textual's footer layout.

### 2. Context model: a small pure function

`_hint_context()` returns one of `"tree" | "results" | "no_match_scanning" |
"no_match_settled"` from existing fields. `_render_hints(context)` returns a Rich
`Text` built from `(action_id, verb)` pairs, resolving each `action_id` through
`self.config.keys` with a display map for pretty key names (`ctrl+e` → `^E`,
`tab` → `⇥`), reusing/refactoring the key-prettifying logic so `help.py` can call
it too. The `Esc` segment is appended from a separate helper
`_esc_hint_label()` that encodes the same precedence as the reworked
`action_seek_back()` (see decision 4) — single source of truth for "what does Esc
do now".

Non-`config.keys` keys shown in hints (`enter`, arrows, `esc`) are literals in
the pair table.

### 3. Mode indicator: words, not colour

`_refresh_status()` spells each mode out (`files·dirs·content`), styled `bold`
when on / `dim` when off — the same on/off treatment the old `[f d c]` used — and
appends the toggle keys resolved from `config.keys` (`^F ^_ ^T toggle`). The
learnable link to the row markers is the shared **initial letter** (`files`↔`f`,
`dirs`↔`d`, `content`↔`c`), which also matches the CLI flags. Colour is not used:
the row-marker colours are dim ANSI hues that would not survive, and (per
decision 6) the status text sits on the terminal background where `bold`/`dim`
is enough. No new `DEFAULT_THEME` keys; `results.py` is unchanged.

### 3a. Separator is a rule, not a filled band

The old `#status` was `background: $primary` — a saturated ANSI-blue fill on
which `dim` text (the inactive modes, the `/total` count) is unreadable and which
reads as harsh. Drop the fill: `#status` and `#hint-bar` render on the terminal
background, and the result area gets `border-bottom: solid $primary` (matching
the existing rule under `#preview`) so a thin blue line still fences the
status / hint / query cluster off from the results. `_refresh_status()`'s text
styles (`bold` / `dim` / `bold bright_magenta` / `bold bright_yellow`) already
read on the plain background.

### 4. Staged `Esc`

Rework `action_seek_back()` precedence to: (modal screens already handle their
own `escape`) → if query non-empty, clear it (set `QueryInput.value = ""`, which
triggers `on_input_changed` → tree view) → elif breadcrumb deep, pop → else
`exit(0)`. `_esc_hint_label()` mirrors this exactly. Update the `Quit` spec
scenarios and the README `Esc` row.

Risk: a user who reflexively double-taps `Esc` to quit now clears the query on
the first press and quits on the second — acceptable and matches the spec's
"resolve one level per press".

### 5. Act-from-detail via the existing return channel

`DetailScreen` gains `Binding`s for the editor / default-app / code actions
(keys from `config.keys`, `show=True`) whose handlers `dismiss(<action_id>)`.
`action_seek_detail()` awaits the result and, if it is a known action id,
dispatches through the same path `ActionsMixin._dispatch_menu()` uses. A short
controls line (or `show=True` bindings) is added so the pager's keys are visible.
The detail view keeps working with no selection (operates on the previewed
result).

### 6. Scanning-aware no-match

In `_apply_results()`, when `rs.state is NO_MATCH`, branch on `rs.scanning`:
scanning → `"scanning… no matches yet"` styled distinctly (e.g. the yellow used
for the scan spinner); settled → the current `no matches for 'q'` plus a second
dim line: `fuzzy match, not regex — <help key> for syntax`, and, when a plausibly
matching mode is off, `· <toggle key> toggles content`. "Plausibly matching mode
off" = content mode off (the common case: user expects a substring in file
contents).

### 8. Streaming indicator for the search pass, not just the walk

The walk spinner already exists (`_on_tick` animates `_spin`; `_refresh_status`
shows `{spin} {count}` while `store.scanning`). The gap: once the walk finishes,
a query's content-search pass can still be streaming partial snapshots
(`ResultSet.partial`) with no "working" cue.

Add a `_searching` flag: set in `_trigger_search`, cleared in `_apply_results`
when a non-partial `ResultSet` for the current generation lands (and on an empty
query). `_on_tick` now animates whenever `store.scanning or _searching`, and
`_refresh_status` shows `{spin} scanning {n}` (walking) or `{spin} searching…`
(content pass). The tick interval drops 0.3s → 0.1s so the spinner reads as
motion; `_update_prompt_glyph` swaps the `❯` for the spinner frame while
streaming and is guarded by a cached last-glyph so idle ticks do no work.

Alternative: a dedicated Textual `LoadingIndicator` overlay. Rejected — it masks
the result list, and the partial results are exactly what the user wants to see
while it streams.

### 9. Cancel the in-flight search on the keystroke, not the restart

Debounce is unchanged: `on_input_changed` stops the pending `_debounce` timer and
sets a fresh `debounce_ms`-second one, so `_trigger_search` runs only after the
query is idle. Previously an already-running search kept going through that idle
window — `exclusive=True` + the generation bump in `_trigger_search` only
cancelled it once the replacement actually started (≤150 ms later). Now
`on_input_changed` bumps `_generation` itself on any change to a non-empty query:
the running worker's `is_stale` closure (`gen != self._generation`) trips at its
next cooperative check, `publish`/`_apply_results` drop anything it returns, and
`_searching` goes false so the spinner reflects that nothing is running during
the idle wait. `_trigger_search` still bumps the generation again when it starts
the replacement.

### 7. Empty-state heading

`_render_tree()` (or a wrapper) prepends a heading `Text` before the tree body in
`#tree-body`: `root: <name> · hidden shown · .gitignore <on|off> · noise pruned ·
type to search`. Values from `self.root`, `self.config.honor_gitignore` /
session, `self.config.apply_noise_excludes`. Rebuilt on re-root/refresh (already
call sites of `_render_tree()`).

## Risks / Trade-offs

- **Vertical space**: the hint bar costs one permanent row. → It replaces
  guidance that was previously only in the vanishing placeholder; the preview is
  still dropped first on short terminals, and the hint bar is 1 line vs. the
  preview's up-to-24.
- **Hint text overflow on narrow terminals** → render hints as a single
  `Text` with `no_wrap=True, overflow="ellipsis"`; order pairs by importance so
  the first-dropped items are the least critical (`action menu` last, which is
  itself the "everything else" escape hatch).
- **Key-name prettifier drift** between hint bar and help overlay → one shared
  function, used by both; covered by a test asserting a rebound key shows in both
  places.
- **`#hint` vs `#hint-bar` id confusion** → rename the existing no-match
  `Static(id="hint")` to `id="nomatch"` in the same change to remove the
  footgun, updating `_set_middle()` and `_apply_results()`.

## Migration Plan

Pure UI change, no persisted state or config migration. Ships in one commit.
Rollback is a revert. README keybinding table and the `Esc` description are
updated in the same change; `config.example.toml` is regenerated only if
`DEFAULT_THEME` gains keys (run the AGENTS.md regen command).
