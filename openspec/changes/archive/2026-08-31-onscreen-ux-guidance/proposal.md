## Why

`seek` keeps the query box focused at all times, so every action lives behind a
modifier hotkey. Today none of those keys are shown on screen: all bindings are
`show=False`, there is no footer, and the only guidance — a placeholder that
reads `… (? for help)` — disappears the moment the user types. At the exact point
where the user has results and wants to act on them, the interface tells them
nothing. The stated product goal is that the app never requires reading a manual
or memorising hotkeys: every piece of information the user needs must be conveyed
by the design or displayed at the moment it is needed. Seven concrete gaps break
that promise.

## What Changes

- **Persistent, context-aware hint bar.** A new one-line bar directly below the
  query input shows the few keybindings relevant to the current context (tree
  view, result list, no-match, detail view), with the labels resolved from the
  user's configured keys so rebindings stay accurate.
- **Self-describing mode indicator.** The cryptic `[f d c]` band becomes a
  labelled indicator that names each mode (`files·dirs·content`), shows which are
  on/off, and shows the key that toggles them. Each mode word starts with the
  same letter used as that kind's row marker, so the link between a `c` row and
  content mode is visible.
- **Query syntax on screen.** The help overlay gains a "Query syntax" section
  (AND terms, `'exact`, `^prefix`, `suffix$`, `!negate`, smart-case) — currently
  the grammar is documented nowhere in the UI. The no-match state gains a rescue
  line pointing out that the query box is fuzzy, not a regex.
- **Act from the detail view.** `Enter` is labelled as "view" so the pager is not
  a surprise, the detail view shows its own scroll/act controls, and open-in
  actions can be triggered from inside it (the return channel that
  `DetailScreen` already declares but never uses).
- **Predictable `Esc`.** With a non-empty query, the first `Esc` clears the query
  (returning to the tree view) and only a second `Esc` pops a breadcrumb or
  quits. The hint bar states which `Esc` behaviour is currently active.
- **Honest scanning state.** While the initial walk is still running, a query
  with no current matches shows a "no matches yet — still scanning" state that is
  visually distinct from a settled "no matches", instead of asserting a
  potentially premature negative.
- **Streaming indicator.** An animated "working" cue shows whenever results are
  still arriving — not only during the initial walk (as before) but also during a
  query's content-search pass. It appears at the query prompt (the `❯` glyph
  animates) and on the status line (`scanning 12,345` / `searching…`), and clears
  when the result set settles.
- **Search cancelled on the keystroke.** A query change now invalidates any
  in-flight search immediately, instead of letting it run for the 150 ms debounce
  window until the replacement search supersedes it.
- **Oriented empty state.** The empty-query tree view gains a heading line naming
  the current root and the non-obvious walk semantics (hidden files shown,
  `.gitignore` off, noise dirs pruned) plus a "start typing to search" prompt.

## Capabilities

### New Capabilities
- `onscreen-guidance`: A persistent, context-sensitive hint bar that surfaces the
  keybindings and `Esc` behaviour relevant to the user's current context, so
  actions are discoverable without opening help or reading docs.

### Modified Capabilities
- `fuzzy-search-engine`: "Cancellable recomputation" is tightened — an in-flight
  search is abandoned the moment the query text changes, not only when the
  debounced replacement recomputation begins.
- `interactive-tui`: The status bar's mode indicator becomes self-describing; the
  help overlay documents the query syntax; the no-match state distinguishes
  "still scanning" from "settled" and points users away from regex expectations;
  the empty-query tree view gains an orientation heading; the full-screen detail
  view exposes its controls and can trigger open actions; `Esc` clears a
  non-empty query before it pops a breadcrumb or quits.

## Impact

- Code: `src/seek/tui/app.py` (new `#hint-bar` widget in `compose`, a
  `_refresh_hints` sibling to `_refresh_status`, staged `action_seek_back`,
  scanning-aware `_apply_results`, empty-state heading), `src/seek/tui/help.py`
  (query-syntax section, grouped layout), `src/seek/tui/detail.py` (visible
  controls, action return values), `src/seek/tui/results.py` /
  `src/seek/config.py` (`DEFAULT_THEME` keys shared by markers and the mode
  indicator).
- Behaviour spec: `openspec/changes/onscreen-ux-guidance/specs/` — one new
  capability spec and one delta against `interactive-tui`.
- Docs: `README.md` keybinding section stays accurate; the placeholder text and
  `Esc` description are updated.
- No new runtime dependencies. No CLI flag or config-schema changes (theme keys
  are additive and already free-form).
