## Context

See proposal.md — Why. Three constraints shaped the fixes:

- The region dividers are thin rules on the *bottom* of the upper element, never
  fills (ANSI themes collapse background shades). The rule sat on the
  `DataTable`, so a table that shrinks would have carried the rule up with it.
- `ChoiceScreen` is shared with the search session's export flow, so a change to
  it changes two callers.
- The hint bar is one `Static`; Rich clips it, and clipping is what dropped the
  keys that mattered.

## Goals / Non-Goals

**Goals:** an empty list reads as a designed state; every modal choice is
reachable at 24 rows; the hint bar's contents are chosen, not truncated.

**Non-Goals:** the narrow-width column strategy (columns still shrink to a
6-cell floor below ~60 columns rather than dropping by priority), a
minimum-size message, an ASCII fallback for the Unicode glyphs, and the marker
column's gutter width. Each is real and each is its own change.

## Decisions

### The region rule moves from the table to a `#list-area` container

The table and the empty message live in one container that carries the
`border-bottom`. The table takes `1fr` normally and `auto` when empty (shrinking
to its headers), so the message sits directly beneath the headers and inside the
fenced region rather than below its divider.

*Alternative rejected:* an overlay layer over the table. More CSS, and the
headers would have been covered — they are the part worth keeping.

### `ChoiceScreen` becomes an `OptionList`

The codebase already had the right pattern in `ActionMenuScreen`; `ChoiceScreen`
was the odd one out. One line per choice fits six recipes in twelve rows,
scrolls past that, and moves with the arrow keys like every list in the app
rather than with `Tab` between buttons. `choose(id)` dismisses by id for the
palette and for tests, which no longer click a button that no longer exists.

### `_fit_hints` picks, then admits

Must-keep is `{first two} ∪ {?, Esc}`; the rest are added in width order until
the line is full, leaving four cells for the `…`. The alternative — shrinking
the verbs, or paging the bar — either makes the hints unreadable or hides them
behind another interaction.

## Risks / Trade-offs

- **Two callers of `ChoiceScreen`** → the search session's export chooser
  changes too; its test now picks by keyboard, and it gains the same fit and key
  hints.
- **The table's height changes when the list empties** → only between "rows" and
  "headers only"; the container's height is fixed, so the divider does not move.
- **`_fit_hints` runs on every status refresh** → it is a handful of `cell_len`
  calls over at most fourteen items, on the same path that already rebuilds the
  status line.
