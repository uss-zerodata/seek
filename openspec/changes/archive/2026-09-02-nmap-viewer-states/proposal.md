## Why

A TUI design review of the running viewer (screenshots at 46–200 columns) found
three states that read as broken rather than designed:

- A filter that matches nothing shows column headers over blank space. It is
  indistinguishable from a scan that found nothing, and nothing on screen says
  how to get back — only a dim `0 rows` in the status line.
- The export chooser stacks six three-line buttons: more than twenty rows, no
  scrolling, so on a 24-row terminal the last choice (`custom…`, the field
  picker) is off the bottom and unreachable. No modal says that `Esc` cancels.
- The hint bar is clipped to the terminal width, mid-word, with no ellipsis. It
  drops whatever comes last, which is `m mark`, `x export`, `? help` and the
  command palette — the least guessable keys, and the door to all the others.

## What Changes

- **The empty list explains itself.** The column headers stay, the table shrinks
  to them, and a headline plus a way out appears underneath — worded from the
  cause (a filter, a reachable-only list, a drill-down, an empty scan). The
  detail pane hides while the list is empty, so the message has the region.
- **Choices are a list, not a stack of buttons.** One line per choice, scrolling
  when needed, moving with the same keys as every other list, and every modal
  states how to choose and how to cancel.
- **The hint bar chooses what to drop.** The two navigation hints, `?` and `Esc`
  are kept whatever the width; the rest fill the space in order; a `…` admits
  when something did not fit.

## Capabilities

### New Capabilities

None — these are states the viewer already enters, presented properly.

### Modified Capabilities

- `nmap-scan-viewer`: **The list is the thing being operated on** gains the
  empty-list requirement and the modal contract. The capability is specified by
  the unarchived `nmap-scan-viewer` change and amended by
  `nmap-statistics-rework` and `nmap-selective-export`, so this delta is written
  against that spec and archives after them.

## Impact

- `src/seek/tui/menu.py` — `ChoiceScreen` rebuilt on `OptionList`; key hints on
  every modal. Shared with the search session, whose export chooser gains the
  same treatment.
- `src/seek/tui/nmap/app.py` — `#list-area` carries the region rule, `#empty`
  holds the message, `_refresh_empty`, `_fit_hints`.
- `tests/test_nmap_viewer.py`, `tests/test_tui.py` — the modal is chosen by
  keyboard rather than by clicking a button id.
- README, AGENTS.md.
