## 1. The empty state

- [x] 1.1 `#list-area` container carries the region rule; the table's own `border-bottom` moves to it.
- [x] 1.2 `#empty` Static, hidden by default, shown with `-shown`; the table takes `-empty` and shrinks to its headers.
- [x] 1.3 `_refresh_empty`: headline and recovery hint chosen from the cause — a filter (with the count behind it), the reachable-only list, a drill-down, or a scan with no hosts.
- [x] 1.4 The detail pane hides while the list is empty.
- [x] 1.5 Tests: the message and its recovery line; the headers stay and the region stays fenced; the state clears when rows return.

## 2. The modal

- [x] 2.1 `ChoiceScreen` rebuilt on `OptionList`, one line per choice, `choose(id)` for callers that pick by name.
- [x] 2.2 Key hints on `ChoiceScreen`, `ActionMenuScreen`, `PromptScreen` and `MultiChoiceScreen`.
- [x] 2.3 Update the viewer's and the search session's tests to choose by keyboard rather than clicking a button id.
- [x] 2.4 Tests: six recipes fit a 24-row terminal with the last reachable; the list moves with the arrow keys; the modal states how to cancel.

## 3. The hint bar

- [x] 3.1 `_fit_hints(items, width)`: keep the two navigation hints, `?` and `Esc`; fill the rest in order; report whether anything was dropped.
- [x] 3.2 `_refresh_status` uses it and appends `…` when something was dropped.
- [x] 3.3 Tests: a narrow terminal keeps navigation and `?` and shows `…`; a wide one shows everything with no `…`; the picker keeps the must-keeps.

## 4. Finalisation

- [x] 4.1 `uv run ruff check` clean.
- [x] 4.2 `uv run pytest -q` green.
- [x] 4.3 `openspec validate nmap-viewer-states --strict` passes.
- [x] 4.4 README and AGENTS.md record the three traps.
