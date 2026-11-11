## 1. Tokens and shell

- [x] 1.1 Rewrite `static/app.css` around the token set in design.md §6 (surfaces, ink, rules, accent, state; 4 px spacing; radii 4/6/8; type 11/12.5/13/14), light and dark, keeping the `.c-*` and `.b .d .i .u .s .rv` record classes
- [x] 1.2 `templates/base.html`: top bar (name, global search, run state, vulndb, `?`), tab strip on one scrolling line, `<main>`, key bar slot; `body.shell` only where a page asks for it
- [x] 1.3 Scroll the active tab into view on load (`viewer.js` or `app.js`, a few lines)
- [x] 1.4 Shell grid: `100dvh`, two `overflow: auto` panes, sticky `thead`; remove the record pane's sticky offset
- [x] 1.5 Narrow layout: one column, page scroll, no sideways scroll at 400 px
- [x] 1.6 Test: token pairs and all sixteen record colours reach 4.5:1 in both themes (parse `app.css`, compute contrast)
- [x] 1.7 Fix `test_web*.py` assertions on moved markup; `uv run ruff check`, full suite green

## 2. List toolbar, table, key bar

- [x] 2.1 `templates/overview.html`: list header with drill path (last step the `h1`), counts (shown, total, marked), filter, the "how it was read" line
- [x] 2.2 Toggles as chip-styled checkboxes, offered only where they apply, each with its `<kbd>`
- [x] 2.3 Action controls `Mark`, `Export`, `Scan` as `button[data-action]`; one delegated listener in `viewer.js` calling `handlers[action]`; `<kbd>` text filled from `KEYS`
- [x] 2.4 Disabled action controls show their reason beside them (scan without nmap, capture without gowitness)
- [x] 2.5 Table: 28 px rows, monospace tabular cells, selection tint plus accent edge, mark column, hover state distinct from both
- [x] 2.6 Row thumbnails at the `--thumb` size, `+N` link, failed-capture sign with its accessible name
- [x] 2.7 `keys.js`: hint order and per-view predicates; key bar rendered from `KEYS`, static navigation hints in the template as fallback
- [x] 2.8 Key bar fitting with `ResizeObserver`: keep navigation, `?`, Esc; drop the rest in order
- [x] 2.9 `events.js`: run state to the top bar, connection and loaded counts to the key bar; lost connection stated in words
- [x] 2.10 Tests: each toggle and action control exists on the views it applies to and not elsewhere; every `data-action` is a key in `KEYS`; `test_every_terminal_key_has_a_browser_key` still passes; the 18-rows-in-560-px rule as a CSS-value check

## 3. Record pane

- [x] 3.1 Record header: title, `Text`, `Full` and search controls with their keys, built in `showRecord` and in the server-rendered first paint
- [x] 3.2 Full-width mode keeps the page heading and the key bar; the control toggles back
- [x] 3.3 Cursor line and link styling as in the specimen; screenshot under its URL at the record's thumbnail size
- [x] 3.4 Empty state: how to select a row
- [x] 3.5 Tests: first paint carries the header and its controls; the capture image follows the last line about its URL

## 4. Gallery, capture, search, dialogs

- [x] 4.1 Gallery: controls from the shared set; grouping as chips with the current one on; cards restyled with tokens, borders only
- [x] 4.2 Capture page and search page restyled with tokens; the facts list and pairs tables on the type scale
- [x] 4.3 `dialog()` in `actions.js` owns the frame: title, body, button row with one primary, cancel, "Esc leaves"; callers pass content only
- [x] 4.4 Header search dropdown restyled; `aria-expanded` and `aria-activedescendant` on the input
- [x] 4.5 Tests: every dialog has a title, one primary and a cancel; gallery grouping marks the current choice

## 5. Record views and the capture page

- [x] 5.1 Record header: view tabs (`#record-views`) and a next-view control, both hidden until the script finds a second view
- [x] 5.2 `viewer.js`: `views()` from the record's raw links or the report modes; tab click opens a view; `o` opens the cursor's link, else the next view
- [x] 5.3 `actions.js`: `setMode` and `MODE_LABELS` replace `cycleMode`; `keys.js` help text for `o`
- [x] 5.4 `templates/capture.html`: heading with status and title, action chips, picture beside grouped facts, folded lists, the no-picture state
- [x] 5.5 Tests: views hidden by default and tied to `o`; the capture page's order, actions and failed state
- [x] 5.6 Record views: nmap's text is one tab, not one per scan
- [x] 5.7 Capture page fills a wide window: lists as a third column from 1600 px
- [x] 5.8 New-scan dialog lists the gowitness capture among the presets (disabled with its reason when unavailable; URL count as its review)

## 6. Verify and document

- [x] 6.1 Run `seek nmap serve` on the fixtures and on `benchmarks/gen_nmap_corpus.py` output; check every tab, the gallery and a capture page in light and dark, at 1440, 1000 and 400 px, by keyboard only and by mouse only
- [x] 6.2 Resolve the open questions in design.md with the user (bundled face, landing page; thumbnail size is settled at 36x22)
- [x] 6.3 `AGENTS.md`: add the web layout rules (shell, tokens, controls dispatch to `handlers`, key bar from `KEYS`); correct the OpenSpec section's stale change path
- [x] 6.4 `openspec validate web-interface-overhaul --strict`; `uv run ruff check`; full suite green
- [x] 6.5 `/` redirects to the Hosts tab and the gallery moves to `/gallery`; a `/` link with gallery parameters redirects there unchanged; every gallery link, the tab, `i` and the search's "all" link use `/gallery`; verified by `test_the_front_page_is_the_host_list_and_old_gallery_links_still_work` and the browser checks
