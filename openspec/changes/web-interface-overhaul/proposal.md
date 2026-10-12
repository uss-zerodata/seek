## Why

The web interface shows the right data but is hard to work in. Its header wraps
into several rows, every text is one size, rows are tall, and mark, export, scan
and the list toggles exist only as keys behind `?`. A reader with a mouse cannot
find them, and a reader with twenty thousand hosts sees too few of them at once.

## What Changes

- A fixed page shell: a top bar, a tab strip that scrolls instead of wrapping,
  a list pane and a record pane that scroll on their own, and a key bar. Column
  headers, the filter and the record's title stay on screen.
- A toolbar beside the list filter: the drill path and row count, the list
  toggles, export, mark and scan as visible controls, each showing its key.
- A dense table: 28 px rows, monospace data cells, a sticky header, selection
  shown by a tint and an accent edge.
- A record header with the record's title and its actions (nmap's text, full
  width, search).
- A key bar along the bottom that shows the keys for the current view and the
  session's state, as the terminal viewer's hint bar does.
- Screenshots stay in the data: thumbnails in the row, the picture under its
  URL in the record, a failed capture marked as failed.
- One control set (button, chip, input, dialog) and one token set (colour named
  by meaning, a 4 px spacing base, one type scale) for the viewer, the gallery,
  the capture page, the search page and every dialog.
- One accent colour, teal, for position and focus. Green, amber and red only
  state a port's or a product's condition; magenta is a mark.

Not changing: the URLs, the API, the keys, the data in any list or record, and
the rule that nothing is loaded from another host. `/` stays the gallery.

## Capabilities

### New Capabilities
- `nmap-web-layout`: how the web interface is laid out and operated - the page
  shell, the list toolbar and its visible actions, table density, the record
  header, the key bar, where screenshots appear, the shared controls, colour
  and legibility in both themes, and behaviour on a narrow screen.

### Modified Capabilities

None. The gallery, host, service and capture requirements of
`nmap-web-interface` keep their behaviour; this change restyles them.

## Impact

- `src/seek/web/static/app.css` (rewritten around tokens), `templates/*.html`,
  `static/js/viewer.js`, `actions.js`, `events.js`, `search.js`, `app.js`.
- No route, schema, API or Python behaviour changes; `pages/routes.py` may pass
  one or two more values to templates (the key hints for a view).
- Tests: `test_web*.py` assertions on markup that moves; new tests for the
  toolbar controls and the key bar; `test_every_terminal_key_has_a_browser_key`
  keeps holding.
- No new runtime dependency, no build step, no font or script from a CDN.
- `AGENTS.md` gains the web layout rules; its OpenSpec section names a change
  directory that no longer exists and is corrected in passing.
