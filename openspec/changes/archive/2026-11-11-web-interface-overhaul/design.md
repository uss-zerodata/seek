## Context

See proposal.md for the motivation. The web interface is server-rendered Jinja2
with one stylesheet (`app.css`, about 210 lines, grown by accretion) and five
small scripts. Three constraints shape everything below:

- Nothing is loaded from another host, and there is no build step.
- The browser's position is its URL; lists and records are the terminal's own
  projections, and `keys.js` is the one table of keys, checked against the
  terminal's bindings by a test.
- The list form works without script (a plain GET), and `fragment=1` swaps the
  list in place with it.

The requirements of `nmap-web-frontend` still live in the unarchived change
`nmap-web-parity`. This change therefore adds a capability of its own
(`nmap-web-layout`) and modifies no existing requirement, so the two can be
archived in either order.

A specimen of the target Hosts view was reviewed and accepted:
https://claude.ai/artifact/4TsU8Ui8tMEDGMvcA1hPFW

## Goals / Non-Goals

**Goals:**

- The layout in the specimen, on every page, in both themes.
- Every key action reachable by mouse, through the handlers the keys already use.
- A stylesheet built on a small token set, so later pages cannot drift.

**Non-Goals:**

- No change to routes, API, schemas, the session or the terminal viewer.
- No new list columns, no new data in a record.
- No resizable panes, no theme switch, no saved preferences.
- No motion. Keys used a hundred times an hour must not animate.

## Decisions

**1. The shell is a CSS grid on `body`, on viewer pages only.**
`body.shell` is `height: 100dvh` with rows `auto auto minmax(0, 1fr) auto`; the
two panes are `overflow: auto`. The gallery, capture and search pages keep
normal page scroll with the same bar and tabs. This removes the record pane's
`position: sticky; top: 56px`, which was wrong whenever the header wrapped.
*Alternative:* sticky regions on a scrolling page - rejected, it is what fails
today, and it needs the header's height as a number.

**2. Toggles stay form checkboxes, styled as chips.**
`<label class="chip"><input type="checkbox" name="up">` with
`label:has(input:checked)` for the on state. They keep working without script,
keep the URL as the state, and need no ARIA. *Alternative:* `<button
aria-pressed>` driven by script - rejected, it reimplements what the form does.

**3. Action controls dispatch to the existing handler table.**
`<button data-action="export">` and one delegated click listener in
`viewer.js` that calls `handlers[action]`, the same table the key handler uses.
A control cannot then do something its key does not. Each control's `<kbd>` is
filled from `KEYS`, so the label and the binding share one source.

**4. The key bar is rendered from `KEYS` by script, with a static fallback.**
`keys.js` gains the order of hints and, per action, an optional predicate over
the view (`tab`, whether a path is open). The template ships the navigation
hints as plain HTML so the bar is not empty without script. Fitting follows the
terminal's `_fit_hints` rule: navigation, `?` and Esc are kept, the rest drop in
order - done with a `ResizeObserver` hiding trailing items, not by clipping.
*Alternative:* render hints on the server - rejected, the key table lives in
`keys.js` and a second copy in Python is the drift the parity test exists to
prevent.

**5. Run and connection state move to fixed places.**
Running scans stay in the top bar (global). Connection state and the loaded
counts go to the key bar's trailing end. `events.js` keeps `setLive`; a second
element takes the session line. Both are `aria-live="polite"`.

**6. Tokens are named by meaning, and the stylesheet is rewritten in one pass.**
`--ground --pane --inset` (surfaces), `--ink --ink-2 --ink-3` (text),
`--rule --rule-strong`, `--key --key-tint --on-key` (accent), `--open
--filtered --closed --mark` (state). Spacing is multiples of 4 px; radii are
4/6/8; type is 11 (label), 12.5 (data), 13 (body), 14 (title). Depth is borders
only - shadows read badly in the dark theme and the terminal has none. The
`.c-*` and `.b .d .i .u` classes that `web/record.py` emits keep their names.
*Alternative:* restyle rule by rule - rejected, the file has no system to
extend and half its rules would be touched anyway.

**7. Faces are system stacks.**
`ui-sans-serif, system-ui` for controls and labels, `ui-monospace` with named
fallbacks for data. Nothing is bundled. *Alternative:* ship a monospace WOFF2 in
`static/` - deferred, see Open Questions.

**8. Row thumbnails shrink to fit the row.**
36x22 px in a 28 px row, set by one token. A row with thumbnails is then no
taller than one without, which keeps the cursor's page step even.

**9. Dialogs share one frame.**
`dialog()` in `actions.js` already builds every dialog; the shared title, body,
button row and "Esc leaves" line become its markup rather than each caller's.

**10. A record's views are derived in the browser, from the record it already has.**
The views of a record are the record and nmap's text - one tab, opening the
first `a.opens[data-raw]` link in its HTML (the links `web/record.py` already
writes); on the Scans tab they are the three report modes. A tab per scan was
tried and dropped: on a host seen in many scans the tabs outgrew the header,
and the record's lines and `←`/`→` in the text already reach each scan. No endpoint
and no schema change. `o` keeps its first meaning - open what the cursor is on -
and otherwise steps views; the old mode-cycling function is gone, the tabs say
the mode. *Alternative:* have the API list a record's views - rejected, the
record already carries them.

**11. The capture page is a grid: picture, facts, folded lists.**
`<details>` for headers, cookies, console and network - native folding, no
script. The facts column is sticky beside a tall screenshot. No `max-width`:
from 1600 px the lists become a third column instead of the page leaving a
margin unused. Row thumbnails stay
36x22 (confirmed by the user).

## Risks / Trade-offs

- [Tests pin markup that moves] → move assertions with the markup in the same
  task; no test is deleted without a replacement.
- [A pane that scrolls breaks the browser's own "scroll to top", and page-find
  jumps inside a pane] → accepted; it is what the terminal does, and `g`/`G`
  remain.
- [Monospace cells show fewer characters per column] → the ellipsis rule and the
  hover title already cover it; the record shows the whole value.
- [36 px thumbnails are too small to recognise a page] → the size is one token;
  see Open Questions.
- [`:has()` in old browsers] → already relied on by the gallery's stacks.
- [The rewrite regresses contrast fixed earlier] → a test computes contrast for
  every token pair and every record colour in both themes.

## Migration Plan

Four steps, each shippable and each leaving the suite green: shell and tokens;
toolbar, table and key bar; record header; gallery, capture, search and dialogs.
Rollback is reverting the step. No data or URL migration.

## Resolved Questions

- **No bundled monospace face.** The system's monospace font renders the pages
  consistently in both themes at 1440, 1000 and 400 px, so 100 kB of package
  size buys nothing. Decided by the user.
- **`/` is the Hosts tab, and the gallery is `/gallery`.** Decided by the user,
  accepting that a bookmark of plain `/` now opens the hosts. A `/` link that
  carries any gallery parameter (`q`, `sort`, `group`, `address`, `port` and the
  others) is redirected to `/gallery` with its query unchanged, so a filtered or
  grouped gallery bookmark still works. Every gallery link, the tab, `i` and the
  search's "all" link point at `/gallery` directly.
