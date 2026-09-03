## Context

See proposal.md — Why for the motivation.

What shapes the approach:

- The record pane is a `Static` inside a `VerticalScroll`, updated with a Rich
  `Group` assembled by `detail.render()`. There is no line model: the pane
  knows a renderable, not a sequence of lines, so "which line is the cursor on"
  has no answer today.
- One function decides what a row's detail is (`_detail_content` → `detail.render`),
  and the full-screen reader shows the same content at a deeper level. That
  invariant is why the pane and the reader can never describe a record
  differently, and it has to survive this change.
- The table keeps focus and every viewer action is a bare key, so the pane's
  keys have to be ones the list does not use. `J`/`K` are already "detail up/
  down"; `left`/`right` are bound to the *same* two actions, so today they are
  a duplicate pair with nothing of their own to do.
- `o` is already bound, to cycling a scan's report mode. That mode only means
  anything on the Scans tab.
- `timeline.raw_text()` already finds a scan's `.nmap` sibling and falls back to
  reconstructing the report from the parsed model. The file-finding and the
  fall-back exist; what does not is cutting one host or one port out of them.
- Reading is now streamed, so a record can be re-rendered under the user while
  a batch of scans is folded in.

## Goals / Non-Goals

**Goals:**

- One place still decides what a record contains, with the pane and the reader
  both consuming it — the line model must not become a second description.
- The cursor is a property of the pane, not of a focused widget: the list keeps
  focus, as everything else in the viewer assumes.
- Cutting the raw text is a pure function of (file text, host, port), testable
  without a terminal and without a scan.
- Nothing is read from disk while the cursor moves. A file is opened when an
  entry is opened, and not before.

**Non-Goals:**

- Reconciling nmap's text against the parsed model, or parsing it at all beyond
  finding block boundaries.
- A cursor in the full-screen reader; it stays a pager, and its existing
  `left`/`right` keep stepping between list entries.
- Raw output for the service-overview and grouping records — see proposal.md.

## Decisions

### A record is a list of lines, and a line may carry an action

`detail.render()` returns `list[Line]` instead of a `Group`, where `Line` is the
renderable plus an optional "what `o` opens here". The reader keeps taking a
`Group`, assembled from the same list by one helper — so the two views still
come from one description and cannot drift.

A *line* is one renderable the record builder emitted, not one terminal row: a
long script line that wraps to three rows is one cursor stop, highlighted across
all three. That is what "line" means to someone reading the record, and it
avoids a layout-dependent cursor whose stops change when the terminal is
resized.

Alternative considered: replacing the pane with an `OptionList` and getting
selection for free. Rejected — it takes focus from the table, which the whole
key map depends on, and it would make the pane and the reader two different
kinds of thing rendering two different structures.

Alternative considered: keeping `Group` and locating the cursor by rendering to
lines and counting rows. Rejected — the answer changes with the terminal width,
so the cursor would move when the window is resized.

### `J`/`K` move the cursor, `left`/`right` jump between openable lines

`J`/`K` already mean "the pane, up and down"; they now move the cursor a line at
a time and scroll the pane only when the cursor reaches an edge, so position
becomes visible rather than implied. `left`/`right` are currently a second pair
bound to those same two actions, which makes them free: they become "previous /
next line that can be opened".

That pairing is deliberate. A record is forty lines with three openable ones in
it, so a cursor that only steps line by line would cost thirty presses to reach
the thing worth reaching. The arrows keep the shape originally asked for —
arrows move between the followable things — while `J`/`K` keep the literal line
cursor.

Alternative considered: `Tab`/`shift+Tab` for the jump. Rejected — `Tab` is
focus traversal in the terminal and in Textual, and the viewer deliberately
leaves it alone.

### `o` opens the line under the cursor, and keeps its meaning where it has one

`o` opens the entry the cursor is on. On the Scans tab a record carries no
openable line — a scan's record *is* raw output, with its own mode key — so `o`
keeps cycling the report mode there. The two contexts are disjoint by
construction rather than by precedence, and the hint bar shows whichever one is
live, so the key never silently does the other thing.

Alternative considered: `Enter`. Rejected — it drills the list, which is the
one thing the pane's keys must never do.

### The pane has two states, and `Esc` is what leaves the second

`Esc` already unwinds the viewer one state at a time — filter box, filter text,
drill-down, tab, quit. Raw output becomes the innermost of those and is checked
first, and the `Esc` hint says "back to the record" while it is showing. Coming
back restores the cursor to the entry that was opened rather than the top of the
record, because that is where the user was.

Moving the list to another row drops the raw state: the text on screen belongs
to the row that was left, and leaving it up would be the pane describing one row
while the list is on another.

### Cutting the block is a pure function over the file's text

A new `nmap/rawlog.py` holds it: given a scan's text, a host address and
optionally a port, return the lines that belong to it. nmap's output is
block-structured — `Nmap scan report for …` opens a host and the next one closes
it; a port line opens a port and its `|` / `|_` continuations belong to it — so
this is a boundary search, not a parse. A port block keeps the host's opening
lines with it, since a bare port line does not say which host it is on.

Nothing here interprets the values: the module answers "which lines", never
"what do they mean". That keeps the XML the single source of the model, which
is the viewer's standing invariant.

### The file is read when an entry is opened, never while the cursor moves

Rendering a record must not touch the disk: at engagement scale the cursor moves
between rows continuously and a `.nmap` file can be tens of megabytes. The
record therefore lists entries from what is already parsed — the scan files the
subject appears in — and the text is fetched only when `o` is pressed. The last
few files read are cached by path so that stepping between the scans of one host
does not re-read.

A file large enough that reading and cutting it would exceed the responsiveness
bound is handled in the worker the viewer already uses for long work, with the
same indicator and the same `Esc`. The size at which that becomes necessary is a
measurement, not a guess — see tasks.

### A missing output file still gets an entry

`timeline` already reconstructs a report from the parsed model when a `.nmap`
sibling is absent, and the Scans tab shows it. The same fall-back is used here,
scoped the same way and labelled as reconstructed in the heading, so the feature
does not vanish for an engagement handed over as XML alone. Labelling is not
optional: text presented as nmap's own when it was rebuilt from the parse would
defeat the only reason this exists.

## Risks / Trade-offs

- **The line model becomes a second description of a record** → `render()`
  returns the lines and one helper turns them into what the reader takes, so
  there is still exactly one builder; a test asserts the reader's content is the
  pane's content joined.
- **The cursor makes `J`/`K` feel slower than the scrolling they replace** →
  `left`/`right` jump between the lines worth reaching, and the hint bar names
  both; the pane still scrolls a screenful at a time through the reader.
- **`o` doing two things** → the two are disjoint (a scan record has no openable
  line) and the hint bar shows which is live; a test asserts the Scans tab keeps
  the report-mode meaning.
- **Cutting the wrong block** — a host whose address is a prefix of another, a
  name-and-address report line, a port number that appears inside script output
  → boundaries are matched on the line shapes nmap actually writes, and the
  fixtures reproduce each of those shapes. Real captures must never be
  committed, so the fixtures are written by hand as `.nmap` siblings of the
  existing XML fixtures and checked once by hand against a real engagement
  directory, the way `benchmarks/check_nmap_real.py` already does for the
  parser.
- **A `.nmap` from a different run than the `.xml`** → the two are written
  together by `-oA`; when the text does not mention the host, the entry says so
  rather than showing an empty block or another host's.
- **Reading a large file blocks the interface** → read on demand, cache by path,
  and move to the existing worker above a measured size.
- **A record re-rendered under the cursor while scans stream in** → the cursor
  is kept by line index and clamped, on the same principle the list's own cursor
  already follows.

## Migration Plan

No data or configuration migration: nothing is persisted and no output changes.
The `.nmap` files are read, never written. Rollback is a revert.

The one thing a user has to relearn is that `J`/`K` move a cursor rather than
scrolling, and that `left`/`right` now jump between entries rather than
duplicating `J`/`K`. Both are shown in the hint bar and the help overlay.

## Open Questions

- Whether the scans block belongs above the collections (services, scripts,
  vulnerabilities) or below them. Above keeps provenance next to the identity it
  qualifies; below keeps the record's existing reading order. Decidable once
  there is something on screen to look at, and it changes no requirement.
- Whether a host record's entry should summarise what the scan established
  (`16 ports open`) or only name the scan. The spec requires it to say what the
  scan contributed; the exact wording is a rendering choice.
