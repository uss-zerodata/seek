## Why

The viewer's filter is fuzzy text plus address ranges. That answers "which rows
mention nginx", but not the questions a review actually asks:

- which hosts have 22 **open** (the text `22` also matches `10.0.0.22`, port
  `2222` and a version string);
- which hosts run nginx **as the product on an http service**, rather than
  mentioning nginx anywhere in a script's output;
- which hosts have `ssh` **or** `telnet`, and which have http but **no**
  Apache.

Fuzzy text cannot express a port's state at all, cannot tie two facts to the
same port, and has no OR. Today the answer is to scroll, or to export and grep.

## What Changes

- **Field terms** in the filter box, tested against the model rather than the
  row's text:
  - `open:22`, `open:80/tcp` — the port was found open;
  - `closed:443`, `closed:443/tcp` — the scan saw the port and it was *not*
    open (closed, filtered, `open|filtered`); a port never scanned matches
    neither `open:` nor `closed:`;
  - `service:nginx`, `service:mysql` — the service name;
  - `product:nginx`, `product:mysql` — the detected product.

  The port-state keys are deliberately `open:`/`closed:`, not `up:`/`down:`:
  "up" already means the host rule behind `u`, and one word must not mean two
  things.
- **Logical operators**: uppercase `AND`, `OR`, `NOT`, the symbols `|` (OR) and
  `!` (NOT, as today), and parentheses. A space still means AND. Lowercase
  `and`/`or`/`not` stay ordinary search words.
- **Field terms joined by AND describe the same port.** `service:http AND
  product:nginx` is a host with an http service whose product is nginx, not a
  host with http somewhere and nginx somewhere else. `NOT` means *none* of the
  host's ports matches: `NOT service:ssh` is a host without ssh.
- **Everything that works today keeps working, unchanged**: fuzzy terms and
  their grammar, highlighting, address ranges and their union, negated ranges.
  A filter using none of the new syntax is evaluated exactly as before, by the
  same code path.
- The status line shows how a structured filter was understood, and a term it
  could not use (an unknown port value, an empty field while typing) is named
  there rather than silently emptying the list.

Non-goals: fields beyond these four (os, version, vulnerabilities, names, host
state — deferred at the user's request); saving queries; the search session's
query grammar (the file search is untouched).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `nmap-scan-viewer`: the filter gains field terms, logical operators and
  grouping, with same-port semantics for AND-joined field terms.

## Impact

- `src/seek/nmap/filtering.py`: a small recursive-descent parser producing an
  expression tree, and its evaluation against a row's records. The existing
  `FilterSpec` path stays for filters without the new syntax.
- `src/seek/tui/nmap/app.py`: `_narrow` evaluates the tree when there is one;
  highlighting takes the positive fuzzy terms; the status line describes the
  expression.
- `src/seek/tui/nmap/help.py`, README: the syntax.
- Tests: a parser suite (precedence, grouping, leniency while typing) and
  evaluation against the existing fixtures.
- No new dependencies. Performance: a filter keystroke over 24 000 host rows
  must stay interactive — measured with `benchmarks/drive_nmap.py`.
