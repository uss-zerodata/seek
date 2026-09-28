## 1. Parser (no terminal)

- [x] 1.1 Tokeniser: whitespace, `(`, `)`, free-standing `|`, leading `!`; uppercase `AND`/`OR`/`NOT` as operators, everything else a term
- [x] 1.2 Recursive-descent parser for the grammar in design.md D2 (NOT > AND > OR, adjacency is AND), producing a small node tree (`And`, `Or`, `Not`, `Fuzzy`, `Range`, `Field`)
- [x] 1.3 Leniency: imply missing `)`, drop a trailing/dangling operator, ignore `()`, a field with no value and an invalid port value; collect what was ignored
- [x] 1.4 Leaves: fuzzy terms via the existing `parse_query` (one term each); ranges via `_as_network`; fields `open:`/`closed:` (`PORT[/PROTO]`) and `service:`/`product:` (substring, `^`/`$` anchors); unknown `key:` stays fuzzy
- [x] 1.5 `parse_filter` chooses the path: none of the new syntax → today's `FilterSpec` exactly; otherwise `FilterSpec.expr` set, `query` = the positive fuzzy leaves for highlighting
- [x] 1.6 `describe()` re-prints a tree with explicit operators and parentheses, plus the ignored terms
- [x] 1.7 Parser tests: precedence, grouping, `!`/`NOT`/`|`/`OR` equivalence, lowercase words stay text, unknown keys stay text, every leniency case, describe round-trip

## 2. Evaluation (no terminal)

- [x] 2.1 `matches(spec, text, addresses, records=())`: plain path unchanged; tree path evaluates against the row
- [x] 2.2 The services a row offers: a record's own service, else all of its host's services (closed and filtered included)
- [x] 2.3 AND node: direct field children form one clause satisfied by a single service; positive direct range children form one union leaf; other children on their own
- [x] 2.4 OR any child; NOT negates the child evaluated on the row ("none of the ports")
- [x] 2.5 Tests against the fixtures: `open:`/`closed:` incl. never-scanned ports and `open|filtered`; same-port AND; `NOT service:ssh`; grouping; ranges inside a structured query keep their union; service-group and bucket rows match by any member pair
- [x] 2.6 Equivalence test: a corpus of plain queries (fuzzy, anchors, negation, ranges) gives the same rows through the plain path and forced through the tree

## 3. The viewer

- [x] 3.1 `_narrow` passes `r.records`; highlighting uses the positive fuzzy leaves
- [x] 3.2 The status line shows the understood expression and ignored terms for a structured filter; the range summary stays for the plain path
- [x] 3.3 Help overlay: the field terms, the operators, same-port AND, NOT as "none"
- [x] 3.4 TUI tests: `open:22` on the host list, `service:ssh OR open:80` on a port list, an unclosed parenthesis still lists rows, `service:` alone keeps the list, highlighting under OR

## 4. Finish

- [x] 4.1 Timing: a structured filter over the 24 200-host benchmark corpus (`benchmarks/gen_nmap_corpus.py`, `drive_nmap.py`) stays within the plain filter's time; record the numbers in the benchmark docstring
- [x] 4.2 README: the syntax with the examples from the proposal; AGENTS.md: the two-path rule and the same-port / NOT-means-none semantics
- [x] 4.3 `uv run ruff check`, `uv run pytest -q`, `openspec validate nmap-structured-queries --strict`
