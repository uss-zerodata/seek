## Context

`nmap/filtering.py` turns the filter box into a `FilterSpec`: address-range
terms (`include` as a union, `exclude` subtracted) plus every other token handed
to the search engine's fzf-style `parse_query` and scored with `match_score`
against `Row.text`. `NmapApp._narrow` calls `filtering.matches(spec, r.text,
r.addresses)` for every row on every keystroke, and `_fill` highlights with
`spec.query`.

Every row already carries `Row.records`: `Record(host)` for a host row,
`Record(host, service)` for a port, and every `(host, service)` pair for a
service group or a grouping bucket. That is exactly what field terms need to be
tested against, and it exists for marking and export already.

## Goals / Non-Goals

**Goals:**

- `open:`, `closed:`, `service:`, `product:` field terms.
- `AND` / `OR` / `NOT`, `|`, `!`, parentheses; space is AND.
- AND-joined field terms describe one port.
- Zero behaviour change, and zero cost, for filters that use none of it.

**Non-Goals:**

- More fields (deferred), query history or saved queries, the file search.

## Decisions

### D1. Two paths, chosen by the text

`parse_filter` looks for the new syntax: a token that is a known field
(`open:`, `closed:`, `service:`, `product:` — case-insensitive key), an
uppercase `AND`/`OR`/`NOT`, `|`, or a parenthesis. None present: the current
`FilterSpec` is built by the current code, and nothing else changes. Present:
`FilterSpec.expr` holds an expression tree, and `matches` evaluates it.

Why not always build a tree: the plain path is the one tuned for 24 000 rows
per keystroke, and its union-of-ranges rule is a behaviour users rely on.
Keeping it byte-for-byte is cheaper than proving a general evaluator equal to it.

An unknown `key:` (`http://x`, `a:b`) is not a field: it stays a fuzzy term, so
pasting a URL still searches.

### D2. Grammar

```
expr    := or
or      := and ( ("OR" | "|") and )*
and     := unary ( ["AND"] unary )*          -- adjacency is AND
unary   := ("NOT" | "!") unary | primary
primary := "(" expr ")" | field | range | fuzzy
```

Tokenising splits on whitespace and around `(`, `)` and a free-standing `|`.
`!` directly before a term or `(` is NOT, as it is today (`!ssh`, `!(…)`).
Precedence: NOT > AND > OR, the usual one. Operators are keywords only in
uppercase; `and`, `or`, `not` are search words.

**Lenient while typing.** The filter re-evaluates on every keystroke, so a
half-typed query is the normal case: a missing `)` is closed at the end; a
dangling operator (`ssh OR`) is dropped; `()` and a field with no value
(`service:`) are ignored rather than matching nothing. Whatever was dropped is
named in the status line.

### D3. Leaves

- **fuzzy** — one token of today's grammar (`'x`, `^x`, `x$`, smart-case),
  scored with `match_score` against `Row.text`, as now.
- **range** — a CIDR or complete address, tested against `Row.addresses`.
  Several *positive* ranges that are direct children of one AND group are
  folded into a single union leaf, which keeps today's
  `10.0.0.0/8 192.168.0.0/16 apache` meaning inside a structured query.
- **field** — `open:` / `closed:` take `PORT` or `PORT/PROTO` (no protocol:
  any); a non-numeric port is invalid (reported, ignored). `service:` /
  `product:` match the value as a case-insensitive substring
  (`service:http` finds `http`, `https`, `http-proxy`, which is what people
  mean; `^`/`$` anchor like the fuzzy grammar, `service:^http$` is exactly
  http).

Per service `s`:

| term | true when |
|---|---|
| `open:P[/T]` | `s.port == P` (and protocol) and `s.state == "open"` |
| `closed:P[/T]` | same port, and state is anything *other* than open |
| `service:V` | `s.name` matches V |
| `product:V` | `s.product` matches V |

### D4. Same-port semantics

The services a row offers: for each record, `[record.service]` when it has one,
otherwise **all** of `record.host.services` (closed and filtered included, or
`closed:` could never match).

Evaluation of the tree for a row:

- **field leaf** alone: some service satisfies it.
- **AND node**: its direct field-leaf children form one *clause*, true when a
  *single* service satisfies all of them; the other children (fuzzy, range,
  OR/NOT subtrees) are evaluated on their own; the node is the conjunction.
  So `service:http product:nginx` needs one port that is both, while
  `service:http 10.0.0.0/8` is simply both conditions on the row.
- **OR node**: any child.
- **NOT node**: the negation of its child evaluated on the row — so
  `NOT service:ssh` is "no port is ssh", and `NOT (service:http product:iis)`
  is "no port is http served by IIS".

This is the one place with a real alternative: evaluating NOT per port would
make `NOT service:ssh` match any host that has some other service, which is
never what is meant. The rule above keeps "AND ties to one port" and makes NOT
read as "none". For a single-port row (a host's port list, a grouping's hosts)
both readings coincide.

A service-group or bucket row matches when some member pair does — the same
existential rule, over its pairs.

### D5. Highlighting and status

Highlighting uses a `ParsedQuery` of the *positive* fuzzy leaves (those under
an even number of NOTs); a negated term has nothing to highlight. The status
line shows the expression as understood, re-printed from the tree with explicit
operators and parentheses (`service:http AND (open:22 OR open:2222)`), plus any
dropped or invalid term. The range summary (`in …` / `not in …`) keeps working
for the plain path.

### D6. Cost

Parsing is once per keystroke. Evaluation short-circuits, fuzzy leaves reuse the
compiled term, and a field clause over a host walks its services once. A host
row at engagement scale has a few dozen services at most. The target: a
structured keystroke over 24 000 hosts stays within the plain path's budget
(checked with `benchmarks/drive_nmap.py` and a timing test at fixture scale).

## Risks / Trade-offs

- **Reserved words.** Uppercase `AND`/`OR`/`NOT` cannot be searched for as
  text. → Lowercase still can, and smart-case makes lowercase match uppercase
  text anyway; `'AND` (quoted exact) is a fuzzy term, not an operator.
- **`|` in a search.** A free-standing `|` is OR; inside a token (`a|b`) it is
  text. → Nothing in scan output is plausibly searched for as a lone `|`.
- **Two evaluators.** The plain path and the tree could drift. → Tests run the
  same plain queries through both and require equal results.

## Migration Plan

None. Nothing is persisted.
