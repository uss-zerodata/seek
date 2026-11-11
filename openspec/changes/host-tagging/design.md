## Context

See proposal.md for the motivation and the specs in this change for the
behaviour. This section lists only the current state that shapes the design.

- **Model.** `nmap/models.py` holds `Host` (keyed by `address` in
  `merge.Accumulator`), `Service` (keyed by `(protocol, port)`), `ScriptResult`
  with a structured `data` tree, `ScanFile` (one parsed file, with `label`) and
  `ScanSet` (merged hosts plus `files`). `Host.sources` holds the labels of the
  files a host came from. `parse.py` reads with `iterparse` and ignores
  `<scaninfo>` and the `timedout` attribute, so seek does not know today which
  ports a scan probed.
- **Discovery.** `merge._scans_below` walks every opened folder once, skips
  dot folders and symlinked folders, and sniffs `.xml` files.
- **Session projections.** `Session.inventory()` is the pattern to follow. It
  is a projection of the model and the captures, cached on
  `(scans identity, shots.generation)`. It is built in the rows worker above
  `INLINE_INVENTORY_HOSTS`, and inline below it. `Session.captures_by_service()`
  joins captures to `(address, protocol, port)`. `Session.row_text()` adds
  capture words to a row's filter text and is cached per row.
- **Filter.** `filtering.py` has a tuned plain path and an expression path.
  Field terms under one AND describe one port. A multi-record row is reduced to
  sample ports keyed by `(port, protocol, state, name, product)`. AGENTS.md
  requires a new field to extend `Field.test` and that sample key together.
- **Front ends.** One `Session` behind the terminal viewer and the web
  interface. Changes carry an `origin` and are announced as `Event`s. Web routes
  that read the model are plain `def`. Routes that change state are
  `async def`, run on the session's loop, and check the request origin.
- **Captures.** `gowitness/results.py` reads defensively and keeps title, final
  URL, headers, technologies, network log and a TLS summary line. It reads only
  the first 64 KiB of a body, to find the generator tag. Captures that seek
  makes store bodies unless `gowitness_collect_all` is off.
- **Statelessness.** The viewer spec allowed writes only for exports and
  vulnerability database updates. The spec delta in this change adds explicit
  tag actions.
- **Measured.** The colleague's engine needs about 100 ms for 5 rules over
  20 000 synthetic hosts. Its test suite fails at collection on `main`,
  because `tests/test_patterns.py` imports `ServicePattern`, which only exists
  on the `rule_changes` branch. The superset is therefore defined against that
  branch, which is the newer dialect.

## Goals / Non-Goals

**Goals:**

- One rule language that reads both of the colleague's dialects and adds
  negation, issues, more fields and literal or case-sensitive values.
- Evaluation that never blocks the event loop. The target is 200 rules over
  24 200 hosts in at most 1 s in the projection worker.
- Every failure is reported where tags are shown, and is limited to the
  smallest unit: an expression, a rule, a tag or a file. A failure never stops
  the viewer.
- Writes that are atomic, apply changes to the current file on disk, and never
  touch a file that a person wrote.
- One evaluator for rules, the `tag:` filter and the builder preview, so they
  cannot disagree.

**Non-Goals:**

- Following a host whose IP address changes, or a service that moves ports.
- Recording who added a manual tag.
- Editing `seek-rules.yaml` from the interface. Seek writes only
  `seek-tags.yaml` and the global `tags.yaml`.
- A regular expression mode for the filter bar. The text matcher is built so a
  later change can reuse it. The filter stays fuzzy.
- Feeding tag issues into the vulnerability views.
- Searching for rule files above the opened folder.
- A command line flag for rule files at other paths. A colleague's file is
  copied or linked as `seek-rules.yaml`.

## Decisions

### D1. Tags are the objects, and rules are compiled into one tree

The loaded form is immutable:

| Object | Holds |
|---|---|
| `TagDef` | name, description, issues, rules, sources (file and line of each part) |
| `Issue` | title, severity, description, references |
| `Rule` | name, `grant` (host, service or both), condition tree, source |
| `All` / `Any` | child conditions |
| `PortClause` | protocol, port or none (any port), state (default open), field tests |
| `HostClause` | address network or expression, hostname, OS, host script |
| `TagClause` | tag name |
| `Not` | exactly one `PortClause`, `HostClause` or `TagClause` |

`Not` wraps only a single clause. That keeps three-valued evaluation simple
(D5) and keeps the builder's exclusions readable. A user who wants to negate a
group writes the equivalent conditions, which is always possible for a group of
clauses. The alternative, `Not` over any subtree, needs full Kleene logic, and
"assumed" would then have no clear meaning under a double negation.

A rule from the colleague's `rules:` list becomes one `Rule` per granted tag.
Its `host_tags` grant to hosts and its `service_tags` grant to services.
`all` and `any` keep their nesting. The native format writes a rule as a list of
conditions, which is an implicit `All`, and allows `any:` as one condition.

### D2. The file format is the colleague's format plus a `tags:` section

```yaml
seek: 1                      # optional; a higher number is refused
rules:                       # the colleague's list, read unchanged
  - name: Printer (port-based)
    pattern:
      all:
        - nmap_port: { port: 515, state: open }
        - nmap_port: { port: 9100, state: open }
    host_tags: ["printer"]
tags:                        # seek's own definitions
  zebra-zd420:
    description: Zebra ZD420 label printer
    issues:
      - title: Admin interface protected by a 4-digit PIN
        severity: medium
        references: ["https://example.invalid/advisory"]
    rules:
      - name: ZD420 web page without ssh
        grant: host
        when:
          - port: 80/tcp
            body: { literal: "ZD420" }
          - port: 9100/tcp
          - not: { port: 22/tcp }
```

How each colleague key maps:

| Colleague key | Seek clause |
|---|---|
| `nmap_port` | `PortClause`. Without `state` it means open, because his parser keeps only open ports. `service` is a full, case-insensitive match, as his `!=` test was exact. `product` is an expression, as on his newer branch. |
| `html_title`, `html_body`, `html_redirect` | `PortClause` with no port and the matching capture field |
| `service_match` | `PortClause` with all fields. Its `hostname` becomes a `HostClause` in the same `All`. `cert:issuer` and `cert:subject` keys are read with the colon. |
| `has_tag` | `TagClause` |
| `all`, `any` | `All`, `Any` |

Native port clause fields: `port` (a number, or `number/protocol`), `state`,
`service`, `product`, `version`, `extrainfo`, `cpe`, `tunnel`,
`script: {id, output}`, `cert_subject`, `cert_issuer`, `title`, `body`,
`redirect`, `header`, `technology`, `network_log`. Native host clause fields:
`address` (a network or an expression), `hostname`, `os`, `host_script`.
`tag` is a tag clause.

Two deviations from the colleague's behaviour are deliberate and tested:

1. **Text ignores case and is searched, not compared.** This was decided with
   the user. It can only widen a match.
2. **Service tags go to every port that satisfied a positive port clause.** His
   `all` intersects the services each pattern matched, so a rule over two
   different ports gives service tags to no port. His own README example
   (`html_title` plus `nmap_port` 515) tags nothing for that reason.

**Strict typing guards against YAML 1.1.** PyYAML reads `no` as false, `1.10` as
the number 1.1, and `22:30` as 1350. Every text field must be a string, and
every tag name must be a string. A value of the wrong type disables its rule,
with a problem that says to quote the value. Port numbers must be integers from
1 to 65535.

**Line numbers.** The loader subclasses `yaml.SafeLoader` (`CSafeLoader` when
it is available) so that each mapping records its start line. Every problem then
names a file and a line. Only `safe_load` semantics are used. Arbitrary object
construction is never reachable.

**Limits.** A rule file over 2 MiB, or a document over 100 000 nodes, is skipped
with a problem. This bounds the cost of anchors and aliases without forbidding
them.

### D3. Text matching is one small type

`TextMatch` holds a compiled pattern and how it was written. A plain string is
an expression with `re.IGNORECASE`, matched with `search`. `{literal: "..."}`
is escaped first. `{regex: "...", case: true}` drops the case flag. Patterns
over 1 000 characters are refused. Compiling happens once, at load. A pattern
that does not compile disables its rule, with the `re.error` message and the
line. A field with several values, such as several captures of one service,
matches when any value does.

The builder writes `literal`, so values like `Jetty(i-jetty g2p5_0.08)` stay
readable. The type lives in `nmap/tagrules.py` and has no dependency on rules,
so a later filter regex mode can import it.

### D4. Evaluation is a session projection, indexed by port

`nmap/tagging.py` exposes `build(hosts, defs, manual, captures, coverage,
bodies, report) -> TagSet`. It is pure, apart from body reads through an
injected reader (D6). `TagSet` is immutable:

- `host_tags[address]` and `service_tags[(address, protocol, port)]`, each a
  mapping from tag name to `Grant(sources, assumptions)`;
- `problems`, the load problems plus evaluation notes such as "not evaluated";
- `counts[tag]`: hosts, services, uncertain;
- `generation`.

A new `TagSet` replaces the old one in one assignment, so a reader never sees a
mix of old and new tags.

`Session.tags(report)` caches the set on
`(id(scans), shots.generation, defs.generation, manual.generation)`.
`Session.tags_ready()` builds inline below `INLINE_TAG_HOSTS` (2 000), and
otherwise returns `None` until the rows worker has built it. That is the same
contract as `inventory_ready()`. The rows worker builds tags after the inventory
and reports hosts through `progress.counted`. The collector policy stays with the
worker, which owns the phase (`bulk`). `tagging.build` is pure, like `merge`.

Performance comes from three things:

- **Order.** Tags are evaluated in topological order of their tag clauses.
  Kahn's algorithm finds the order. Strongly connected components with more
  than one tag, or a tag that refers to itself, are disabled at load with one
  problem that names the cycle.
- **Index.** Each host gets a dictionary from `(protocol, port)` to service, and
  a frozen set of its open ports. Each rule records the open ports it requires.
  A subset test rejects most hosts before any text is matched.
- **Cheap first.** Within an `All`, clauses run in this order: required ports,
  scan fields, capture fields, tag clauses, negations, then body clauses. Body
  clauses are deferred and batched (D6).

A rule whose port clauses name no port is legal. It costs a pass over every
service of every host. The tag list shows it as "slow: no port" so a heavy rule
is visible.

### D5. Three-valued evaluation, with assumptions only from negations

A clause evaluates to `Holds`, `Fails`, or `Assumed(evidence)`:

- A positive clause is `Holds` or `Fails`. Missing data means `Fails`. A body
  clause on a capture without a body also counts toward a per-rule
  "not evaluated" note (D6).
- A `Not` over a port clause is `Fails` when any port satisfies the clause.
  Otherwise it is `Assumed` when the evidence is incomplete, and `Holds` when it
  is complete. Evidence is incomplete in these cases:
  - the clause names a port and protocol that the host's coverage lacks;
  - the clause names a port without a protocol, and no protocol covers it;
  - the clause tests capture fields, and the named port is open with no
    capture, or a body clause meets a missing body.

  A clause without a port cannot know about unscanned ports, so it is treated
  as complete. This limit is documented in the help text.
- A `TagClause` is `Holds`, `Assumed` with the tag's evidence, or `Fails`. A
  `Not` over a tag clause is `Fails` when the tag is held or assumed. It
  follows the assumption consistently, so a host can never be granted both a
  tag and its negation.
- `All` is `Fails` when any child fails. Otherwise it is `Assumed` with the
  union of the evidence, or `Holds`.
- `Any`, and the rules of one tag, give `Holds` when any child holds.
  Otherwise they give the `Assumed` child with the least evidence, otherwise
  `Fails`.

Evidence is short structured text such as `22/tcp not scanned`,
`no capture of 80/tcp`, or `no page body for 80/tcp`. It is shown in the record
and in the browser.

**Making the missing scan.** Uncertain hosts are listed with `tag:NAME`.
Marking them and choosing the export destination "scan" opens the existing scan
flow with those addresses. The record names the ports to add. No new scan code
is needed.

### D6. Page bodies are read in batches from the capture database

Body clauses run last, and only for services where every other clause of the
rule held. The candidates are grouped by `(database path, row_id)`. The reader
runs one query per chunk of 500 ids:

```sql
SELECT id, substr(html, 1, :cap) FROM results WHERE id IN (...)
```

The pattern is matched in Python. Memory is bounded by the chunk size times the
cap. The cap `BODY_CAP` is 1 MiB, and text after it is not searched. The help
text and the record say so when a page was cut.

The connection opens read-only (`mode=ro`) with a 2 s busy timeout. A locked or
damaged database gives "not evaluated" for its services and a problem. It is
tried again on the next `shots.generation`. A missing `html` column, or an empty
body, gives "not evaluated (no page body)". Results are cached in the session on
`(path, mtime_ns, size, row_id, pattern)` in a bounded LRU, so a recomputation
after a manual tag does not read bodies again.

The alternative was registering a `REGEXP` function in SQLite. It saves nothing,
because the function still runs Python per row. It would also hide the cap
inside SQL.

`gowitness/results.py` also gains `tls_subject` and `tls_issuer` as separate
fields, selected only when the columns exist. The display line stays as it is.

### D7. Scan coverage comes from `<scaninfo>` and per-file host facts

`parse.py` already streams `start` and `end` events. It now also handles:

- `<scaninfo protocol services>` adds the parsed ranges to
  `ScanFile.coverage[protocol]`. Protocol `ip` from `-sO` is ignored. A
  malformed `services` attribute puts that protocol in
  `ScanFile.coverage_unknown` and the file still loads. `ScanSet.failures` is
  not used, because it lists files that could not be read at all. The tag
  problems name the protocol instead.
- `<host timedout="true">` adds the address to `ScanFile.timed_out`.
- `<host>` with status `down` adds the address to `ScanFile.not_scanned`,
  because nmap does not probe ports of a host it found down.

Coverage is stored per file, never on `Host`. `merge` mutates the first file's
hosts, so a per-host flag would leak between files. `nmap/coverage.py` builds
`Coverage.of(host)` from `host.sources` and the files with those labels. The
result is the union of the ranges over files where the host was neither timed
out nor down. Ranges are sorted, merged `(low, high)` tuples searched with
`bisect`. Results are cached per tuple of sources, because thousands of hosts
share the same few file combinations.

A truncated file keeps its `<scaninfo>`, which nmap writes before any host, so
coverage stays correct for the hosts it finished. A scan from `-sn` states no
ports and covers nothing.

### D8. Tag files are found during the scan walk

`tagfiles.find` collects `seek-rules.yaml`, `seek-rules.yml` and
`seek-tags.yaml` with `gowitness.locate.files_below`, the walker capture
discovery already uses, by the scan search's rules. That is a second walk of
the opened folders, as capture discovery already is: tens of milliseconds on a
large tree, against changing `discover`'s interface for the command and both
re-read paths. A file named directly makes seek
look in that file's own folder, without descending. The global files are
`config_dir()/rules.yaml` and `config_dir()/tags.yaml`. Dot folders are skipped,
as they are for scans. This is documented, because a `.seek/` folder would
otherwise look like an obvious place.

**Precedence.** Each file has a scope folder. The global files have no folder
and rank below everything. When two files define one tag differently:

| Relation | Result |
|---|---|
| A's folder is below B's folder, or B is global | A replaces B, with a warning |
| Same folder, or unrelated folders | Merged, with a warning |
| Identical definitions | Kept once, no warning |

"Identical" compares a canonical form: sorted keys, pattern source and flags,
and severity. It ignores comments and order. Merging takes the union of rules.
Issues are united by title, ignoring case. When titles match and severities
differ, the higher severity wins and a warning is added. Descriptions keep the
first in path order, with a warning when they differ.

**Reload.** `Loaded` keeps `(path, mtime_ns, size)` for every file. Every model
publication re-stats the known files, on the loop, which is a stat per file. A
change reloads all of them, because partial reloads would complicate
precedence. Finding new files is a walk of the sources, so only the explicit
reload, `R`, does it, off the loop. A file in a new subfolder is found then.

### D9. Writing `seek-tags.yaml` and `tags.yaml`

```yaml
# Written by seek. Edits to values are kept; comments are not.
seek: 1
tags:
  zebra-zd420: { description: ..., issues: [...], rules: [...] }
entries:
  - { tag: explored, host: 10.0.0.5, added: 2026-11-10T14:02:11Z }
  - { tag: high-value, host: 10.0.0.5, port: 443/tcp, added: 2026-11-10T14:03:40Z }
```

The tag home is the first opened folder, or the folder of the first opened
file. `seek nmap serve` uses the same rule.

A write is an operation, not a snapshot: add entries, remove entries, set a
definition, or delete a definition. The steps are:

1. Take `seek-tags.yaml.lock` with `O_CREAT | O_EXCL`. Its content is the
   process id and the host name. Retry for up to 2 s. Break a lock older than
   30 s, and say so.
2. Read and parse the file as it is now. If it does not parse, stop. Nothing is
   written, and the error is returned to the front end.
3. Apply the operation. Adding an existing entry or removing a missing one does
   nothing.
4. Serialise in a fixed order: tags by name, then entries by tag, address key
   and port. Write to a temporary file in the same folder, `fsync`, then
   `os.replace`. Keep the old file's mode. Release the lock in `finally`.

Applying the operation to the file as it is on disk means two writers never
lose each other's changes. The lock closes the window between read and replace.
On network file systems `O_EXCL` is reliable on NFSv3 and later. The remaining
risk is listed below.

A removal changes every file that holds the entry. That can include
subfolders' files. If one file fails, the others still change, and the error
names the file that failed.

Addresses are stored in canonical form with `ipaddress.ip_address(...).compressed`.
A value that is not an address is kept as written. Entries for hosts that are
not loaded are kept, and counted in the tag list.

**Copy to global** writes the definition only, never entries. A test asserts
that `tags.yaml` contains no address after any operation.

**Threads.** File work runs off the loop: in a thread worker in the terminal
viewer, and with `asyncio.to_thread` in a web route. The result, a new
`ManualTags` snapshot or an error, is then applied on the loop by
`Session.adopt_manual(snapshot, origin)`. That method bumps
`manual.generation` and emits `Event("tags", origin)`. Memory changes only after
the write succeeded.

### D10. Session, filter, views and export

- **Session.** It gains `tag_files`, `tag_defs` (definitions, problems,
  generation), `manual_tags`, `tags()`, `tags_ready()`, `reload_tags(origin)`,
  `tag_records(records, name, add, origin)`, `save_definition(...)`,
  `copy_to_global(name)` and `propose_rule(records)`. A new event type, `tags`,
  is emitted on every change.
- **Filter.** `tag:` joins `FIELDS`. `Field.test` reads the port's tag set from
  a sample. The sample key gains the frozen set of service tags plus host tags.
  `matches` takes an optional `tags_of(host, service)` lookup. Without it, or
  before tags are ready, `tag:` terms are listed in `FilterSpec.ignored` with
  the reason "tags not ready", so the list is never emptied. The plain path is
  unchanged. `test_nmap_query`'s corpus gains `tag:` queries.
- **Row text.** `Session.row_text` appends the row's tag names, so the fuzzy
  `zebra` finds tagged hosts. Its cache key gains the tags generation.
- **Views.** The host view gains a Tags column. It shows names in ASCII, with
  `?` after an uncertain tag and `+N` when they do not fit. The colour is that
  of the highest issue severity, from the existing severity styles. `View.stamp`
  gains the tags generation, like the lookup views. `views.group_by` gains the
  key `tag`, which takes the `TagSet`. Host tags put every open service of the
  host into the bucket, or the host record when it has no open service. Service
  tags put their own pairs into it.
- **Record.** `record.record_lines` gains a Tags block after the names block.
  It lists each tag, its source (`file:line` and rule name, or manual and file),
  its issues with severities, and any missing evidence. The web interface
  renders it through `web/record.py` unchanged, by style attribute.
- **Export.** `Record` gains optional `tags` and `issues`, filled by
  `records_for(hosts, tagset=None)`. The field catalogue gains `tags` and
  `issues`. `export.py` stays pure. The inventory JSON document is unchanged.

### D11. The rule builder is a pure module over the same evaluator

`nmap/tagbuild.py` takes the selected records, the hosts, the `TagSet`,
`Coverage` and the capture index. It returns a `Proposal`.

1. **Facts per host.** Open port, service name, product, version and title per
   port; certificate issuer organisation and common name; `Server` header; OS
   family; tags. Values are kept exactly as found.
2. **Shared facts.** Facts that every selected host has, ranked by how few
   other hosts share them. A text fact that every selected host has with
   different values gets a partial proposal: the longest common prefix or
   suffix of at least 4 characters, as an anchored literal. For Zebra titles
   like `D2J201900995 - READY`, that proposes ` - READY` at the end. When
   services were selected, port facts are tied to their ports.
3. **Exclusions.** The chosen positives are compiled into a draft rule and run
   through `tagging`'s evaluator, the same code that tags. Its matches minus
   the selection form the contrast set. Facts that no selected host has are
   ranked by how many contrast hosts have them. If none covers the whole
   contrast set, a greedy cover proposes up to 3. For each exclusion, the
   selected hosts that are not covered are listed, which is the assumption in
   the spec.
4. **Preview.** The counts are matched, of them selected, and of them assumed.
   A draft that excludes every selected host needs a confirmation to save.

Edge cases: one selected host warns that every fact is shared. A selection with
no shared fact says that no rule can be proposed. Selected hosts that vanished
after a re-read are dropped with a note. The target is 300 ms per step at 24 200
hosts. It runs in a worker or the threadpool.

### D12. Front ends

**Terminal viewer.** Each item lists a key and the action:

- `t` opens the tag dialog for the marks, or for the row. It is an `OptionList`
  of tags, each showing how many selected rows carry it, plus an input for a new
  name. `Enter` adds or removes. The dialog also offers "Edit definition…",
  which edits the description and issues and lets a severity be picked from a
  list, and "Copy to global".
- `T` opens the builder as a sequence of the viewer's existing dialogs: the
  shared facts as a list to tick, with counts; then the exclusions the same
  way; then the preview, which offers saving and asks for the tag. One screen
  with two lists was the first plan; the existing dialogs already fit the
  terminal and say how to leave, and the choices are the same.
- `R` reloads the rule files.

The tag dialog follows the modal rules in AGENTS.md: it uses an `OptionList`,
fits the terminal, and says how to leave.

**Web.** Routes under `/api/v1/tags`:

| Method and path | Purpose |
|---|---|
| `GET /tags` | Definitions, counts, sources, problems |
| `POST /tags/entries` | Add or remove a tag on row references |
| `PUT /tags/{name}` | Set a definition |
| `POST /tags/{name}/global` | Copy a definition to the global file |
| `POST /tags/reload` | Reload the rule files |
| `POST /tags/builder` | Propose facts for row references |
| `POST /tags/builder/preview` | Count a draft |
| `POST /tags/{name}/rules` | Save a draft as a rule |

Reading routes are plain `def`. Changing routes are `async def`, check the
origin like the marks, and do file work with `asyncio.to_thread`. `keys.js`
gains `t`, `T` and `R` with hints, which the key parity test enforces. Pages
reuse the dialog helper in `actions.js`.

### D13. PyYAML is the one new dependency

Seek's config is TOML, but the colleague's files are YAML. Python has no YAML
reader in its standard library.

| Option | Verdict |
|---|---|
| PyYAML | Chosen. Small and widely packaged, with a C loader. Only `safe_load` semantics are used. |
| ruamel.yaml | Rejected. It keeps comments when rewriting, but seek never rewrites a human file, so that buys nothing. It is heavier and slower. |
| Seek format in TOML plus a YAML importer | Rejected. It still needs a YAML reader, and it would mean two formats to document. |

## Risks / Trade-offs

- **Catastrophic backtracking.** Python's `re` has no timeout. A careless
  pattern on a large body can stall the worker.
  → Bodies are capped at 1 MiB, patterns at 1 000 characters, and evaluation
  runs off the loop, so the interface stays usable. The worker checks for
  staleness between hosts, not inside one match. The help text warns about
  nested quantifiers. A timeout-capable engine is a possible later change.
- **Overlapping private ranges.** Two networks with the same addresses merge
  into one host. This is already true for scans.
  → Documented. Tagging adds no new failure here.
- **Network file systems.** `O_EXCL` locking can fail on very old NFS.
  → Operation-based writes still keep both changes in most races. The window
  is a few milliseconds. Atomic replace means the file is never torn.
- **YAML 1.1 coercion** turns unquoted values into numbers or booleans.
  → Strict types, with problems that say to quote the value.
- **Wider matches** for colleague files, from ignoring case and searching.
  → A test runs his example rules and requires identical host tags on his
  fixtures and seek's.
- **The service tag rule differs** from `categorize_systems`.
  → Documented in the spec and tested. His rule tags no port for cross-port
  `all` rules, so no working rule loses a tag.
- **Port-less negations** cannot know about unscanned ports.
  → They are treated as complete, and the help text says so.
- **Precedence can surprise.**
  → Every collision warns and names both files. The tag list shows which file
  won.
- **Statelessness is weaker.**
  → Writes happen only on explicit tag actions. A test opens and closes a
  session and asserts that no file was created.
- **Tag files hold client addresses.**
  → They live in the engagement folder, beside the scans. The global file never
  receives entries, and a test holds that.
- **Cost on very large rule sets.**
  → The port index and required-port subset test, the "slow: no port" note,
  and a tagging phase in `bench_nmap.py`. The rule is to compare against the
  recorded baseline before merging.

## Migration Plan

The change is additive. Without any tag file, every view and export is as
before, and the Tags column is empty. To adopt the colleague's rules, copy or
link his file as `seek-rules.yaml` in the engagement folder, or as `rules.yaml`
in the config directory.

Rollback means removing the tag files. Seek ignores them if the feature is
reverted. Archive `nmap-web-parity` before this change, because two of its
capabilities receive deltas here.

## Open Questions

- Should `BODY_CAP` become a config field? It starts as a constant at 1 MiB.
  Change it only when a real capture needs it.
- Should tag issues later appear in the vulnerability lookup views? That is a
  separate change, and the `Issue` shape already carries what it would need.
