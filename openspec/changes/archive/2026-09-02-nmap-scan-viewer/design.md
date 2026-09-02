## Context

See `proposal.md` — Why. What shapes the approach:

**The real sample.** `nmap/nmap_tcp_top1000_*.xml` in the workspace, 1.4 MB:
256 hosts (255 up, 1 down), 40 ports (31 open, 9 closed), 90 `<script>` results
of which **55 carry structured `<table key=…>` / `<elem key=…>` trees**. Element
shape confirmed against it rather than assumed:

```
nmaprun > host > status[state,reason]
                 address[addr,addrtype]
                 hostnames > (empty in this scan)
                 ports > port[portid,protocol] > state[state,reason]
                                                 service[name,product,version,
                                                   extrainfo,ostype,devicetype,
                                                   tunnel,method,conf,servicefp]
                                                 script[id,output] > table/elem[key]
                 os > osmatch[name,accuracy] > osclass[vendor,osfamily,osgen,type]
                 hostscript > script
```

Two things the sample proves: `<hostnames>` can be **empty**, and `<script>` may
carry structured tables *or* only free text — so both must be optional
everywhere.

**A purpose-built corpus.** Four further scans were run against authorised hosts
in `10.10.10.0/24` to cover what the original sample could not, in
`nmap/scans/` (gitignored):

| file | covers |
|---|---|
| `01-discovery.xml` | real host discovery, **no `-Pn`** — reasons `syn-ack`/`conn-refused`, zero ports. Exercises the evidence classification's unaffected path, and a host reachable with no open port. |
| `02-ports-a.xml` | ports with **no** version detection — the port-scan side of a merge |
| `03-services-b.xml` | service detection, **overlapping `02` on 10.10.10.21** — real reconciliation data |
| `04-vuln.xml` | `--script "vuln and not dos"` — 12 script results, 2 with structured vulnerability tables |

The overlap in 2/3 is genuine merge material: on `10.10.10.21`, port 22 has no
product in `02` and `OpenSSH 10.0p2 Debian 7` in `03`; 3128 gains
`Proxmox Virtual Environment REST API 3.0`; and each file carries ports the other
does not. That is the "later file fills in a missing fact" and "union the
services" behaviour, validated against real output rather than invented.

**Existing pieces to reuse.** `engine.score.match_spans` for filtering (so the
query grammar is identical), `tui/keyhints`, the hint-bar / status-line
conventions, the help-overlay and action-menu patterns, and the breadcrumb model
from the search session.

**Spec hygiene.** Three changes are unarchived, two holding deltas against
`interactive-tui` and `configuration`. This change therefore keeps every
requirement — including its CLI entry point and its in-search hint — inside the
new capability, touching no existing spec.

## Goals / Non-Goals

**Goals:**

- Answer the two questions a scan is read for: what is on this host, and who else
  runs this service.
- Tolerate a hostile corpus: truncated files, non-nmap XML, empty scans, absent
  hostnames and OS.
- Reuse the query grammar so there is one filtering language in the app.
- Stay stateless: the files on the command line are the whole truth for a run.

**Non-Goals:**

- Not running nmap. The viewer reads output; it never scans.
- No vulnerability *assessment* — only surfacing what a scan's scripts already
  reported. No severity is invented where a script did not give one.
- No editing or writing of scan files.
- Not a general XML browser: non-nmap XML is rejected, not rendered.
- **No import step, no database, no cache, no state carried between runs.** This
  is a hard constraint, not a simplification to be revisited: see decision 1.

## Decisions

### 1. Stateless, and `ElementTree.iterparse` to keep it cheap

**Stateless is the constraint; the measurement says it is free.** The 1.4 MB
sample parses in **11 ms**, so a five-scan engagement costs ~53 ms and twelve
scans ~128 ms — below the threshold where anyone would want an import step to
avoid it. ntell's SQLite import exists to make repeated queries cheap over a
corpus that is expensive to re-read; that is not the situation here, so the cost
of a database (a step before you can look at anything, state that drifts from the
files on disk, and the standing question of what is currently imported) buys
nothing. Files in, view out, nothing written unless the user exports.

`xml.etree.ElementTree.iterparse` with `clear()` on each finished `<host>` is
chosen for **memory, not speed** — measured, `ET.parse` of the whole tree is the
same 11 ms. Streaming keeps peak memory proportional to one host rather than to
the total size of the consolidation, which matters when a dozen scans are opened
at once. `minidom` is rejected on both counts: it builds a full DOM and was
already measured at 2.3× slower on comparable input during the formatting work.

Parsing is strict about *shape* and lax about *content*: a missing attribute
yields `None`, never an exception. Validity is decided by one check — the root
element is `<nmaprun>` — so a well-formed XML file that is not a scan is rejected
cleanly rather than producing an empty model.

### 2. Model: `Host` owns `Service`; the service overview is a projection

`ScanSet` holds `hosts: dict[str, Host]` keyed by address. `Host` owns its
`Service` list. The service *overview* is computed by grouping services across
hosts on `(protocol, port, name, product, version)` — it is a view, not stored
state, so it stays correct after a merge and cannot drift.

Grouping on the version means two hosts running different Apache versions are
two rows, which is what an assessment wants to see. The service detail then lists
each host with its own specifics.

### 3. Merge: union services, prefer present facts, keep provenance

Consolidation is the normal path, so the merge is not a special case bolted on:
`ScanSet` is always the product of merging one or more parsed files, even when
only one was given.

Each `Host` and `Service` records the source files it was seen in. With five
scans reconciled, "which scan found this?" is a question that comes up constantly
— when scans disagree, when a port appears in only one, when checking whether a
finding predates a change. ntell's flat import cannot answer it; keeping a small
set of source ids per record costs almost nothing and does.

A directory argument is expanded to the nmap XML files directly inside it, since
naming five or more files by hand every run is precisely the friction that pushes
people towards an import step.

Reconciliation is keyed on address. Services union on `(protocol, portid)`.

**Refined against the real overlapping scans.** First-non-empty is wrong for
service *identification*: consolidating `02-ports-a.xml` (no `-sV`) with
`03-services-b.xml` (with `-sV`) reported port 3128 as `squid-http` — nmap's
port-table guess for that number — because that file came first. A scan that
probed the port must beat one that guessed, in either order, so
`name`/`product`/`version`/`extrainfo`/`ostype`/`tunnel` are overridden by a
`method="probed"` record, and `method`/`conf` travel with them so the row says
how the values it carries were arrived at. The same asymmetry applies to host
state: an observed reason beats `user-set`.

Other single-valued facts (OS, hostname) take the first non-empty value
encountered, so a discovery scan with no service data and a service scan with no
OS data combine into a complete host. Files are merged in the order given, making
the outcome deterministic and explainable.

Alternative considered: last-writer-wins. Rejected — re-running with the files in
a different order would silently change the model.

### 4. Scripts are generic; vulnerabilities are a recogniser on top

`ScriptResult` is `(id, output, data)` where `data` is the `<table>`/`<elem>` tree
as nested dicts and lists. That is exercised by 55 of the sample's 90 scripts, so
the generic path is well covered by real data.

**Corrected against real output.** The captured `04-vuln.xml` shows the NSE
`vuln` library shape, which is not what this design first assumed:

```
script id='http-vuln-cve2011-3192'
  table key='CVE-2011-3192'            <- the identifier is the TABLE KEY
    elem  key='title'  'Apache byterange filter DoS'
    elem  key='state'  'VULNERABLE'    <- a state, NOT a severity
    table key='ids'    -> 'CVE:CVE-2011-3192', 'BID:49303'   (prefixed, repeated)
    table key='description' -> free text
    table key='dates'  -> table 'disclosure' -> elem 'disclosure' '2011-08-19'
    table key='refs'   -> list of URLs
```

Two corrections follow. The identifier comes from the *table key*, not from an
`elem key="id"`. And the NSE `vuln` library reports **`state`**
(`VULNERABLE` / `LIKELY VULNERABLE` / `NOT VULNERABLE`) and no severity at all —
so the model is
`Vulnerability(id, title, state, severity, ids, refs, disclosed, source_script)`
with `severity` populated only by scripts that genuinely score, such as
`vulners`' CVSS. Mapping a state onto a severity would be inventing an
assessment, which the Non-Goals forbid.

Recognised sources:

- NSE `vuln` library (`vuln-*`, `http-vuln-*`) — table keyed by identifier
- `vulners` — `<table key="cpe">` entries carrying `id` and `cvss`
- CVE identifiers in free-text `output` as a last resort, id only

Also observed and handled: 10 of the 12 scripts in the capture reported "found
nothing" with no structured output and must yield no records; and a script that
runs against several ports of a host appears once per port, so records are
de-duplicated per service.

### 5. `DataTable`, and filtering through the existing scorer

Textual's `DataTable` gives columns and per-column sort; `OptionList` (what the
search results use) has neither. Rows are built once per view and re-sorted or
re-filtered in place.

Filtering builds one searchable string per row and runs `match_spans` against it,
so `'exact`, `^prefix`, `!negate` and AND terms behave exactly as in the search
session — one filtering language, no second grammar to learn or document.

Rows are few (hundreds, not hundreds of thousands), so no bounded heap or
narrowing machinery is needed; a straight filter-then-sort per keystroke is
comfortably fast at this scale.

### 6. Detection for the in-search hint

Recognising nmap XML must be cheap enough to run on the highlighted result as the
cursor moves: read the first ~4 KB and look for `<nmaprun` with `scanner="nmap"`.
Extension is checked first so non-XML files cost nothing. The result is memoised
per path for the session.

The hint surfaces in the hint bar when the highlighted row is a recognised file,
plus an action-menu entry, matching how every other action is made discoverable.

### 7. Navigation mirrors the search session

A breadcrumb stack of views, `Esc` unwinding one level per press exactly as the
search session does (clear filter → pop view → quit). Reusing the model means the
two modes do not need separate mental models.

### 8. Reachability is derived, and `-Pn` is detected

Verified against the sample: `args` contains `-Pn`, and 255 of 256 hosts carry
`<status state="up" reason="user-set">` — nmap asserting what it was told, not
what it saw. Only 9 hosts have any `<port>` element at all.

Two independent signals, either sufficient: `-Pn` present in `nmaprun@args`, or a
host status `reason` of `user-set`. Per host, `Host.evidence` is then computed
from what the scan actually found — any port element, any service, any OS match,
any script result — and `Host.reachable` is that, not the recorded state. The raw
`state` and `reason` are kept and shown in the host detail, so nothing is
discarded, only reinterpreted.

The host overview defaults to the evidence classification and the status line
reports both counts (`255 asserted up · 9 with evidence`) whenever they differ.
This is the one place the viewer deliberately disagrees with the file it read, so
it says so rather than quietly substituting a different number.

Alternative considered: filter asserted-up hosts out entirely, as
`nmap-parse-output hosts` effectively does by listing only hosts with open ports.
Rejected — a target that responded on no port is still a scan result worth
seeing, and silently dropping rows is how the current confusion arises in the
first place. Reclassify and show, do not hide.

### 9. Statistics, grouping and export are projections, not stored state

All three are computed from the filtered row set on demand, like the service
overview (decision 2). Statistics mirror the taxonomy `ntell --stats` uses, with
the asserted/evidenced split from decision 8 added. Grouping reuses the same
grouping key machinery as the service overview with a different key selector.

Export reuses the session's existing export action (stdout / clipboard / file)
rather than inventing a second mechanism, and its formats are chosen to be
directly consumable by the next command — a bare address list, a comma-separated
port list of the kind `-p` takes, `host:port` pairs, and URLs. URL scheme is
decided by the service's `tunnel="ssl"` attribute and by known TLS service names,
with the port included whenever it is not the scheme default.

## Risks / Trade-offs

- **The recogniser covers the NSE `vuln` library and `vulners`; other scripts
  carry vulnerability information in free text only** → those degrade to an
  id-only record or to nothing, never to an error. The "scan with no vulnerability
  scripts" case is an explicit spec scenario and is exercised by the original
  sample, which has none.
- **Grouping services on version splits what some users may want grouped** →
  sorting and filtering make either reading available; grouping without the
  version would hide the version spread, which is usually the point.
- **`DataTable` is a second list widget** with different conventions from
  `ResultsList` → confined to the nmap screens; the surrounding chrome (hint bar,
  status, help, action menu, `Esc` semantics) is shared, so what the user
  operates is consistent even where the widget differs.
- **The evidence heuristic could hide a genuinely up host** that answered host
  discovery but exposed no port. → Mitigated because a host reached by real
  discovery has a status reason other than `user-set`, which itself counts as
  evidence; the heuristic only overrides `user-set`. Covered by the "scan with
  real host discovery is unaffected" scenario.
- **Real scan files are sensitive.** The workspace sample is used to validate the
  parser during development; committed fixtures are synthetic and contain no real
  addresses or hostnames.

## Migration Plan

Purely additive: a new subcommand, a new package, and one hint in the existing
session. Nothing about the search session's behaviour changes when no nmap file
is present. No config keys, no new runtime dependency.
