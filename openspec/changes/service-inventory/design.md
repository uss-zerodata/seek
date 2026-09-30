## Context

See proposal.md (Why) and `specs/service-inventory/spec.md` for the behaviour.
The code as it stands:

- `nmap/parse.py` reads `product`/`version`/`extrainfo`/`method`/`conf` but not
  `<cpe>` children of `<service>` or `<osmatch>`. For the OS it keeps only the
  best match's name and family. `merge._merge_service` already lets a
  `method="probed"` identification override a table guess, and carries
  `method`/`conf` with it.
- Recognisers already exist, and each is run once per host by `views.prepare`:
  `vulns.attach` and `names.attach`. They only see the `ScanSet`.
- Captures are not in the `ScanSet`. They live on `Session.shots` and are joined
  to services by `Session.captures_by_service()` (URL → `(address, protocol,
  port)` through `export.service_urls`). That index is cached on
  `(id(scans), shots.generation)`.
- `gowitness/results.py` reads `technologies` (values like `Nginx:1.16.1`,
  `PHP`), `headers`, and the `results` columns. The `html` column exists but is
  not read.
- Every list is a `View` built in the projection worker. Tabs come from
  `tabs.TABS`/`tab_view`, and both front ends use them. Records come from
  `record.record_lines` → `detail.*_detail(…, shots, full)`. Exports come from
  `export.produce` (pure: records in, text out).
- Real data (`test_scans/`) shows what the recognisers must handle: nmap CPEs
  such as `cpe:/a:samba:samba:4.6.2` and `cpe:/a:igor_sysoev:nginx`, OS CPEs for
  several kernel lines, `http-server-header` values `pve-api-daemon/3.0` and
  `Python/3.8 websockets/8.1`, and gowitness detections `Nginx:1.16.1`,
  `PHP:7.4.33`, `jQuery:2.1.3`, `Apache HTTP Server` and `TYPO3 CMS`.

## Goals / Non-Goals

**Goals:**
- One pure module computes the inventory from `(ScanSet, capture index)`. Every
  consumer (tab, record block, export, API, gap scan) reads its output and
  derives nothing on its own.
- Adding a source means adding one recogniser function, with no change to
  reconciliation or rendering.
- The JSON export is a stable contract for the vulnerability-lookup change.

**Non-Goals:**
- Version *range* reasoning (for example "7.4.x"). Versions are compared as
  strings with the refinement rule only.
- A complete CPE dictionary. The alias table covers common names, and a gap is
  reported, not guessed.
- Letting users edit the alias table through config (see Open Questions).

## Decisions

### 1. The inventory is a session projection, not a model attachment

`names`/`vulns` write onto `Service` in `views.prepare`. The inventory cannot
work that way, because half of its evidence (captures) is not in the
`ScanSet`, and the captures change without the model changing. So
`nmap/inventory.py` exposes a pure
`build(hosts, captures_by_service, report=None) -> Inventory`, and
`Session.inventory(report=None)` caches the result on the same key as
`captures_by_service`: `(id(self.scans), self.shots.generation)`.

`Inventory` holds `by_service: dict[(address, protocol, port), list[Component]]`,
`by_host: dict[address, list[Component]]` and `unplaced: int` (captures that
matched no service; `captures_by_service` currently drops these silently, so it
also has to return the count).

*Alternative considered:* attach `Service.components` in `prepare` and add the
capture components later. That splits one reconciliation into two passes, and
it makes a capture read mutate the model, which breaks the rule that
`self.scans` is replaced only in `_publish`.

### 2. Recognisers yield observations, and reconciliation groups them

```
Observation(product: str, version: str | None, cpes: tuple[str, ...],
            kind: "a"|"o"|"h", source: str, detail: str, rank: int)
Component(key, product, version, kind, cpes, cpe_origin: "nmap"|"alias"|None,
          observations: list[Observation], conflicting: bool)
```

Each source is a function `(host, svc, captures) -> Iterable[Observation]`
(`from_nmap_service`, `from_os`, `from_scripts`, `from_capture`), listed in one
`RECOGNISERS` tuple. Reconciliation groups observations by `(scope, product
key)`. It then picks the version from the lowest `rank` that has one, and
applies the refinement rule: one version refines another if the other is a
prefix of it at a token boundary (`.`, `-`, `p`, `_`, or a letter/digit
change). `conflicting` means that two observed versions exist and neither
refines the other.

The rank order comes from the spec: nmap probe (0) < script banner or header
(1) < captured header (2) < technology detection (3). A nmap `method="table"`
service yields **no** observation (spec: a guess is not a product).

### 3. Product identity: an alias table that also carries the CPE

`nmap/cpe.py` holds one table, `ALIASES: dict[str, Product]` with
`Product(key, display, kind, vendor, product)`. Its lookup keys are casefolded
spellings from every source, plus the `vendor:product` of nmap CPEs:

```
"nginx" / "igor_sysoev:nginx" / "f5:nginx"      -> nginx      (f5:nginx)
"apache httpd" / "apache http server" / "apache" -> apache-httpd (apache:http_server)
"php", "openssh", "jquery", "microsoft iis httpd", "samba smbd", ...
```

A name missing from the table gets `key = casefold(collapsed whitespace)`, no
CPE, and `display` = the most common spelling seen. So the table does two jobs
at once: it unifies names (one Nginx row, not three) and it maps them to CPEs.
It is a Python module constant with a test, not a data file, so that a wrong
entry fails CI.

Sizing: start with the products that appear in `test_scans/` and the most
common products nmap reports for web, SSH, mail, SMB, databases and proxies
(about 60 entries). Each entry is checked against the NVD CPE dictionary by
hand while it is written, and the test only checks the table's shape.

CPE forms: nmap writes 2.2 URIs (`cpe:/a:v:p:ver`). `cpe.py` parses them and
formats both 2.2 and 2.3 (`cpe:2.3:a:v:p:ver:*:*:*:*:*:*:*`), with the 2.3
escaping of `:`, `*`, `?` and `\` in the version. When nmap gave a CPE without
a version and reconciliation found one, the version is filled into the 2.3
form. The nmap-given URI is kept as nmap wrote it.

*Alternative considered:* shipping the NVD dictionary. It is hundreds of MB,
needs updating, and gives no real gain for the names that actually appear.

### 4. Parsing CPEs and OS matches

- `Service.cpes: list[str]`. `merge._merge_service` adds `cpes` to the fields
  that override on `probed` (it travels with the identification, like `conf`).
  Otherwise it unions the lists.
- `Host.os_matches: list[OsMatch(name, accuracy, cpes)]` for every `<osmatch>`,
  while `Host.os`/`osclass` stay as they are for their current readers. Merging takes `os_matches` from whichever scan supplied `os`; they are never unioned, because two scans' guesses interleaved would make "best first" meaningless. The
  inventory's OS component uses the best match only (the highest accuracy, as
  nmap orders them) and keeps its CPEs. It asserts no single version when the
  CPEs disagree (for example kernels 4 and 5), as the spec scenario requires.
  `smb-os-discovery`'s `os`/`lanmanager` give a more specific OS observation at
  rank 1.
- `Service.copy`/`Host.copy` copy the new lists.

### 5. Script recognisers are anchored to shape

- `http-server-header`, `Server:`/`X-Powered-By:`/`X-AspNet-Version:` lines in
  `fingerprint-strings`: one shared `parse_product_tokens(value)` splits RFC
  7231 product tokens (`Python/3.8 websockets/8.1` → two, and comments in
  parentheses are dropped). In `fingerprint-strings` only lines that start with
  the header name are read, never the body. This is the same anchoring rule
  `names.py` follows for redirects.
- SSH: `^SSH-\d\.\d+-(\S+)` → `OpenSSH_8.9p1` → (OpenSSH, 8.9p1). The
  distribution suffix is kept in `detail`.
- FTP/SMTP greetings: only `^220[ -]` lines, matched against a short list of
  known daemon patterns (vsFTPd, ProFTPD, Pure-FTPd, Postfix, Exim, Microsoft
  ESMTP). An unknown greeting gives nothing. Free text is not guessed.
- `http-generator`: its output is the generator string. Tokenise it the same
  way.
- `vulners`: its table keys are CPEs. Each gives an observation with a CPE and
  a version at rank 1 (vulners chose them from nmap's own probe).
- Anything in `http-vuln-*`, `vuln` or other scripts is ignored. That is the
  "advisory text is not software" scenario.

### 6. Capture recogniser

`Capture` gains `generator: str` (from `<meta name="generator" content=…>`,
read by a bounded regex over the first 64 KiB of `html`, and only if the column
exists, following the defensive schema rule). The technologies split on the
*last* `:` only when the part after it looks like a version (`^\d`). The
`Server`/`X-Powered-By` headers go through `parse_product_tokens`. Several
captures of one service (address plus host names) are all read, so each name
behind virtual hosting contributes. That is intended: they are the same port.
A failed capture gives nothing.

The existing `derived_system()` (the title fallback) is **not** an inventory
source. A page title is not a product identification.

The technology detector also reports things that are not software with a
version of their own (`HSTS`, `HTTP/3`, `WebSocket` in the real data). A small
named set (`inventory.NOT_SOFTWARE`) is skipped, so these do not become
components.

### 7. Views, records, export, API

- `tabs.TABS` gains `("inventory", "Inventory")` after `group-port`, so the three grouping tabs stay together. A `View.stamp` (here the captures generation) is added to the row cache key, because captures change without the model changing.
  `vdefs.inventory_view(session)` is `reports=True` and builds rows from
  `session.inventory(report)`, one row per `(key, version)`. The row's
  `records` are the `Record(host, svc)` pairs that run it (the host record for
  host-level components), so marking, export and drill-down all work through
  the existing machinery. The row text includes product, version, CPE and each
  observation's `source` (spec: filter by source). Drill-down opens the
  existing services-list view over those records.
- `detail.service_detail` / `host_detail` gain an `inventory` argument and a
  `_software_block` that emits `Line`s. `record.record_lines` passes
  `session.inventory()`, so the pane, the reader and the web all share it.
- `export.py` stays pure: `inventory_entries(records, inventory) -> list[dict]`
  and `render_inventory(entries, fmt)`. `produce` takes an optional
  `inventory`. The `EXPORTS` dict gains `"inventory"`, and the dialog offers
  CSV/JSON for it. JSON shape:
  `{"schema": "seek.inventory", "version": 1, "generated_from": [scan labels],
  "unplaced_captures": n, "entries": [...]}`.
- `web/api/v1/inventory.py`: a plain `def` (it reads the model), returns
  `produce(all records, "inventory", "json")` parsed through a pydantic schema.
  Registered in `ROUTERS`. `keys.js` gets the new tab key and the gap-scan key.

### 8. "Scan unversioned" (union of ports, as decided)

`Session.draft_version_gaps(records) -> (command, note, out_base) | ScanError`.
Targets are the addresses whose open services have no component with a
version. The ports are the sorted union of those services' ports, as
`T:`/`U:` groups when UDP is involved, and `-sU` is then added. The argument
string is a constant in `presets.py`:
`-vv -T4 -n -Pn -sV --version-all --script banner,http-server-header,http-generator -p{ports}`,
so the scripts the recognisers read are produced in the same pass. The note
reports `extra = len(targets) * len(ports) - gap_pairs`. The draft then goes
into the existing scope/command/review screens (`plan_scan`), and elevation is
derived from the flags as usual. A bound key (`U` in the terminal, free in both `NmapApp` and `keys.js`; `V` is taken) plus a
palette entry, and the same key in `keys.js`. Output naming follows the preset
convention: preset `03 · Versions, unversioned ports` gives `nmap_03-versions-unversioned-ports_<ts>`. The cost note is shown on the editable-command step of the review, where the command it describes is. In the browser, `POST /api/v1/scans/gaps` returns the same draft for the view, and `/scans/review` + `/scans` accept the gap preset with the command that draft produced.

### 9. Performance

The build is a single pass over open services and captures, and each
recogniser is a handful of `str` operations and anchored regexes (no
backtracking patterns). It runs inside the projection worker's `bulk()` phase,
as other overviews do. It is cached per model and captures generation, so a
keystroke in the filter only re-filters the rows. The benchmark to add is
`bench_nmap.py`'s pipeline split with the inventory included, on the
24 200-host corpus. The target is under one second, which the design expects
easily, since `names.attach` does comparable work.

## Risks / Trade-offs

- [The alias table is incomplete, so vulnerability lookups miss products] →
  Unmapped products stay visible and are marked "no CPE" in the tab, so the
  gap can be seen and filtered. The next change can match by name as a
  fallback.
- [A wrong alias entry gives a wrong CPE, which leads to false vulnerabilities]
  → Entries are reviewed against NVD while they are written, and the alias CPE
  is marked `cpe_origin="alias"` in the export, so a consumer can weight it
  below nmap's.
- [A reverse proxy's header is attributed to the backend it fronts] → The spec
  keeps different products as separate components rather than a conflict. The
  record shows each observation's source, so "Traefik (nmap) + nginx (Server
  header)" can be read correctly.
- [The union-of-ports gap scan probes extra pairs] → Accepted by the user. The
  review states the extra count before anything runs.
- [`html` is large in big capture databases] → Only the first 64 KiB of each
  row is read, and the column is read by the existing results pass, not by a
  second query per row.
- [The JSON contract drifts] → The schema version is in the document, and a
  test pins the field set of version 1.

## Open Questions

- Should users be able to extend the alias table from `config.toml`? This is
  deferrable: the table is data behind one lookup function, so adding a config
  overlay later changes neither the spec nor the tasks.
