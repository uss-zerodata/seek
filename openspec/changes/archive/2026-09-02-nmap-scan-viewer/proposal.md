## Why

`seek` already walks trees and searches text well, but nmap output is *records*,
not lines. Reading a scan today means either `grep`-ing a 1.4 MB XML file or
opening it in a browser: the two questions an assessment actually asks — "what is
on this host?" and "who else runs this service?" — cannot be answered by a
line-oriented search at all.

The workspace sample is representative of the problem: **256 hosts, 40 ports,
90 `<script>` results** in one file, and a real engagement produces several such
files (discovery, top-1000, service scans) that have to be read *together* to be
useful. The interesting relationships are cross-file: a service seen on one host
in one scan and on twenty hosts in another.

**And one class of answer is currently wrong.** The sample was scanned with
`-Pn`, so nmap marked every target `up` with reason `user-set`:

| | count |
|---|---|
| targets asserted `up` | **255** |
| hosts with any port, service, OS or script data | **9** |

`ntell --host-state=up` returns 255 of them. `ntell --stats` does report
`Hosts up: 255` beside `Hosts with open ports: 9`, and `nmap-parse-output hosts`
sidesteps the problem by only ever listing hosts with open ports — but nothing
tells you that "up" was an assumption rather than an observation.

## Prior art in the user's workflow

Two tools already in use, studied against this sample:

- **`ntell`** — imports into SQLite, then queries it. Host-centric: `--stats`
  (target/alive/up/with-open-ports counts, then service name × occurrences ×
  ports, and the set of all open ports), `--port-state=open` (per-host indented
  listing with product and version, showing the status *reason*), `--urls`
  (HTTP/HTTPS URLs including non-standard ports), and repeatable
  `--host-filter` / `--service-filter` / `--port-filter` with matching
  `--*-exclude`.
- **`nmap-parse-output`** — stateless and pipeable. Extraction-centric: `hosts`,
  `ports` (comma-separated, for feeding the next scan), `ports-reachable`,
  `service-names`, `product`, `group-by-service` / `-product` / `-ports`
  (markdown), `http-info`, `http-title`, `tls-ports`, `ssl-common-name`,
  `blocked-ports`.

The shape of both is the same: **derive a list, then feed it to the next
command**. That is the workflow to serve — browse and narrow interactively, then
export exactly the list you need — which is why filtering, grouping, statistics
and export are first-class here rather than an afterthought.

**One thing deliberately not copied: ntell's import step.** This viewer is
stateless — files in, view out, nothing persisted. That is affordable because
parsing is not the bottleneck: the 1.4 MB sample parses in **11 ms**, so
consolidating a typical engagement's five scans costs about **53 ms**, and twelve
about **128 ms**. A database buys nothing at that scale while adding a step
before you can look at anything, state that can drift from the files, and a
question ("what is in the DB right now?") that a stateless tool never raises.

## What Changes

- **A new `seek nmap [PATHS...]` subcommand** opening a viewer directly on the
  given scans — no import, no database, nothing written. Consolidating several
  scans is the normal case: any number of files, or a directory whose nmap XML
  files are collected for you, so an engagement's five-plus scans need not be
  named one by one. Hosts seen in several files are reconciled rather than
  duplicated, and the scan each fact came from is retained and visible.
- **Two top-level views, switchable:**
  - *Hosts* — address, hostname, OS, and open-service count.
  - *Services* — port, protocol, service name, product, version, extra info, and
    vulnerability count, aggregated across every host.
- **Drill-down in both directions.** From a host, its services. From a service
  (`tcp/80 apache`), every host running it, with each host's specifics. A
  breadcrumb tracks the path back out, matching the search session's model.
- **Fuzzy filtering and sorting.** The filter box reuses the existing scorer, so
  the query grammar (`'exact`, `^prefix`, `!negate`, AND terms) works unchanged
  against a row's text. Columns are sortable, ascending and descending.
- **Scripts and vulnerabilities.** `<script>` output is parsed generically into
  its `<table key=…>` / `<elem key=…>` tree — the structure 55 of the sample's 90
  scripts already use — and shown in the detail view. Vulnerabilities are a
  recognizer layered on that: known vulnerability-bearing scripts (`vulners`,
  `vuln-*`, CVE-bearing `ssl-*`) are lifted into typed records with id, severity
  and reference where the script provides them.
- **Discoverability from the search session.** When the highlighted result is an
  nmap XML file, the search TUI says so and offers to open it in the viewer, so
  the feature is found without knowing the subcommand exists.
- **`-Pn` scans are not taken at their word.** The viewer detects an asserted
  host state and classifies hosts by the evidence actually present, defaulting
  the overview to that and surfacing both counts rather than the misleading one.
- **Aggregate statistics** over the filtered model: target / asserted-up /
  evidenced / with-open-ports counts, service occurrences and their ports, and
  the distinct open-port set.
- **Grouping views** by service, product and port, ordered by size.
- **Derived-list export** reusing the session's existing export action: host
  addresses, comma-separated open ports, `host:port` pairs, and HTTP/HTTPS URLs
  with non-standard ports and the right scheme.
- **Malformed and partial files are tolerated.** A truncated or unparseable file
  is reported and skipped rather than aborting the run, matching how the rest of
  the app treats a hostile tree.

## Capabilities

### New Capabilities
- `nmap-scan-viewer`: parsing one or more nmap XML files into a merged host and
  service model, the two overviews, filtering and sorting, both drill-down
  directions, script and vulnerability extraction, the `seek nmap` entry point,
  and the hint that surfaces it from a search session; evidence-based
  reachability for `-Pn` scans; statistics, grouping and derived-list export.

### Modified Capabilities
<!-- none: the new capability owns its entry point and its discoverability hint,
     so no existing spec's requirements change. Three changes are already
     unarchived and two of them hold deltas against `interactive-tui` and
     `configuration`; adding more would tangle them further. -->

## Impact

- New `src/seek/nmap/` package: `parse.py` (XML → models, tolerant), `models.py`
  (`Host`, `Service`, `ScriptResult`, `Vulnerability`, `ScanSet`), `merge.py`
  (reconciling hosts across files), `vulns.py` (the recognizer).
- New `src/seek/tui/nmap/` screens built on Textual's `DataTable` for sortable
  columns, reusing `engine.score` for filtering and the existing chrome — hint
  bar, status line, help overlay, action menu, `keyhints`.
- `src/seek/cli.py`: a `nmap` subcommand added to `_KNOWN_SUBCOMMANDS`.
- `src/seek/tui/app.py`: detection of nmap XML on the highlighted result and the
  hint/action that opens the viewer.
- Test fixtures: small synthetic XML files committed under `tests/fixtures/nmap/`.
  The workspace `nmap/` sample is used to validate the parser against real
  output but is **not** copied into the repo.
- No new runtime dependency — `xml.etree.ElementTree` is stdlib and, unlike
  `minidom`, is a streaming-capable parser suited to multi-megabyte files.
