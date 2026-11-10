## Why

The viewer already knows a lot about what software runs where, but it keeps it
in pieces. nmap's `product`/`version` sit in the service columns; the CPE
identifiers nmap writes (`<cpe>` under `<service>` and `<osmatch>`) are not read
at all; banners in `http-server-header` and `fingerprint-strings`, gowitness's
technology detections (`Nginx:1.16.1`, `PHP:7.4.33`, `jQuery:2.1.3`) and headers
such as `X-Powered-By: PHP/7.4.33` show up only as text in a record. A service
on port 80 that nmap called `http` with no product reads as unidentified in
every list and export, even though its screenshot says nginx 1.16.1 with PHP
7.4.33 behind it.

The next step in the workflow is automatic vulnerability lookup, which needs
exactly one input: a list of software components, each with a version and,
ideally, a CPE, and each tied to the host and port it runs on. This change
builds that list from every source the viewer already reads, so the lookup
change can consume it without re-deriving anything.

## What Changes

- **A software inventory**: for every open service, a list of *components*.
  Each component has a normalised product name, a version (if any source gave
  one), a CPE (if one is known), a kind (application, OS, hardware) and the
  evidence it rests on. A web port lists its whole stack: reverse proxy, web
  server, language runtime, CMS, client libraries. Host-level components (the OS
  from `-O`, `smb-os-discovery`) belong to the host.
- **Every available source is read**, each through a small recogniser, the same
  way `vulns.py` and `names.py` work:
  - nmap service identification (`product`, `version`, `extrainfo`, `method`,
    `conf`) and its **CPEs, which the parser starts reading**;
  - nmap OS detection (`osmatch`, `osclass`, their CPEs);
  - NSE script output that names software: `http-server-header`,
    `fingerprint-strings` (HTTP `Server:`/`X-Powered-By:` lines, SSH, FTP and
    SMTP greeting banners), `http-generator`, `smb-os-discovery`, `banner`,
    `ssh2-enum-algos`/`sshv1`, and the CPE keys of `vulners`;
  - gowitness captures joined to their service: the technology detector
    (`Name:version`), `Server`, `X-Powered-By`, `X-AspNet-Version`,
    `X-Generator`, and the page's `<meta name="generator">` (read from the
    HTML that gowitness stores).
- **Reconciliation that never throws evidence away.** Observations of the same
  product on the same service become one component. It shows the version from
  the most trusted source (a real nmap probe > a banner > a header > a
  technology detection > nmap's port-table guess), keeps every observation with
  its source, and is marked **conflicting** when two sources give different
  versions. A component that no source versioned is marked **unversioned**.
- **CPEs for software nmap did not name**: nmap's own CPEs are carried as they
  are. A small, curated alias table maps the common names from other sources
  (Nginx, Apache HTTP Server, PHP, OpenSSH, jQuery, …) to a CPE
  `vendor:product`, with the version filled in. A name with no mapping keeps its
  name and version and is marked as having no CPE. It is never guessed.
- **An Inventory tab** in the terminal viewer and the web interface: one row per
  distinct `(product, version)` with its host and service counts, and drill-down
  to the services running it. The service record and the host record gain a
  "Software" block that lists their components with the source of each.
- **An inventory export** (CSV and JSON) with one line per component per
  service: address, port, protocol, product, version, CPE, kind, confidence,
  sources, conflict flag. The JSON shape is versioned and is the contract the
  vulnerability-lookup change will read. A matching `GET /api/v1/inventory`
  returns the same data.
- **"Scan unversioned"**: one action that drafts a version-detection scan
  (`-sV --version-all`) of exactly the open ports that have no versioned
  component yet. It goes through the existing scope, command and review flow,
  and nothing runs without confirmation.

Non-goals: looking up vulnerabilities (the next change); any network access to
build the inventory (it is derived from files already read); editing or
overriding components by hand; fingerprinting beyond what the listed sources
already recorded.

## Capabilities

### New Capabilities

- `service-inventory`: the component model, the recognisers per source, CPE
  handling and the alias table, reconciliation with provenance and conflicts,
  the Inventory tab and record blocks, the inventory export and API, and the
  "scan unversioned" action.

### Modified Capabilities

- `nmap-scan-viewer`: the tab row gains the Inventory overview.

## Impact

- `seek/nmap/parse.py`, `models.py`: `Service.cpes`, `Host.os_cpes` (and OS
  accuracy). `merge.py` unions them as it does `sources`.
- New `seek/nmap/inventory.py` (recognisers, reconciliation) and
  `seek/nmap/cpe.py` (the parsing and the alias table), pure, with no Textual.
- `nmap/session.py`: the inventory is a session projection, because it joins the
  `ScanSet` with the captures (`captures_by_service`). It is cached on the same
  key `(id(scans), shots.generation)`.
- `tui/nmap/tabs.py`, `tui/nmap/views.py`, `tui/nmap/detail.py`: the tab, its
  view, and the Software block. `web/` gets the tab, the API router and the
  schema, and `keys.js` stays in parity.
- `nmap/export.py`: the inventory recipe. `nmap/presets.py`/`session.py`: the
  drafted "scan unversioned" command.
- No new dependencies. Test fixtures gain synthetic XML with CPEs and banners,
  and a synthetic gowitness database with versioned technologies.
