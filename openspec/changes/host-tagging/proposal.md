## Why

Engagements contain many devices of the same kind: printers, switches, cameras,
appliances. A known weakness of one model is easy to miss when it appears on 40
hosts among 24 000. An example is a Zebra printer whose admin interface is
protected only by a four-digit PIN. Today a tester finds such hosts by hand,
with grep over gnmap files. A colleague's tool, `categorize_systems`, showed
that declarative rules can tag such hosts from scan data. It also has gaps: no
negation, no issues, exact-only product matches, and no manual tags. It also
loads scans separately from seek and duplicates seek's parser, merge and viewer.

Seek already holds everything those rules need: ports, products, scripts,
certificates, captures and names. Tagging belongs in seek. It must also keep
the colleague's rule files working, so that existing rule sets are not lost.

## What Changes

- **Tags are named objects.** A tag carries an optional description, optional
  known issues with a severity, and the rules that grant it. Any matching rule
  grants the tag. Issues belong to the tag, not to the rule.
- **Rules are conditions that must all hold.** A condition tests one port, with
  its state, service, product, version, scripts, certificate, and capture title,
  body, redirect, headers or network log. It can also test the host: address,
  hostname, OS, or another tag. A condition can be negated. A negation means
  that no port of the host satisfies it.
- **Text values are regular expressions** that match anywhere and ignore case
  by default. A condition can ask for case-sensitive matching or for a literal
  value. The builder writes literal values.
- **A match can rest on an assumption.** A negated condition can pass only
  because the scan never probed the port, or because no capture exists. The tag
  is then still granted, marked uncertain, with the missing evidence named. For
  that, seek reads which ports each scan covered (`<scaninfo>`), which it does
  not do today.
- **Rule files are found like scans.** `seek-rules.yaml` (written by people)
  and `seek-tags.yaml` (written by seek) are found in every folder below the
  opened folders, and `rules.yaml` and `tags.yaml` in the config directory.
  All of them apply to every scan opened. When two files define the same tag
  differently, a file in a deeper folder replaces one above it, and a project
  file replaces the global one. Unrelated files are merged. Both cases show a
  warning. Identical definitions are not a collision.
- **Superset of the colleague's format.** Seek reads his `rules:` list
  unchanged: `nmap_port`, `html_title`, `html_body`, `html_redirect`,
  `has_tag`, `service_match`, `all` and `any`, with `host_tags` and
  `service_tags`. Seek adds `tags:` definitions, `not`, issues, more fields,
  and literal or case-sensitive matching. Two deliberate deviations are
  documented in the design.
- **Manual tags.** The user tags the selected or marked rows from the viewer or
  the browser, for example "explored" or "high-value". Hosts are keyed by IP
  address, and services by address, protocol and port. A host or service can
  carry several tags. Manual tags are saved in `seek-tags.yaml` in the opened
  folder, so they survive across sessions. A manual tag can carry issues too,
  and it can be copied to the global file.
- **Rule builder.** From marked hosts or services, seek proposes the facts they
  share and the facts that separate them from similar hosts, including
  negations such as "22/tcp not open". Each fact shows how many selected and
  unselected hosts it keeps. The user picks facts, sees the live match count,
  and saves the rule to a tag.
- **Tags appear everywhere a host appears.** A Tags column, the record pane
  with issues and uncertainty, a `tag:` filter field, a grouping by tag, the
  exports, and the web interface. The browser has the same keys and the same
  endpoints as the terminal.
- **Page bodies are read only for body conditions.** Seek runs body conditions
  inside the capture database, one row at a time, with a size cap. A capture
  made without bodies reports "not evaluated", never "no match".
- **New runtime dependency: PyYAML**, to read the colleague's YAML format.
- **The stateless rule changes.** The viewer now writes `seek-tags.yaml`, but
  only when the user tags, untags, saves a rule or copies a tag. Nothing is
  written at start or at exit.

## Capabilities

### New Capabilities

- `host-tagging`: tag definitions with issues, the rule language (a superset
  of `categorize_systems`), rule and tag files and their precedence,
  evaluation with uncertainty, manual tags and their file, and the rule
  builder.

### Modified Capabilities

- `nmap-scan-viewer`: Stateless operation (tag files are an explicit write),
  the filter grammar (a `tag:` field), grouping views (group by tag), and a new
  requirement that each scan's port coverage is recorded.
- `nmap-session`: tags and their definitions belong to the session, like marks,
  and changes reach every front end.
- `nmap-web-frontend`: tags, manual tagging, and the rule builder in the browser,
  with the same keys and the same origin check as other changes.

## Impact

- **New modules.** `nmap/tagrules.py` loads and validates rules. `nmap/tagfiles.py`
  finds, reads and writes tag files. `nmap/tagging.py` evaluates rules into a
  projection. `nmap/tagbuild.py` is the rule builder. None of them imports
  Textual or FastAPI.
- **Changed code.** `nmap/parse.py` and `nmap/models.py` gain scan coverage and
  the host timeout flag. `nmap/merge.py` discovery also collects tag files.
  `nmap/session.py` gains a tags projection cached like the inventory.
  `nmap/filtering.py` gains the `tag:` field. `nmap/views.py` gains tag
  grouping. `nmap/export.py` gains tag and issue fields. `gowitness/results.py`
  keeps the certificate subject and issuer as fields of their own.
- **User interfaces.** The terminal viewer gains a Tags column, a tag block in
  the record, `t` to tag and `T` for the builder. The web interface gains
  `/api/v1/tags` routes, the same keys in `keys.js`, and its pages.
- **Dependency.** `pyyaml` is added to the runtime dependencies.
- **Files on disk.** `seek-tags.yaml` in the opened folder, and `tags.yaml` in
  the config directory. Seek never rewrites a file that a person wrote.
- **Prerequisite.** `nmap-web-parity` is complete but not archived. Archive it
  first, because this change adds to the `nmap-session` and
  `nmap-web-frontend` capabilities that it creates.
- **Benchmarks.** `benchmarks/bench_nmap.py` gains a tagging phase over the
  generated 24 200-host corpus.
