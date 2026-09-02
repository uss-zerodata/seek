# Design

## What the tool actually does

Everything here was verified against `ghcr.io/sensepost/gowitness` (v3) rather
than taken from the reference workflow, which does not run against the current
image. A sample run is kept at
`scratchpad/gw/gowitness.jsonl` for building fixtures from.

**Corrections to the reference commands.** The image's entrypoint is already
`gowitness`, so `docker run … ghcr.io/sensepost/gowitness gowitness scan file`
fails with `unknown command "gowitness"`. `-D` is `--debug-log`, not a database
flag. The second `-v "$(pwd)":/fh` mount is redundant with the first.

**Target expansion is the load-bearing detail.** `scan file` prepends both
`http://` and `https://` to a target that has no scheme, and crosses that with
`--port` (default `[80,443]`). Measured: two bare names produced seven probes.
A URL that carries a scheme *and* an explicit port is probed exactly once:

| input | probes |
|---|---|
| `hektor.cc` | 4 (`http`/`https` × `:80`/`:443`) |
| `https://sso.hektor.cc:443` | 1 |

`export_urls` already emits the second form. So the app sends complete URLs and
gets a 1:1 result-to-service mapping for free — no `--no-http`/`--no-https`
juggling, and no result that cannot be attributed to a port the scan found.

**Read JSONL, not the database.** `--write-jsonl` emits one JSON object per
result with a stable, documented shape; `--write-db` produces a gorm-managed
SQLite schema (`results`, `technologies`, `headers`, `tls`, `network_logs`, …)
whose column layout is an implementation detail of gowitness. The app writes
**both**: JSONL because it is the parsing contract, the database because
`gowitness report server` needs it and because an externally run capture would
have produced one.

Fields used per record: `url`, `final_url`, `response_code`, `response_reason`,
`title`, `protocol`, `content_length`, `file_name` (the screenshot, relative to
`--screenshot-path`), `failed`, `failed_reason`, `technologies[].value`,
`headers[].key`/`.value` (for `Server`), and `tls`.

`--skip-html` and `--skip-network-logs` are passed: `html` carries the full
response body per result and is the difference between a lean results file and
a huge one. Neither is needed for anything shown.

**Correction, found while implementing: a failure is not a result.** The spec
requires that a result which failed is carried with its reason. The `failed` and
`failed_reason` fields in the JSONL schema suggested that would come from the
results file. It does not. Measured against v3, a target that cannot be loaded
writes **no JSONL record at all**, and without `--log-scan-errors` it produces
no output of any kind — a host that refused is indistinguishable from one that
was never asked:

| flag | unreachable target produces |
|---|---|
| (default) | nothing — no record, no line |
| `--log-scan-errors` | `ERRO failed to witness target target=<url> err="<reason>"` |

So `--log-scan-errors` is mandatory rather than a verbosity preference, and
failures are recovered from the run's log, not its results file. Two
consequences follow:

- the progress counter must count *two* different lines to know how many
  targets are done, which is why `CaptureRun.finished` is captured + failed
  rather than a single counter;
- an **externally produced** capture directory yields successes only. gowitness
  records a failure nowhere on disk, so there is nothing to read back. This is
  a limit of the tool, not of the reader, and the reader must not present the
  absence of a failed URL as evidence that it succeeded.

## Architecture

### Where the code goes

```
src/seek/gowitness/
  detect.py     which backend, if any - the Probe, mirroring nmap's
  capture.py    argv for a backend + output layout; no Textual, no process
  results.py    parse JSONL -> Capture records; index by URL
  runner.py     (see below - shared, not duplicated)
```

`nmap/runner.py` is generalised rather than copied. Its docstring already
promises this ("a future feature that runs a different tool supplies the same
and gets the same supervision"), and the supervision — process group, stream to
a bounded deque, SIGTERM then SIGKILL, settle into done/failed/cancelled — is
genuinely tool-neutral. What is *not* neutral is `ScanRun`: `xml_path`, the
nmap progress regexes, and `_summarise` looking for "IP addresses"/"hosts up".

Split along that seam:

- `runner.Run` — the neutral base: argv, state, timing, log deque, cancel.
- `runner.Runner` — supervision, unchanged, typed on `Run`.
- `nmap.runner.ScanRun(Run)` — keeps `xml_path`, nmap progress, nmap summary.
- `gowitness.capture.CaptureRun(Run)` — screenshot dir, db path, jsonl path,
  capture progress, capture summary.

A `Runner` instance owns one slot. The app holds two — `self.runner` for nmap,
`self.captures` for gowitness — which is what makes "one per tool, concurrent
across tools" fall out with no new concurrency logic. The quit guard asks both.

### Detection

`gowitness/detect.py` mirrors `nmap/presets.py:probe()` — runs once at startup,
never raises, absence is an answer. Order is docker-then-native by default, set
by `gowitness_mode`:

| mode | behaviour |
|---|---|
| `auto` (default) | docker if usable, else native |
| `docker` | docker only; disabled with a reason if unusable |
| `native` | `PATH` only; disabled with a reason if absent |

"Docker usable" means the client exists **and** the daemon answers — `docker
info` succeeding, not merely `shutil.which("docker")`. A docker binary with a
dead daemon is the common broken case, and detecting it at startup is the whole
point of not failing at the moment the user presses the key. The image is not
pulled during detection: that is a several-hundred-megabyte network operation
and belongs to the first run, where it can be reported as progress.

### The docker path problem

A container sees its own filesystem, so the URL file going in and the artefacts
coming out have to be reachable from both sides. One mount, one working
directory, everything relative to it:

```
docker run --rm -v <capture-dir>:/data -w /data <image> \
  scan file -f /data/urls.txt --write-db --write-jsonl \
  --screenshot-path /data/screenshots --skip-html --skip-network-logs …
```

The native command is the same argument list with `/data` replaced by the real
path — so `capture.py` builds one argv from a single "where is the capture
directory, from the runner's point of view" parameter, and the two backends
differ only in that prefix and the `docker run` preamble. That keeps the
translation in one function instead of scattered through the command builder.

Being root-in-container, artefacts may be owned by root on the host. Noted as a
known wrinkle; the app reads them, it does not need to write them.

## The interface

### 1. Availability, in the status bar

nmap's rule is already set: *symbol and words, never colour alone*, bold when
available and dim when not. Capture availability joins it as a sibling token
rather than a new region, and the two sit adjacent so the line reads as one
"what tools are here" cluster:

```
314 host(s) across 7 scan(s)        512 rows  ·  3 marked  ·  ⌁ nmap 7.94  ◉ gowitness docker  ·  sorted by 1 Address ↑
```

```
◉ gowitness docker      backend in use, bold
◉ gowitness native      backend in use, bold
◉ gowitness not found   dim
```

The backend is named, not just its presence, because a containerised run starts
slower and writes root-owned files — behaviour the operator should not have to
deduce. `◉` reads as a lens and is distinct from nmap's `⌁`.

### 2. Results in the record

**A service already lists its URLs** — `_service_urls` builds exactly the list a
capture probes. So captures are not a new section competing with it; they
annotate the section that is already there. This is the whole reason "detail
pane only" is not a compromise:

```
  URLs (3)
    • https://gamma.hektor.cc:443
        200 OK · Home — Hektor.cc · nginx · Cloudflare, Bootstrap
    • https://alpha.hektor.cc:443
        403 Forbidden · 403 Forbidden
    • https://beta.hektor.cc:443
```

The annotation is a dim continuation line under its URL, not a wide column, so
it survives a narrow pane without the pane having to scroll horizontally to
read a status code. A URL with no capture (the third) gets no line at all —
silence, not "not captured", which would put noise on every record in a project
where no capture was ever run.

Status codes carry colour *in addition to* the number: 2xx success, 3xx info,
4xx warning, 5xx and failures error. The number is the information; colour only
speeds the scan.

**A host** gets a `Captures` section summarising across its services, aligned so
the eye runs down the status column — triage is the job here:

```
  Captures (4)
    • 200  https://gamma.hektor.cc:443      Home — Hektor.cc
    • 200  https://hektor.cc:443            Home — Hektor.cc
    • 403  https://alpha.hektor.cc:443      403 Forbidden
    • ✗    https://beta.hektor.cc:8443      dial tcp: i/o timeout
```

Built with the same `Text`-padding idiom the existing `Names` section uses, so
it needs no new helper. Failed results are kept and marked `✗`: a server that
refused is a finding, and dropping it would make the capture look incomplete.

### 3. Getting to the image

**The detail pane has no line cursor** — it is a rendered report, not a list. So
"open the selected capture" has no referent when a record carries twelve of
them. Rather than adding a cursor to the pane (a large change to a component
whose simplicity is load-bearing), the picker *is* the selection:

- `i` — open a capture's **image**. With one capture on the record it opens
  directly; with several it raises the existing `ChoiceScreen`, one line per
  captured URL with its status, and opens the chosen one.
- `W` — start `gowitness report server` against this capture's own database and
  open the browser at its gallery. Already running: just reopen the browser.

`ChoiceScreen` is reused, not rebuilt — it is the app's established modal for
"pick one of these", it is one line per choice, and it already states how to
leave. A result that failed has no screenshot; it is listed but disabled, with
its reason as the subtitle, so the picker still shows the whole truth.

Key choice: `s` is taken by statistics, `r` by reverse-sort. `i` (image) and `W`
(web report) are free and mnemonic. They are not an `x`/`X` pair because they do
different things — pairing them would imply a toggle relationship that is not
there. While the server runs, the status bar gains `◉ report :7171` so a
background process is never invisible.

### 4. The capture entry point

The export dialog is already the place where "a derived list of URLs" is
produced, and a capture consumes exactly that list, so it belongs there as one
more recipe — reachable by the same `x`, honouring the same marks and filter:

```
  Export                                                    Esc to cancel

    Hosts with open ports        512 hosts
    All hosts                    1024 hosts
    Open ports (comma separated) 47 ports
    host:port pairs              1289 pairs
    HTTP/HTTPS URLs              233 urls
    ─────────────────────────────────────────────
    Capture screenshots          Run gowitness over 233 urls   ◉ docker
```

It sits last, under a rule, because it is categorically different: every entry
above writes a file, this one starts a process. The count is shown before
committing — 233 URLs is a long capture, and the operator should see that
number before pressing Enter, not after.

When gowitness is unavailable the entry stays visible but disabled, with the
reason as its subtitle (`gowitness not found — install it, or docker`). A
hidden feature is an undiscoverable one; a disabled feature with a reason
teaches.

### 5. Captures in the Scans tab

The existing columns take a capture with **no schema change at all**, which is
the sign the tab was factored right:

```
  Scan                  Scope        State     When              Result
  ✓ services-top-1000   10.10.10.0/24  done    09-02 07:14  1024 IP addresses (7 hosts up)
  ● capture             233 urls       running 09-02 14:17  84/233 captured
  ✓ capture             12 urls        done    09-02 09:31  10 captured, 2 failed
```

The state glyph slot is kept for state (`●✓✗⊘`); the tool is legible from the
label, since nmap rows carry a preset name and a capture row reads `capture`. A
second tool-glyph would be noise. Progress fills the same `progress()` contract
nmap's percentage does — `84/233 captured` instead of `45% · 12 up`.

A capture's three report modes (`o`) map cleanly: overview (counts, failures by
reason), diff (what this capture found that the previous one did not — new
status codes, changed titles), raw (the streamed log). The raw log is what the
full-screen reader (`d`) was built for; a 233-URL capture prints a line per
result.

## Alternatives considered

**A "Web" tab.** Rejected per the decision to keep results in the detail. It
would also duplicate the Services tab filtered to HTTP, and split "what is on
this host" across two places — the opposite of the standing rule that the
operator should be able to see everything from wherever they are.

**Reading the SQLite database instead of JSONL.** Rejected: the schema is
gorm-generated and undocumented, and would couple the app to gowitness's
internal model across versions. JSONL is the documented output contract. The
database is still written, for the report server.

**Copying `runner.py` for gowitness.** Rejected: two copies of process-group
signalling and cancellation logic would drift, and the cancel path is the part
that must not be subtly different between tools.

**A cursor in the detail pane** so `i` could act on a "selected" line. Rejected
as too large a change to a component whose simplicity is doing real work; the
picker solves the same problem with an existing component.

## Risks

- **Image pull on first run** is large and slow, and will look like a hang if it
  is not reported. The first capture must stream pull progress into the run log
  like any other output.
- **Chrome inside the container** downloads a browser on first use unless the
  image bundles one; the observed run did not, but a `--chrome-path` escape
  hatch should be reachable through configuration.
- **Root-owned artefacts** from the container, noted above.
- **`--delay` defaults to 3s per target**, so a 233-URL capture is minutes, not
  seconds. The progress counter matters more here than it does for nmap.
