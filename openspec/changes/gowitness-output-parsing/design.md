# Design

## The database, as it actually is

Read from a real capture, not from documentation. Nine tables; the ones that
matter:

```
results        id, url, probed_at, final_url, response_code, response_reason,
               protocol, content_length, html, title, perception_hash,
               perception_hash_group_id, screenshot, filename, is_pdf,
               failed, failed_reason
headers        id, result_id, key, value          (~14 per result)
technologies   id, result_id, value
console_logs   id, result_id, type, value
cookies        id, result_id, name, value, domain, path, expires, …
network_logs   id, result_id, request_type, status_code, url, mime_type, …
tls            id, result_id, protocol, cipher, subject_name, issuer,
               valid_from, valid_to, …
tls_san_lists  id, tls_id, value
```

**Trap: the column is `filename`, the JSON field was `file_name`.** The same
datum under two names in the same tool. A reader ported field-for-field from
the JSONL parser silently loses every screenshot path.

**Trap: `response_reason` is empty over HTTP/2** (`protocol` = `h2`). The status
line must not assume a reason string exists — already handled today, and must
stay handled.

**Header key casing depends on the protocol.** Measured across one capture:
every `http/1.1` result kept the case the server sent (`CF-RAY`,
`Content-Type`), and every `h2` result was lowercased, as HTTP/2 requires. So
the earlier note that keys "are lowercased" was wrong - they are lowercased
*sometimes*, which is worse, because a case-sensitive lookup would work on some
rows and silently fail on others in the same table. Every lookup is
case-insensitive. The fixture contains both protocols for exactly this reason.

Two columns are worth more than they look:

- `perception_hash_group_id` groups results that *look* the same. Forty hosts
  serving one appliance's default page land in one group, which is exactly the
  "which of these is actually different" question a capture is run to answer.
- `console_logs` carry version strings the headers do not. A real captured page
  logged `authentik(early): version 2026.5.6` — the product *and* its version,
  from a source neither nmap nor the technology detector produced.

## Reading it defensively

The schema is gorm-generated and not a published interface, which was the
original argument for JSONL. That argument loses to three facts: the JSONL is
absent from an externally produced capture, its `id` is always `0` so the report
server cannot be addressed, and it carries less. So the database is read, and
the defence moves into the reader:

- introspect first — `sqlite_master` for tables, `PRAGMA table_info` for
  columns — and select only what is present, rather than a fixed column list;
- a missing optional table (`cookies`, `network_logs`, `console_logs`,
  `tls_san_lists`) yields empty data, not an error;
- a missing `results` table means this is not a gowitness database, which *is*
  reportable;
- open read-only (`file:…?mode=ro`) so a viewer can never write to a capture,
  and so a database being written by a running capture is not disturbed;
- `sqlite3.DatabaseError` anywhere is caught and reported as a problem on the
  index, exactly as a malformed JSONL line was, leaving the viewer usable.

`Captures.problems` already exists for this and is already surfaced; it keeps
its job.

## The one invariant this change amends

AGENTS.md currently records: *the reader shows exactly what the pane shows,
always* — so that the reader "is never a second description of a record that can
drift from the first, only a bigger one".

Showing curated metadata inline and the complete set only in the reader breaks
that as written. The amendment is narrow and worth stating precisely:

> The reader shows **everything the pane shows, and may show more**. Both are
> rendered from the same `_detail_content` call, with a depth argument; neither
> composes its own version of a record.

Drift is still impossible, because there is still exactly one function that
decides what a row's detail is. What changes is that it takes `full: bool`, and
the reader passes `True`. The alternative — putting fourteen headers, the
cookies and the console log into a pane that is often twelve rows tall — would
push a host's services and vulnerabilities off the screen, which is the failure
the pane's own docstring was written against.

`_refresh_detail` already pushes updates into an open reader; it will pass the
same flag, so a streaming capture keeps working at both depths.

## What goes where

**Inline, in the record** — the facts that identify what is running, and only
those:

```
    • https://sso.hektor.cc:443
        200  ·  sso.hektor.cc  ·  h2  ·  authentik  (from x-authentik-id)
        tls       TLS 1.3 · AES_128_GCM · issued by YR2 · until 2026-11-23
        headers   referrer-policy, x-content-type-options   ·   missing: hsts, csp
```

The curated set is `server`, `x-powered-by`, `content-type`, and the security
headers the system looks for by name. **Absence is shown, not just presence**:
a missing `strict-transport-security` cannot be noticed by reading a list of
the headers that *are* there, and that asymmetry is the whole reason to name
them. This is a presentation decision, not a judgement — the record says which
were looked for and which were absent, and stops there.

**In the reader (`d`)** — everything, laid out the way script output already is:
every header as a key/value block, cookies, console messages, the full TLS
record with its SAN list, `probed_at`, content length, and the perception-hash
group when other captures share it.

**Deriving a system name.** Where `technologies` is empty, a candidate comes
from the page title and the `server` / `x-powered-by` / `x-*-id` headers, and is
labelled with its source (`authentik (from x-authentik-id)`). Labelled, because
a guess presented as a detection is worse than no guess: the operator has to
know whether to trust it.

## The deep link

The report server is a single-page application — every path returns the same
document — so the link is a client-side route, confirmed against the running
server's own bundle:

| route | purpose |
|---|---|
| `/results/detail/:id` | one result — the deep link |
| `/results/gallery`, `/results/list` | the front pages |

`:id` is `results.id`, which exists only in the database. `W` therefore opens
`/results/detail/<id>` when the selected record identifies exactly one capture,
and the gallery otherwise. A capture read from a database has an id; a failure
recovered from a run's log does not, and falls back to the gallery rather than
building a link that would not resolve.

## Collection

`gowitness_collect_all`, default `false`. False keeps `--skip-network-logs` and
`--skip-html`; true drops both. It changes *collection only* — the reader shows
whatever a database happens to hold, so a database recorded with it on stays
fully readable with it off. That separation is what keeps the setting from
becoming a display mode by accident.

`--write-jsonl` is dropped along with the JSONL reader. A writer nothing reads
is dead weight that rots; the database is written either way for the report
server, and every capture directory the app has produced has one.

## Alternatives considered

**Keep JSONL as a fallback when no database exists.** Rejected: the app has
never written one without the other, and an external run producing JSONL but no
database would have had to pass `--write-jsonl` while omitting `--write-db`,
which no documented workflow does. Carrying a second parser for that case costs
more than it protects.

**Show every header inline.** Rejected above — it is the pane-overflow failure
the design already guards against.

**Wire the TLS SAN list into the names model** so certificate SANs become
discovered vhosts. Genuinely attractive, and adjacent to work already done, but
it changes what the *names* feature knows rather than what the capture shows.
Out of scope here; the SANs are displayed, and a later change can promote them.

## Risks

- **Schema drift between gowitness versions** is the standing risk of this
  approach. The introspecting reader degrades instead of failing, and the
  fixture is a real database so a future version's differences show up as a
  test failure rather than a crash in the field.
- **A capture in flight**: the database is being written while a run streams.
  Read-only opening avoids locking it, and a partially written row is skipped
  by the same defence that handles a foreign schema.
