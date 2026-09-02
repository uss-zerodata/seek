## Why

**A capture run outside the app is invisible to it.** The reference workflow
this project documents is `gowitness scan file -f dns.txt --write-db` — the
database, no JSON Lines. The reader added by `gowitness-integration` reads only
`gowitness.jsonl`, so a capture directory produced that way returns *zero*
results while its database and screenshots sit beside it, unread. Measured, not
assumed: pointing the viewer at such a directory finds nothing.

The database is also the only place two things exist. Every JSONL record
carries `"id": 0`, while the database rows have real ids — and the report
server's own deep link is `/results/detail/:id`, so "open this element in the
browser" is not reachable from JSONL at all. The database further holds what
the JSONL reader discarded: the full header set, cookies, console logs, and
`tls_san_lists`, the certificate SAN names that are exactly the vhost evidence
the viewer already collects from nmap.

Reading the database instead closes all of it: external captures start being
seen, the metadata already collected stops being thrown away, and the report
server becomes reachable at the row the cursor is on rather than at its front
page.

## What Changes

- **Capture results are read from `gowitness.sqlite3`, not `gowitness.jsonl`.**
  The database is what an external run leaves and what the app already writes
  for the report server, so it becomes the single source. **BREAKING (internal):**
  the JSONL reader is removed and the capture no longer asks for `--write-jsonl`.
  No captured data is lost — every directory the app has ever written also has a
  database — but a hypothetical JSONL-only directory would no longer be read.
- **The full record is carried.** Every response header, the cookies, the
  console logs, the TLS detail including its SAN list, the content length,
  perception hash and the database row id, in addition to what is read today.
- **Metadata is shown at two depths.** A curated set inline — server,
  powered-by, content type, and the security headers whose *absence* is itself a
  finding — with the complete header, cookie and console block in the
  full-screen reader (`d`), laid out the way script output already is. The pane
  stays readable on a 40-row terminal without anything being discarded.
- **The system behind a page is named where it can be.** gowitness's detected
  technologies are already shown; a page title and `Server`/`X-Powered-By`
  headers often name an appliance or product that the technology list misses,
  and those are surfaced as a derived line that says what it was derived from.
- **The report server opens at the selected element**, using the row id and the
  server's own `/results/detail/:id` route, rather than at the gallery front
  page. Verified against the running server: the route exists and answers.
- **A configuration key turns on full collection.** `gowitness_collect_all`,
  default off, drops `--skip-network-logs` and `--skip-html` so per-request
  network logs, cookies and response bodies are recorded. Off by default because
  gowitness's own documentation warns this can make storage explode.

## Capabilities

### New Capabilities

None. This changes how an existing capability sources and presents its data.

### Modified Capabilities

- `gowitness-capture`: results are read from the capture database rather than
  its JSON Lines file, carry the full collected record and its row id, are shown
  at two depths, and the report server is opened at the selected result. What
  the capture collects becomes configurable.

`configuration` is unchanged: it already requires that the file SHALL be able to
override "at least" an enumerated list, and separately that the shipped example
documents every supported key, so a new key is admitted by the existing wording.

## Impact

- **Modified**: `src/seek/gowitness/results.py` (a SQLite reader replaces the
  JSONL parser; `Capture` grows the id, headers, cookies, console logs and SAN
  list), `capture.py` (drop `--write-jsonl`, honour the collection key),
  `tui/nmap/detail.py` (curated inline set, full block in the reader),
  `tui/nmap/app.py` (deep link), `config.py`, README, help.
- **Dependency**: none added. `sqlite3` is in the standard library.
- **Risk**: the database schema is gorm-generated and undocumented, which was
  the original reason for preferring JSONL. That trade is now clearly worth
  making — the JSONL cannot see an external capture, cannot deep link, and
  carries less — but the reader must treat the schema defensively: query columns
  by name, tolerate tables and columns that a different gowitness version does
  not have, and degrade to what it can read rather than failing the directory.
- **Test data**: real databases from live captures already exist in the
  scratchpad, including one with a TLS SAN list and one with console logs; the
  fixture is built from those rather than hand-written SQL.
