## Why

One web server is often captured many times - by its address, by each name it
answers to, run after run - and the gallery listed every capture as its own
card. Ten screenshots of one port read as ten services, which overstates what
the engagement found and hides the services that were captured once.

## What Changes

- The gallery's default view shows one card per host:port. The other captures
  of that port are stacked behind it: the card has a stacked edge and a badge
  with the count, and expands in place to show them all.
- A grouping entry, "every screenshot", shows each capture on its own, as the
  gallery did before. The existing groupings (host, service, title, look-alike)
  are unchanged.
- The gallery places a capture on a service the way the inventory does:
  by URL, then by its host and port when nmap did not identify the port as a
  web service, so one port's captures land in one stack.
- `GET /api/v1/captures/stacks` serves the same stacks.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `nmap-web-interface`: the gallery stacks the captures of one host:port by
  default.

## Impact

`web/query.py` (`capture_stacks`), `web/schemas.py` (`Stack`, `StackPage`),
`web/pages/routes.py`, templates `gallery.html`, `_stacks.html`,
`_macros.html`, `app.css`, `web/api/v1/captures.py`; `web/source.py` uses
`nmap.session.service_at` for the host-and-port fallback.
