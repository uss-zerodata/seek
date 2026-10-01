## 1. Stacks

- [x] 1.1 `query.capture_stacks`: the filtered captures, one stack per host:port (the service key, or the URL's host:port when not in the scans), in the gallery's order; `Stack`/`StackPage` schemas
- [x] 1.2 Gallery default view `_stacks.html`: front card with a stacked edge and a count badge, `<details>` to expand in place (no script needed), an open stack spans the row; "every screenshot" (`group=every`) keeps the flat list; the card's sibling link is left out inside a stack
- [x] 1.3 `GET /api/v1/captures/stacks`
- [x] 1.4 The web model places captures with the session's host-and-port fallback (`session.service_at`), so the gallery and the inventory agree
- [x] 1.5 Tests: stacked by default with the count, expanded content, flat view, API, the grouping switch
