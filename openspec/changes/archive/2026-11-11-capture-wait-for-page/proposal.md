## Why

gowitness photographs a page a fixed three seconds after navigating to it. Slow
pages are captured half drawn - many screenshots of a real engagement show only
part of the page - and fast pages wait for nothing.

## What Changes

- A capture takes each screenshot once the page has loaded and stopped
  changing, instead of after a fixed delay, with an upper limit per page.
- Two configuration values: how long a page must be still
  (`gowitness_settle_ms`, default 2000) and the upper limit
  (`gowitness_settle_cap_ms`, default 20000). `0` for the first puts back the
  fixed delay.
- gowitness is run with its `gorod` driver, the only one that waits for the
  script that does this (measured against 3.2.2).

## Capabilities

### New Capabilities

None.

### Modified Capabilities
- `gowitness-capture`: adds when a screenshot is taken.

## Impact

- `src/seek/gowitness/capture.py` (`settle_script`, `scan_argv`),
  `src/seek/nmap/session.py` (passes the configuration), `src/seek/config.py`,
  `config.example.toml`, `tests/test_gowitness_capture.py`.
- The capture command shown before a run is longer: it carries the script.
- No new dependency. Captures already on disk are read as before.
