## Why

An engagement's output is often spread over several directories - one per
network segment, per tester, or per day - and `seek nmap dir1 dir2 dir3` is the
natural way to read them together.

Reading and merging already works: `discover()` walks every path it is given,
de-duplicates a file reached twice (overlapping or repeated directories), and
the viewer merges the lot into one model. But three parts of the viewer still
assume there is one directory, and they fail quietly:

- **Provenance collapses.** A scan is named by its file name alone. Two
  directories that each hold `scan.xml` (tools and presets write the same names
  everywhere) give two sources both called `scan.xml`, and merging then records
  a host seen in both as seen in one. The Scans tab, the record's scan entries
  and the export's `sources` field cannot tell the two apart.
- **Captures from the other directories are ignored.** gowitness results are
  read from `<first directory>/gowitness` only; a capture sitting in `dir2`
  never appears.
- **The output directory is implicit.** A scan or capture started in the viewer
  writes into the first directory. That is a reasonable default, but nothing
  but the review's `writes` line says so, and the spec still describes a single
  "directory given".

## What Changes

- **Scans are named by their directory when more than one is given.** With two
  or more directories on the command line, every scan is labelled by its path
  relative to the directories' common parent (`dir1/scan.xml`,
  `dir2/sub/scan.xml`) - everywhere a scan is named: host and service
  provenance, the record's scan entries, the Scans tab, failure reports and the
  `sources` export field. A single directory, or files named directly, keep
  bare file names as today.
- **Captures are read from every directory given.** Each directory's
  `gowitness/` capture is read and merged into one set of results, and each
  appears in the Scans tab as a capture run.
- **The first directory is the output directory, and says so.** Scans and
  captures started in the viewer write into the first directory given; the
  scan review names it (it already does, with the full path) and the capture
  confirmation names it too.
- The command's help and the `seek --help` epilog say that several files and
  directories may be given.

Non-goals: choosing the output directory per scan; merging several capture
databases into one on disk; serving captures from more than one directory in
the report server (captures it cannot address are already handled as such).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `nmap-scan-viewer`: the entry point accepts several directories and says
  which one output goes to; scans are named unambiguously when several
  directories are read.
- `gowitness-capture`: capture results are read from every directory given,
  not only the first.

## Impact

- `src/seek/nmap/parse.py` / `merge.py`: the source label is no longer always
  `path.name`; `read()` (and the accumulator) take the label from a naming
  function built from the command-line roots.
- `src/seek/cli.py`: builds the naming from the given paths; help text.
- `src/seek/tui/nmap/app.py`: `_load_captures` reads one capture directory per
  given directory; the capture confirmation names the output directory; a
  finished in-app scan is re-read with the same naming.
- `src/seek/nmap/timeline.py`, `rawlog.py`: anything that matches a scan by
  `ScanFile.name` has to keep working with qualified labels (they match by
  object or path today, which needs confirming).
- Tests: multi-directory fixtures built in `tmp_path` from the existing XML.
- No new dependencies. No configuration change.
