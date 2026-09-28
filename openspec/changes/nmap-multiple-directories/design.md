## Context

`seek nmap dir1 dir2 dir3` already reads and merges all three: `discover()`
walks each root in turn, drops a file already reached through another root, and
the viewer consolidates the result. What does not survive several roots:

- **Naming.** `parse_file` sets `source = path.name` on every host and service,
  `ScanFile.name` is `path.name`, `ScanSet.sources` lists those names and
  `read()` reports failures by `path.name`. Merging unions provenance *by that
  string* (`if src not in into.sources`), so two different files called
  `scan.xml` become one source and a host seen in both reads as seen once.
  Measured: `192.0.2.40` in `x/scan.xml` and `y/scan.xml` merges with
  `sources == ["scan.xml"]`.
- **Captures.** `_load_captures` reads `capture_dir(self.scan_dir)` only, and
  `scan_dir` is the first root.
- **Output.** `cli.nmap` sets `scan_dir` to the first root when it is a
  directory, else the working directory. The scan review already prints
  `writes <absolute base>.{xml,nmap,gnmap}`.

Nothing matches a scan by its label: the raw-log index and the timeline key
files by object and path, and the only string comparison on a `source` is the
certificate-name source in `models.py`, which is unrelated.

## Goals / Non-Goals

**Goals:**

- Every scan has a label unique within the run whenever two or more directories
  are given, and that label is what every consumer shows.
- Captures are read from each directory given.
- Where output goes is stated, not inferred.

**Non-Goals:**

- Picking the output directory per scan or per capture.
- Changing labels for a single directory or for files named directly.
- Serving more than one capture directory from the report server.

## Decisions

### D1. One naming function, built once from the roots

```
naming(roots) -> Callable[[Path], str]
```

in `nmap/merge.py`, beside `discover`. With fewer than two *directory* roots it
returns `path.name` - today's behaviour, byte for byte, so every existing test
and fixture is untouched. With two or more it returns the path relative to the
common parent of the resolved directory roots (`os.path.commonpath`), as a POSIX
string: `/eng/x` and `/eng/y` give `x/scan.xml` and `y/sub/scan.xml`.

Why the common parent rather than the argument as typed: typed arguments can be
`.`, `../y` or absolute, and would show inconsistently; the common parent gives
the shortest labels that are still unique (two distinct files have distinct
paths below it). Why qualify every label once there are several directories
(the user's choice) rather than only colliding ones: a label then says where a
scan came from on its own, and the names do not change when a later scan adds a
collision partway through a session.

A file named directly alongside directories is labelled the same way when it
sits under the common parent, and by its absolute path otherwise - rare, and
unambiguous.

### D2. The label travels with the parse

`parse_file(path, label=None)` uses `label or path.name` as the `source` it
stamps on hosts and services, and stores it on `ScanFile` (`ScanFile.name`
returns it). `read()` and the viewer's reading worker take the naming function
and call `parse_file(path, name(path))`; failures are reported by the same
label. `merge.Pending` carries the naming function next to the paths, so the
command decides it once and the worker does not re-derive it.

A scan finished in the viewer is re-read through the same path, so it is
labelled like everything else; it is written under the first root, so it is
always under the common parent.

### D3. Captures from every root

`_load_captures` iterates over the directory roots (not files) and calls
`self.shots.load(...)` for each `capture_dir(root)` that exists - `Captures.load`
already accumulates - and registers each as a capture run in the Scans tab, the
Scans tab label qualified like a scan's (`dir2/gowitness`) when there are
several. A missing capture directory is the ordinary case and stays silent.

The report server keeps serving the first root's capture; a result from another
root is "a result the report server cannot address", which the viewer already
reports rather than opening a wrong page.

### D4. Output directory

Unchanged in behaviour: the first root when it is a directory, otherwise the
working directory (`config.scan_output_dir` still wins). The scan review
already names the full output path; the capture confirmation gains the same
`writes` line. With several directories, the status bar's run count line says
`output → dir1` once, so the choice is visible before anything is started.

## Risks / Trade-offs

- **Labels get longer with several directories.** → The Scans column and the
  provenance line are clipped like every other cell; the full label is in the
  record. Relative to the common parent keeps them as short as unique allows.
- **A user relying on bare names in an export's `sources` field** gets
  qualified ones when several directories are read. → Only in the multi-root
  case, which is exactly where bare names were wrong.
- **Two roots with no common parent but `/`.** → Labels become near-absolute;
  still correct, just long.

## Migration Plan

None. Nothing is persisted.
