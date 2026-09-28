## 1. Naming (no terminal)

- [x] 1.1 Add `naming(roots)` to `nmap/merge.py`: `path.name` with fewer than two directory roots; otherwise the POSIX path relative to the common parent of the resolved directory roots, falling back to the absolute path for a file outside it
- [x] 1.2 `parse_file(path, label=None)`: stamp `label or path.name` as the source on hosts and services, and keep it on `ScanFile` so `ScanFile.name` returns it
- [x] 1.3 `read()` and `load()` take the naming and use it for parsing and for failures (`read` defaults to bare names; `load` defaults to `naming(paths)`, since it has the roots); `merge.Pending` carries it beside the paths
- [x] 1.4 Tests: two directories each holding `scan.xml` for the same host give two sources on the host and its services; one directory keeps bare names; files only keep bare names; a nested scan is `dir/sub/x.xml`; two truncated `scan.xml` files fail under two distinct labels

## 2. The command and the reading worker

- [x] 2.1 `cli.nmap` builds the naming from the given paths and hands it over in `Pending`; help text and the `seek --help` epilog say files and directories, several allowed
- [x] 2.2 The viewer's reading worker parses through the `Pending` naming; a scan finished in the viewer is re-read with the same naming
- [x] 2.3 Confirm the raw-log index, the timeline and the Scans tab key files by object or path and show `ScanFile.name`; fix any that compare labels
- [x] 2.4 TUI test: open on two directories with same-named scans; the Scans tab lists both qualified, and the host record's scan entries list both

## 3. Captures from every directory

- [x] 3.1 `_load_captures` reads `capture_dir(root)` for every directory root, accumulating into `self.shots`, and registers each existing one as a capture run, labelled with its directory when there are several
- [x] 3.2 Tests: a capture only in the second directory is read and shown against its URLs; no capture anywhere stays silent; captures in both are both read

## 4. Saying where output goes

- [x] 4.1 The capture confirmation names the capture directory it will write to
- [x] 4.2 With several directories, the status bar names the output directory once
- [x] 4.3 Tests: opened on `dir1 dir2`, the scan review's `writes` line is under `dir1`, and the capture confirmation names `dir1/gowitness`

## 5. Finish

- [x] 5.1 README: the `seek nmap` usage with several directories, and how scans are named then
- [x] 5.2 AGENTS.md: the naming rule in the nmap invariants (labels are unique per run; provenance is per file, never per file name)
- [x] 5.3 `uv run ruff check`, `uv run pytest -q`, `openspec validate nmap-multiple-directories --strict`
