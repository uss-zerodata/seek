## 1. Measurement harness

- [x] 1.1 Add a repeatable generator for engagement-scale fixtures (file count, hosts per file, ports per host, size of the unique address pool) under a development script, so every figure in this change can be reproduced rather than remembered
- [x] 1.2 Add a benchmark that reports the pipeline split (discover, parse, merge, prepare, scan history, each overview projection) for a generated set, and record the current figures as the baseline to beat
- [x] 1.3 Add a latency probe that measures event-loop responsiveness (median, p95, worst) while a build runs, so the fifth-of-a-second bound in the spec is checked rather than assumed

## 2. Collector policy

- [x] 2.1 Add a `bulk()` context manager that suspends cycle collection and restores the previous state in `finally`, with a docstring saying why the domain functions do not use it themselves
- [x] 2.2 Add the freeze/unfreeze pair to the single publication path: freeze once a model is published, unfreeze before a re-read replaces it
- [x] 2.3 Raise the thread switch interval while a background build runs and restore it when the last one finishes
- [x] 2.4 Apply `bulk()` at the two owners of a long phase — the reading worker and the projection worker — and nowhere else
- [x] 2.5 Test that a phase raising an exception leaves collection exactly as it found it
- [x] 2.6 Test that a re-read does not leave the superseded model pinned: the frozen object count after a re-read is no higher than before it
- [x] 2.7 Re-run 1.2 and 1.3 and record the improvement

## 3. One report shape

- [x] 3.1 Define the shared report callable — work done, work total, and the unit counted — in the nmap domain package
- [x] 3.2 Convert `merge.load` from its four-field progress record to the shared shape, reporting files with a zero total during discovery
- [x] 3.3 Convert `timeline.build` to the shared shape, reporting scans
- [x] 3.4 Give each overview projection a report, counting hosts, so that every tab can show a bar rather than only the Scans tab
- [x] 3.5 Render any report from one place in the viewer: bar plus counts and unit where the total is known, running indication where it is not
- [x] 3.6 Test that each producer reports monotonically, ends at done == total, and names its unit
- [x] 3.7 Test that an overview projection over a model above the background threshold produces a determinate bar naming hosts

## 4. Reading moves into the viewer

- [x] 4.1 Split discovery from reading in `merge`, so a caller can get the candidate file list without parsing anything
- [x] 4.2 Have `seek nmap` discover, decide "nothing to read and nothing to run" from that alone, and otherwise start the viewer with the candidate list and a loader
- [x] 4.3 Accept either a finished model or a loader in the viewer's constructor, leaving the finished-model path exactly as it is today so existing tests keep testing it
- [x] 4.4 Read in a worker: parse file by file, fold each into an accumulating set, publish an immutable snapshot on the throttled cadence, and only when something new was read
- [x] 4.5 Coalesce publications: while a projection is running the newest snapshot supersedes the pending one instead of queueing
- [x] 4.6 Preserve the selected record across publications through the existing mark-and-restore path, so the cursor does not move under the user as rows arrive
- [x] 4.7 Report reading progress in the status line and in the empty list's message, distinct from a projection's own report
- [x] 4.8 Make the exit status non-zero when candidates existed but nothing could be read, and say so where the rows would have been, naming the files that failed
- [x] 4.9 Test that the viewer answers input before the last file is read
- [x] 4.10 Test that the model grows only by addition: every host listed stays listed, with services at least as complete, and no file is folded in twice
- [x] 4.11 Test that a hundred quick files publish on the cadence rather than a hundred times
- [x] 4.12 Test that a streamed read ends at the same model a blocking read produces, for the same files
- [x] 4.13 Test the empty-list wording while reading is unfinished, and that it is distinct from the settled no-hosts message
- [x] 4.14 Test the two failure paths: no candidates and no nmap exits without opening; candidates that all fail open, report, and exit non-zero

## 5. Verification at scale

- [x] 5.1 Re-run the benchmark and the latency probe on the 120-file, 24 000-host set and record the figures against the baseline from 1.2
- [x] 5.2 Drive the viewer at that scale by hand: every tab shows a determinate bar, `Esc` abandons a build, reading progress is visible in the status line, and no wait exceeds the bound in the spec
- [x] 5.3 Confirm the small-set path is unchanged: a handful of files still opens with no spinner, no bar and no streaming
- [x] 5.4 Run the full suite and the linter, and update the README's large-engagement passage to match what was built
