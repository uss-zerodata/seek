## 1. Fixtures for nmap's own text

- [x] 1.1 Write `.nmap` siblings for the existing XML fixtures, by hand, covering the shapes the cutting has to survive: a discovery run whose hosts have no ports, a port scan with a `Not shown:` summary and a `REASON` column, a version scan with `Service Info:` and `Host script results:`, and a service carrying `|` / `|_` script continuations
- [x] 1.2 Include the traps in those fixtures: a report line carrying a name *and* an address, two hosts whose addresses are prefixes of one another, and a port number that also occurs inside another port's script output
- [x] 1.3 Add a fixture pair where the XML has no `.nmap` sibling at all, so the reconstruction path has something to be tested against

## 2. Cutting the text (no terminal, no scan)

- [x] 2.1 Add `nmap/rawlog.py` with the entries of a subject: one per scan file that recorded it, in the order the scans ran, each carrying the scan it came from and whether that scan left an output file
- [x] 2.2 Cut a host's block out of a scan's text: from its report line to the start of the next one, ending at nmap's closing summary rather than running into it
- [x] 2.3 Cut a port's block: the host's opening lines, the column header, that port's line and the script continuations belonging to it — and nothing belonging to the port after it
- [x] 2.4 Reconstruct the same two shapes from the parsed record when the scan left no output file, and mark the result as reconstructed
- [x] 2.5 Report the two failure states as content rather than as an exception: a file that cannot be read, and a file that does not mention the subject
- [x] 2.6 Test the cutting against every fixture shape from section 1, including the traps in 1.2
- [x] 2.7 Test that reading raw text leaves the model untouched — the same record before and after

## 3. A record is a list of lines

- [x] 3.1 Change `detail.render()` to return the record's lines, each optionally carrying what `o` opens on it, and add the one helper that turns those lines into what the reader takes
- [x] 3.2 Convert every record renderer to the new return type without changing what any of them renders
- [x] 3.3 Replace the `seen in` value in the host and service records with a scans block, one entry per line, each saying what that scan established and each carrying its raw-output action
- [x] 3.4 Test that the reader's content is still exactly the pane's content, so the two cannot describe a record differently

## 4. The pane cursor

- [x] 4.1 Track the cursor as a line index on the record, reset it when the list moves to another row, and clamp it when the same record is re-rendered under it
- [x] 4.2 Render the cursor's line distinctly from the rest of the record, without disturbing the styles the record already uses
- [x] 4.3 Keep the cursor in view: scroll the pane only when the cursor reaches an edge of the visible region
- [x] 4.4 Move the cursor with `J`/`K`, one line at a time, in place of the scrolling they do now
- [x] 4.5 Jump the cursor to the previous and next openable line with `left`/`right`, stopping at the ends rather than wrapping
- [x] 4.6 Say in the hint bar what the pane keys do, and show `o` only when the line under the cursor can be opened
- [x] 4.7 Test that the pane cursor and the list selection never move each other
- [x] 4.8 Test a record with no openable line: the cursor still moves through it and the record still reads to its end
- [x] 4.9 Test that the cursor survives a re-render of the same record while scans are still streaming in

## 5. Opening an entry

- [x] 5.1 Give the pane its two states, and switch to the raw one when `o` opens the entry under the cursor
- [x] 5.2 Head the raw state with the scan it came from and the subject it is scoped to, and say when the text is reconstructed
- [x] 5.3 Read the file when the entry is opened and not before, caching the last few by path so stepping between one host's scans does not re-read
- [x] 5.4 Measure the size at which reading and cutting exceeds the responsiveness bound, and above it do the work in the viewer's existing worker with its indicator and its `Esc`
- [x] 5.5 Return to the record on `Esc`, positioned at the entry that was opened, and make the `Esc` hint say so while the raw state is showing
- [x] 5.6 Drop the raw state when the list moves to another row
- [x] 5.7 Open whichever state the pane is in when the record is opened full-screen, so search and paging reach the raw text unchanged
- [x] 5.8 Keep `o` cycling the report mode on the Scans tab, where no line can be opened
- [x] 5.9 Test the round trip: open an entry, come back, and land on the entry that was opened
- [x] 5.10 Test that moving the list while raw output is showing returns the pane to the new row's record
- [x] 5.11 Test the reconstructed and unreadable entries end to end, from the record to what the pane shows

## 6. Verification

- [x] 6.1 Drive a real engagement directory by hand: check a scoped host block and a scoped port block against the file they came from, and confirm the reconstruction path on an XML-only scan
- [x] 6.2 Confirm the pane is unchanged for a record with nothing to open, and that the Scans tab still behaves as it did
- [x] 6.3 Confirm the responsiveness bound holds while the cursor is moved through a large record during a streaming read
- [x] 6.4 Run the full suite and the linter, and update the README and the help overlay to describe the cursor, the jump keys and `o`
