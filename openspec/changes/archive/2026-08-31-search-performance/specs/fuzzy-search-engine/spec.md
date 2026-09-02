## ADDED Requirements

### Requirement: Bounded per-file content read
The engine SHALL read at most a configurable number of bytes from any one file when searching its contents (default 5 MB). A file larger than that cap SHALL be searched up to the cap and SHALL NOT be read into memory in full, so that a single very large file in scope cannot stall the session or exhaust memory. Content results produced from a truncated read SHALL be correct for the portion that was read.

#### Scenario: Oversized file is searched only up to the cap
- **WHEN** a 2 GB file is in scope and the content size cap is 5 MB
- **THEN** at most 5 MB of it is read, matches within that portion are returned, and the session stays responsive

#### Scenario: Normal file is unaffected
- **WHEN** a file is smaller than the content size cap
- **THEN** its entire contents are searched, exactly as before

### Requirement: Bounded cancellation latency
A superseded search SHALL stop within a bounded amount of work regardless of the size of the file it is currently scanning. The staleness check SHALL therefore be made while scanning a single file's lines, not only between files.

#### Scenario: Cancellation during a single huge file
- **WHEN** a search is scanning a file with millions of lines and the query changes
- **THEN** the search abandons that file part-way rather than finishing it, and its results are discarded

### Requirement: Incremental query narrowing
When an edit to the query can only make it stricter, the engine MAY compute the new result set from the previous one instead of rescanning every candidate. The result SHALL be identical — in membership, scores, and ordering — to what a full rescan of the same query would produce. When an edit cannot be shown to be strictly narrowing, the engine SHALL perform a full rescan.

#### Scenario: Extending a term narrows without a full rescan
- **WHEN** the query goes from `main` to `main.p`
- **THEN** the returned results are exactly those a full rescan for `main.p` would return

#### Scenario: Widening the query rescans everything
- **WHEN** the user deletes a character, or edits the query anywhere other than by extending it
- **THEN** the engine performs a full rescan and does not lose candidates that the narrower query had excluded

#### Scenario: Negation is not treated as narrowing
- **WHEN** the previous query ended in a negated term and the user extends that term
- **THEN** the engine performs a full rescan, because extending a negation excludes fewer candidates rather than more

## MODIFIED Requirements

### Requirement: Bounded result set
The engine SHALL return at most a configurable number of results (the highest-scoring ones), and SHALL report the total number of matches found so the interface can indicate how many were withheld. The engine SHALL NOT accumulate more than that number of result objects while searching: the peak memory used for results SHALL be bounded by the cap, not by the number of matches, and the reported total SHALL be maintained as a count rather than by retaining every match.

#### Scenario: More matches than the cap
- **WHEN** 5000 candidates match the query and the result cap is 500
- **THEN** the engine returns the 500 highest-scoring results and reports a total of 5000

#### Scenario: Very broad query stays within bounded memory
- **WHEN** a query matches millions of content lines and the result cap is 500
- **THEN** the engine holds on the order of the cap in result objects, not one per match, and still reports the true total

### Requirement: Match spans for highlighting
Each result the engine returns SHALL expose the positions within its displayed label that matched the query, so the interface can highlight exactly those characters. Spans are only required for results the engine actually returns; the engine MAY defer computing them until the result set has been capped, so that matches which are discarded never have their spans computed.

#### Scenario: Highlight positions available
- **WHEN** a candidate `main_helper.py` is returned for query `mnh`
- **THEN** the result reports the positions of `m`, `n`, and `h` within the label

#### Scenario: Spans survive capping
- **WHEN** a query produces far more matches than the result cap
- **THEN** every result in the returned, capped set still reports its match positions

### Requirement: Binary file handling
The system SHALL detect binary files (for example by the presence of a NUL byte in an initial chunk) and SHALL exclude them from content matching while still allowing them to match by name. The detection SHALL be made from that initial chunk alone, without first reading the rest of the file, so that a large binary file costs a header read rather than a full read.

#### Scenario: Binary file skipped for content
- **WHEN** a file in scope contains NUL bytes
- **THEN** it produces no content results, but it can still appear as a filename result

#### Scenario: Large binary file is not read in full
- **WHEN** a 1 GB binary file is in scope and a content search runs
- **THEN** only its initial chunk is read before it is rejected as binary

### Requirement: Name index and budgeted content cache
The system SHALL hold the set of walked file and directory paths in memory for the session, and SHALL cache file contents in memory up to a configurable total budget; files whose contents do not fit the budget SHALL be read from disk during each content search instead. The budget SHALL be accounted in bytes of memory actually retained, including the per-line object overhead of the cached representation, so that the configured budget bounds real memory use. Cache bookkeeping SHALL be O(1) per access, so that a session with many thousands of cached files does not slow down as the cache fills.

#### Scenario: Cached file is not re-read
- **WHEN** a file's contents are within the cache budget and the user issues successive queries
- **THEN** the file's contents are read from disk at most once for the session

#### Scenario: Overflow file is rescanned from disk
- **WHEN** total file contents exceed the cache budget
- **THEN** the files that do not fit are searched by reading them from disk on each content search, and results for them are still correct

#### Scenario: Budget bounds real memory
- **WHEN** the cache budget is set to 64 MB and enough files are searched to fill it
- **THEN** the memory retained by the cache stays near 64 MB rather than several times that

#### Scenario: Cache access does not degrade with size
- **WHEN** tens of thousands of files are cached and a further content search runs
- **THEN** the per-file cache lookup cost does not grow with the number of cached files

### Requirement: Progressive results during a search
When given a progress callback, the engine SHALL deliver ranked, capped snapshots of the results found so far as the content pass proceeds, in addition to the final result set. Snapshots SHALL be throttled by elapsed wall-clock time rather than by how many matches have accumulated: the engine SHALL leave at least a configurable minimum interval (default 500 ms) between consecutive snapshots, and SHALL emit a snapshot only when new matches have been found since the last one. Throttling SHALL NOT affect the final result set.

#### Scenario: Content matches stream in
- **WHEN** a content search over many files is running and a progress callback was supplied
- **THEN** the callback receives one or more ranked partial result sets before the final set is returned

#### Scenario: Snapshots are spaced by at least the interval
- **WHEN** a long content search runs with the minimum interval set to 50 ms
- **THEN** consecutive snapshots are at least 50 ms apart, however fast matches are found

#### Scenario: A fast search reports no intermediate snapshots
- **WHEN** a content search completes in less time than the minimum interval
- **THEN** no partial snapshot is delivered and only the final result set is returned

#### Scenario: Throttling does not change the outcome
- **WHEN** the same query is run with the interval set to zero and to a value longer than the search
- **THEN** both runs return the same results, in the same order, with the same reported total
