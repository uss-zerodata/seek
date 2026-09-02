## MODIFIED Requirements

### Requirement: Re-root the search from the detail view
From the detail view of a directory the system SHALL let the user re-root the search at that directory via a keybinding. Re-rooting SHALL push the previous root onto a breadcrumb stack, keep the current query, and recompute results against the new root. A keybinding SHALL pop one level off the stack, back toward the original launch root, which SHALL be the bottom of the stack.

The filesystem is treated as stable for the lifetime of a session, so changing root SHALL be derived from the scan already in hand rather than by walking the filesystem again: once the launch-root scan has completed, re-rooting into a directory it covered — and popping back up — SHALL reuse it, and SHALL yield exactly the candidates a fresh walk of that root would have produced. The system SHALL fall back to a real walk whenever the scan cannot be reused, in particular when the launch scan has not finished, when the new root lies outside it, or when a positional path scope is active (its accept decisions were resolved against the launch root and do not carry over).

#### Scenario: Re-root into a directory
- **WHEN** the user re-roots at `src/` from its detail view
- **THEN** subsequent results and the tree view are scoped to `src/` and the breadcrumb shows the path from the launch root

#### Scenario: Re-rooting does not rescan the filesystem
- **WHEN** the launch-root scan has completed and the user re-roots into a directory it covered, then pops back to the launch root
- **THEN** neither step walks the filesystem again, and the candidates for each root match what a fresh walk of that root would produce

#### Scenario: A positional scope forces a real walk
- **WHEN** the session was started with positional path patterns and the user re-roots
- **THEN** the new root is walked rather than derived from the launch scan

#### Scenario: Pop back up a level
- **WHEN** the user has re-rooted twice and presses the pop key
- **THEN** the search returns to the previous root and the breadcrumb loses its last segment

#### Scenario: Cannot pop past the launch root
- **WHEN** the breadcrumb stack is at the original launch root and the user presses the pop key
- **THEN** the root does not change

### Requirement: Manual refresh
The system SHALL provide a keybinding that re-walks the current root from scratch and re-runs the current query, so filesystem changes made during the session are picked up. This is the explicit escape hatch from treating the filesystem as stable: refreshing SHALL discard any cached scan and read the filesystem again, and SHALL never be served from it.

#### Scenario: Refresh picks up a new file
- **WHEN** a new file matching the current query is created after the walk finished and the user presses the refresh key
- **THEN** the new file appears in the results

#### Scenario: Refresh bypasses the cached scan
- **WHEN** the user presses the refresh key after the launch scan has completed
- **THEN** the filesystem is walked again rather than the cached scan being reused
