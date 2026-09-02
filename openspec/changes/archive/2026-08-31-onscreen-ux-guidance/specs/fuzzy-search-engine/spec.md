## MODIFIED Requirements

### Requirement: Cancellable recomputation
When a new query supersedes an in-progress recomputation, the system SHALL abandon the superseded work and SHALL NOT let its partial results reach the result set. The superseded work SHALL be abandoned as soon as the query text changes — not only once the debounced replacement recomputation begins — so an in-flight search does not keep running (holding resources, animating a "working" indicator) during the idle-wait for the restart.

#### Scenario: Stale results discarded
- **WHEN** a content search for query `alpha` is still running and the user changes the query to `beta`
- **THEN** results produced by the `alpha` search never appear in the list shown for `beta`

#### Scenario: In-flight search stops at the keystroke, not at the restart
- **WHEN** a search for `alpha` is still running and the user types one more character
- **THEN** the `alpha` search is marked stale immediately and stops at its next cooperative check, before the debounce interval for the new query has elapsed
