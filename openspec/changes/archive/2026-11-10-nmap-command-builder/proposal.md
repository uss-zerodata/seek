# Proposal

## Why

The scan chooser is a fixed list of 25 presets with `-T4` everywhere. Choosing one needs knowledge of nmap the user may not have: which scan answers the question, what `--max-retries 1` costs, why UDP takes hours. Every preset also uses the same timing for a LAN host 1 ms away and an Internet host 180 ms away. Earlier scans already hold what is needed to do better: nmap records each host's measured round-trip time (`<times srtt rttvar to>`) and the command that produced each file. Commands the user has run before cannot be found again, except by retyping them.

## What Changes

- The scan chooser gets two new entries above the presets:
  - **Build a command…**, a guided builder;
  - **recent and frequent commands**.
- **Guided builder.** It asks goal-first questions: what to find out, which protocol and how many ports, how the hosts are reached (privilege, discovery), and the network's conditions. Every choice states its advantages and disadvantages, citing nmap's documentation, and the command is shown as it is built. At the end it always offers **two commands**:
  - one built for **speed**;
  - one built for **reliability**.
  Each states what it gives up. The user picks one, and it continues into the existing editable command and review steps. Nothing bypasses the review.
- **Every nmap option, under the user's control.** A catalogue of every option nmap documents (nmap 7.99, all 11 groups of its option summary, plus the options documented only in the man pages) is the one source of truth. A **fine-tune** step lists every option by nmap's own group. Each option shows its value, where the value came from, and its documented meaning, and can be set, changed or cleared. A value the user sets is never overridden by a profile or by derived timing. Values are checked where they are typed, and conflicts are named, for example "one TCP scan type at a time". Only the options seek itself owns are not offered, each with its reason: output files, the target list, and modes that do not scan.
- **A guided flow built to UX best practice:**
  - a step indicator that always shows where the user is;
  - one decision per step, with the recommended choice labelled in words;
  - the command always visible;
  - help for the option under the cursor;
  - back without losing answers;
  - Esc asks before discarding;
  - keys always shown;
  - a layout that fits from 60x18 upwards.
- **Timing from data.** RTT timeouts, retries, host groups and timeouts are derived, in this order of preference:
  - from earlier scans of the same targets (nmap's recorded `srtt`/`rttvar`);
  - from a **short measurement that the user confirms first** (TCP connects to known open ports, or a bounded `nmap -sn`);
  - from documented defaults.
  Each derived value says where it came from.
- **Recent and frequent commands** come from two places:
  - the commands recorded in this session's scan files, with nothing new stored;
  - a small history file in the state directory. It holds **arguments only**: targets, output flags and paths are removed before anything is written, so one engagement's scope never reaches the next.
- The parser reads `<times>` per host.
- The browser gets the same chooser and builder through API endpoints (the parity rule).

## Capabilities

### New Capabilities
- `nmap-command-builder`: the guided builder (steps, trade-off explanations, the speed and reliability commands, timing derivation, the confirmed measurement) and the recent/frequent command list with its target-free history.

### Modified Capabilities
- `nmap-scan-runner`: "A scan runs from a reviewed command" now has more than one way to reach the command step. The chooser offers the builder and the recent/frequent commands beside the presets. The review stays the only way to start.

## Impact

- New pure modules:
  - `seek/nmap/options.py`: the option catalogue (spelling, value form and validator, group, privilege, conflicts, default, description, source page). `recent.strip` and the builder read it; a test checks it against `needs_root`;
  - `seek/nmap/builder.py`: the steps, the choices with their trade-offs, the option state with provenance, the two commands;
  - `seek/nmap/timing.py`: derive timing from RTT observations, and the measurement;
  - `seek/nmap/recent.py`: argument extraction and the history file.
- `seek/nmap/parse.py` and `models.Host` gain `times`.
- TUI: a new chooser screen and a builder screen in `tui/nmap/` (step list, content, live command, key bar).
- Web: `api/v1/builder.py` and dialogs in `actions.js`.
- `seek.paths`: a state file for the command history.
- No new dependency. The measurement sends packets only after an explicit confirmation.
