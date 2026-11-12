# Proposal

## Why

The rule builder (`T`) is the way to turn "these hosts are printers" into a rule,
but today it takes too much effort to use:
- It is a three-step wizard with no way back.
- The match total appears only at the end.
- It never shows which unselected hosts match.
- It hides every fact as soon as one marked host lacks it.
- Every fact is fixed to one port and is an exact literal.
- It forces you to type a tag name.
- A saved rule cannot be opened again.

As a result, users write rules by hand. The builder should make a good rule
the easy path.

## What Changes

- **One-screen workbench instead of the wizard.**
  - On one screen, each proposed fact is set to ignore, require or exclude.
  - Facts are grouped by port, with "k/N selected · M others" counts.
  - A live line shows what the draft rule matches.
  - Exclusion suggestions appear inline as soon as the draft matches
    unselected hosts.
  - Nothing is lost until the user leaves, and leaving with changes asks first.
- **A selection and match pane.**
  - It lists the selected hosts, each marked as matched or not, and the
    unselected hosts that match, with their ports and title.
  - The user adds a match to the selection, drops a selected host, or excludes
    one host by address.
  - The facts and counts follow each change.
- **Facts most of the selection shares.** A fact that at least half the selected
  hosts have is offered with its "k/N", so a host marked by mistake shows up
  instead of silently emptying the list.
- **Editable facts.**
  - For a text fact (service, product, version, title, certificate issuer,
    Server header), the user edits the value. The mode is one of equals,
    contains, starts with, ends with or regex, with a case toggle.
  - For any fact with a port, the user picks the port scope: this port, a list
    and ranges, or any port.
  - Live counts warn when the edit drops selected hosts.
- **Broader proposals.** A value the selected hosts share on different ports
  ("product equals `Zebra httpd` on 80,8080/tcp"), and a word all the differing
  values contain ("product contains `Zebra`").
- **Same-port toggle.** It is on by default: required facts with the same port
  scope must hold on one port, and are saved as one condition.
- **A save dialog.** The user picks an existing tag or types a new one, names the
  rule, and chooses whether it tags the host, the matched services or both.
- **One tag editor.** Name, description, issues (with description and
  references) and rules are on one screen, and saved together. It opens after
  the builder saves a rule, and from `t` for any tag.
  - A rule in it opens in the builder and comes back.
  - A rule can be deleted.
  - A rename reaches every project file.
  - Rewriting a hand-written `seek-rules.yaml` is confirmed first, because its
    comments are lost.
- **Ports or hosts.** A builder started from ports can switch to their whole
  hosts, and back.
- **Records show the tag's description**, and each issue's description and
  references.
- **More ways to open the builder.**
  - The marks, or the row under the cursor, as today.
  - The rows in the filtered view, when nothing is marked.
  - An existing rule, opened from the tag menu, changed and saved back in place.
- **The rule format.**
  - A text test accepts `{equals: value}`: the whole value, case ignored unless
    `case: true`.
  - `port:` accepts a list and ranges, for example `"80,443,8000-8999/tcp"` or
    `[80, 8080]`.
  - Existing files read unchanged. An older seek reports a rule that uses the new
    forms as broken, and loads the others.
- The browser gets the same workbench through the same API (parity rule).

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `host-tagging`:
  - the rule format: `equals`, and port lists;
  - the rule builder: it is replaced by the workbench, with its proposals,
    editor, selection pane, save dialog and entry points.

  This depends on the `host-tagging` change, which must be archived first.
- `nmap-web-frontend`: the browser rule builder is the same workbench.

## Impact

- `src/seek/nmap/tagrules.py`: `equals`, port lists, and the canonical form.
- `src/seek/nmap/tagging.py`: candidates, the probed set and assumptions over a
  port list.
- `src/seek/nmap/tagbuild.py`: an editable `Fact`, a `Draft` (the selection, the
  facts with their states, same port) and one `assess(draft)`. It also adds
  near-shared and broader proposals, inline exclusions and `from_rule`.
- `src/seek/nmap/session.py`: replacing a rule in place, guarded against a change
  on disk.
- `src/seek/tui/nmap/`: a new workbench screen and fact editor, and the changed
  entry points in `tagflows.py`, help and hint bar.
- `src/seek/web/api/v1/tags.py`, `schemas.py` and `static/js/actions.js`: one
  assess endpoint, the extended fact schema, rule replace, and the workbench
  dialog.
- `examples/seek-rules.yaml`, `README.md`, the benchmark, and the tag tests.
