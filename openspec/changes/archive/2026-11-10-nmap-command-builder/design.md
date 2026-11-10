# Design

## Context

See proposal.md (Why). What exists:
- `presets.DEFAULT_PRESETS`, 25 argument strings, all `-T4`;
- `PresetScreen` (the chooser);
- `CommandScreen` and `ReviewScreen`, both inside the `_Fits` frame from the last change;
- `Session.draft_command` / `plan_scan`;
- `presets.needs_root` and the elevation route (`ScanPlan.via`);
- `presets.parse_command` (refuses shell characters and output flags);
- `ScanFile.args` (the command nmap recorded);
- `history.py` (the query history in the state directory).

The `<times srtt rttvar to>` element is not parsed; nmap's DTD gives its values in microseconds.

**Sources.** Seventeen pages of the nmap reference guide were read for this design:
- the option summary `man-briefoptions` [S], which is the text of `nmap --help` for 7.99;
- the man page sections for target specification [TS], host discovery [HD], port scanning techniques [PT], port specification [PS], version detection [VD], OS detection [OS], NSE [NSE], timing and performance [P], firewall/IDS evasion [FW], output [O] and miscellaneous [M];
- the book chapters on timing templates [T], scan algorithms [ALG], UDP scanning [UDP], port selection [PSel] and low-level timing [LL].

Every rule and every option entry below cites one of them.

## Goals / Non-Goals

**Goals:**
- One catalogue of every documented nmap option, used by the builder, the history stripper and the privilege check.
- One pure model from answers, overrides and facts to steps and two commands, used by both front ends.
- Timing derived from data, with where every value came from.
- A flow that follows terminal UX practice and fits small terminals.

**Non-Goals:**
- Options that only appear in nmap's source, not its documentation.
- Validating a value against the network (for example, whether an interface given to `-e` exists).
- Learning a packet rate from scan durations: nmap's XML has no packet counts.
- Changing the shipped presets.
- Automatic re-scans.

## Decisions

### 1. The option catalogue, `nmap/options.py`

It is a tuple of `Option` records, data with no logic. Each record has:

- `names`: spelling and aliases, such as `-g`/`--source-port`, `-sR`/`-sV`, `--osscan-guess`/`--fuzzy`, `-PN`/`-P0`/`-Pn`.
- `group`: one of nmap's eleven, in [S]'s order: target specification, host discovery, scan techniques, port specification, version detection, script scan, OS detection, timing and performance, evasion and spoofing, output, misc.
- `value`: `None` (a flag), or a `Value(form, attach, optional)`.
  - `form`: `number(lo, hi)`, `real(lo, hi)`, `time` (a number with an optional `ms`/`s`/`m`/`h` [P]), `ports` (the `-p` grammar: ranges, `-`, `T:`/`U:`/`S:`/`P:` prefixes, names with `*`/`?`, `[-1024]` [PS]), `portlist` (for the `-P*` probes, which take no type prefixes [HD]), `protocols`, `list` (a comma list), `hosts` (target syntax [TS]), `choice(...)`, `hex`, `text`, `script` (names, categories, `+` prefixes, `and`/`or`/`not`, parentheses [NSE]), or `script-args`.
  - `attach`: `space`, `attached` (`-PS22,80`, `-T4`, `-v3`), or `equals`; `optional` covers `-PS[<ports>]`.
- `repeat`: for `-v`, `-d` and `-f`.
- `default`: the documented default, in words (version intensity 7 [VD], max retries 10 [P], …).
- `root`: `True` where a page states raw sockets or root, `False` for connect scans, `None` for "not stated".
- `conflicts`: rules, each with its source (see 2).
- `owner`: `None`, or the reason seek controls this option (see 3).
- `about`: the documented one-line description.
- `source`: the page key.

Inventory, by group: the full list is in the module and in the test that pins it.

| Group [page] | Options |
|---|---|
| target spec [TS] | `-iL` `-iR` `--exclude` `--excludefile` `--resolve-all` `--unique` |
| host discovery [HD][TS] | `-sL` `-sn` `-Pn` `-PS` `-PA` `-PU` `-PY` `-PE` `-PP` `-PM` `-PO` `-PR`¹ `--disable-arp-ping` `--discovery-ignore-rst` `--traceroute` `-n` `-R` `--dns-servers` `--system-dns` |
| scan techniques [PT] | `-sS` `-sT` `-sA` `-sW` `-sM` `-sU` `-sN` `-sF` `-sX` `--scanflags` `-sI` `-sY` `-sZ` `-sO` `-b` |
| port spec [PS] | `-p` `--exclude-ports` `-F` `-r` `--top-ports` `--port-ratio` |
| version [VD] | `-sV` (`-sR`) `--allports` `--version-intensity` `--version-light` `--version-all` `--version-trace` |
| scripts [NSE] | `-sC` `--script` `--script-args` `--script-args-file` `--script-trace` `--script-help` `--script-updatedb` |
| OS [OS] | `-O` `--osscan-limit` `--osscan-guess` (`--fuzzy`) `--max-os-tries` |
| timing [P][T] | `-T` (0–5 or names) `--min-hostgroup` `--max-hostgroup` `--min-parallelism` `--max-parallelism` `--min-rtt-timeout` `--max-rtt-timeout` `--initial-rtt-timeout` `--max-retries` `--host-timeout` `--script-timeout` `--scan-delay` `--max-scan-delay` `--min-rate` `--max-rate` `--defeat-rst-ratelimit` `--defeat-icmp-ratelimit` `--nsock-engine` |
| evasion [FW] | `-f` `--mtu` `-D` `-S` `-e` `-g` (`--source-port`) `--proxies` `--data` `--data-string` `--data-length` `--ip-options` `--ttl` `--randomize-hosts` `--spoof-mac` `--badsum` `--adler32` |
| output [O] | `-oN` `-oX` `-oS` `-oG` `-oA` `-v` `-d` `--reason` `--open` `--packet-trace` `--iflist` `--append-output` `--resume` `--noninteractive` `--stylesheet` `--webxml` `--no-stylesheet` `--stats-every` |
| misc [M] | `-6` `-A` `--datadir` `--servicedb` `--versiondb` `--send-eth` `--send-ip` `--privileged` `--unprivileged` `--release-memory` `-V` `-h` |

¹ `-PR` (ARP ping) is described on [HD] but not in [S]. Each entry carries its page, so the inventory can be compared with a newer nmap.

A test pins that:
- every option named on [S] is in the catalogue;
- every catalogue option marked `root=True` is classified by `presets.needs_root`. `needs_root` gains the raw-packet evasion options (`-f`, `--mtu`, `-D`, `-S`, `--spoof-mac`, `--ip-options`, `--badsum`, …), which it does not know today;
- every shipped preset parses against the catalogue with no unknown token.

`recent.strip` reads its option arity from the catalogue (`value.attach == "space"` means the next token is the value), replacing the ad hoc table of the first draft. The arity can no longer drift from what the builder knows.

### 2. Conflicts: documented, refused by nmap, or advice

The builder keeps the command valid, and names the rule each time it acts on one. A rule has a `kind`:

- **exclusive**: setting one clears the other, and the step says which it cleared and why.
  - One scan method at a time, except that `-sU` and one of `-sY`/`-sZ` may join one TCP type [PT].
  - `-sO` and `-sL` stand alone [PT][HD].
  - `-sn` excludes port selection, scan types, `-sV` and `-O` [HD].
  - `-f` and `--mtu` [FW].
  - `-n` and `-R` [TS].
  - `-F` and `-p`. nmap itself refuses this pair at start; this rule is marked "refused by nmap" rather than cited.
- **ignored**: both stay, with a note, because one has no effect.
  - `-sC` with `--script` [NSE].
  - `--dns-servers` with `--system-dns` [TS].
  - `-D` with `-sV` or `-sT` [FW].
  - `--source-port` with connect, version or script scans [FW].
  - `--traceroute` with `-sT` or `-sI` [HD].
  - fragmentation without a raw scan [FW].
- **advice**: a warning only.
  - `--min-rate` [ALG].
  - `-T5` [P].
  - `--max-retries 0` [P].
  - `--defeat-*` [P].
  - `-S` without `-e` and `-Pn` [FW].
  - `--osscan-limit` without `-O`/`-A` [OS].

### 3. What the user cannot set, and why

`owner` is set for:
- `-oN`, `-oX`, `-oS`, `-oG`, `-oA` and `--append-output`: seek writes all three formats beside the scans, which is what makes a scan run here indistinguishable from one run outside.
- `-iL` and `-iR`: targets come from the scope step.
- `--resume`: "no other arguments are permitted" [O].
- `--iflist`, `--script-help`, `--script-updatedb`, `-V` and `-h`: they do not scan.

These options are listed in fine-tune, dimmed, with the reason, because a hidden option teaches nothing (house rule). `--stylesheet`, `--webxml` and `--no-stylesheet` stay settable: they change only the XML's header.

### 4. The model, `nmap/builder.py`

- `Facts`: targets; the known open ports per protocol; the hosts known up; `ScanPlan.via` (root, capabilities, sudo or none); RTT observations.
- `Answers`: the step answers.
- `Overrides`: `{option: value | CLEARED}`, set in fine-tune.
- `State = (answers, overrides, step)`. It is immutable; each key returns a new state. The web sends it back and forth as JSON, so the server keeps none.
- `resolve(state, facts, profile) -> Resolved`: `{option: Setting(value, source, why)}`.
  - Precedence: **user > goal answers > profile > measured > earlier scans > nmap default**.
  - The first source that sets an option wins, and the losers are kept in `why` so the help can say what was overridden.
  - Conflicts (see 2) are applied after precedence, and the user's latest setting wins an exclusive conflict.
- `render(resolved) -> argv`: catalogue order within [S]'s group order, with the attach rules applied. The same answers always give byte-identical commands, which is what makes "the same command in both front ends" testable.
- `steps(state, facts) -> [StepView]`: each has a key, a title, a status (done / current / ahead / skipped), and for the current step its choices (`label`, `adds`, `gain`, `cost`, `recommended`, `why_recommended`) or, for fine-tune, the option rows.

Steps: **Goal → Protocol → Ports → Reach → Network → Fine-tune → Choose.**

- Protocol and Ports are skipped for the goal "find live hosts".
- Reach covers discovery (ping, `-Pn`, ARP), DNS and the privilege note.
- Network shows the conditions, the measurement and timing.
- Fine-tune is optional and can be passed with `↵`.
- Choose shows the fast and reliable commands side by side, with their differences and `misses`.

### 5. Fast and reliable: the profile rules, with sources

The profiles set only options the user has not set. Each rule names its source; `misses` is built from the rules that applied.

| Concern | Fast | Reliable | Why [source] |
|---|---|---|---|
| template | `-T4` | `-T4` on a measured LAN or "from scans"; otherwise none (T3) | "If you are on a decent broadband or ethernet connection, I would recommend always using -T4" [P][T]; T3 keeps 10 retries and a 10 s max RTT [T] |
| RTT timeouts | from data: initial 2×, max 3× the largest srtt | initial 2×, max 4× | [P]: "double that for the --initial-rtt-timeout and triple or quadruple it for the --max-rtt-timeout"; clamped to 100–1000 ms [P] |
| retries | `--max-retries 2` (TCP), `1` (UDP) | nmap's default | [P]: "You usually lose some information when Nmap gives up on ports early" |
| closed TCP ports | `--defeat-rst-ratelimit` when the goal is open ports only | none | [P]: closed ports may then read as filtered |
| UDP versions | `--version-intensity 0` | default (7 [VD]) | [UDP]: 12.92 s vs 3691.89 s |
| UDP rate limits | `--min-hostgroup 100` for more than one host | the same | [UDP]: one ICMP unreachable per second on Linux; parallel hosts keep accuracy |
| per host cap | `--host-timeout` 30m (TCP), 3h (UDP) | none | [P]: a timed-out host is skipped with no results |
| host groups | `--min-hostgroup 256`, few ports, more than 256 targets | dynamic | [P] |
| OS on many hosts | `--osscan-limit` with `-Pn` | none | [OS]: "can save substantial time, particularly on -Pn scans" |
| `--min-rate` | only as a user override | never | [ALG]: "at your own risk" |

### 6. RTT data

- Order: earlier scans → measured now → defaults.
- **From scans:** the largest srtt among the targets with `Host.times`, because the timeout must cover the slowest [P]. If fewer than a third of the targets have data, the step says so and still uses it [ALG].
- **Measured now**, offered and confirmed first:
  - with known open ports: up to 8 hosts × 3 TCP connects, 2 s each, 8 s in total;
  - otherwise: `nmap -sn -n -oX -` on up to 8 hosts, reading `<times>`.

  It runs in a worker, and Esc cancels it. A refused or filtered connect is no data, not a large RTT.
- **Defaults:**
  - LAN: `--max-rtt-timeout 100ms` [P];
  - Internet or unknown: nothing set, the template's adaptive timing [ALG].
- Every timing value carries its sentence, for example: "from earlier scans: slowest of 12 hosts 1.2 ms (10.0.0.7), raised to the 100 ms floor".

### 7. The terminal flow (UX)

`BuilderScreen` is one modal on the `_Fits` frame, with four regions. **At 120 columns or wider:**

```
╭ Build a scan · 24 targets ───────────────────────────────────────────────────────────────╮
│  ✓ Goal        How are the hosts reached?                    -Pn                         │
│  ✓ Protocol                                                  Treat all hosts as online:  │
│  ✓ Ports       ○ Ping first             nmap's default       skip host discovery.        │
│  ● Reach         + hosts that are down cost nothing          Takes no value.             │
│  ○ Network       − firewalls drop pings; live hosts look     Root: not needed.           │
│  ○ Fine-tune       down and are not scanned                  Conflicts: -sn, -sL.        │
│  ○ Choose      ● Treat all as up  -Pn   recommended          man-host-discovery          │
│                  + 22 of 24 were seen up in earlier scans                                │
│                  − every target is port-scanned, up or not                               │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│  nmap -sS -Pn -p 22,80,443 -T4 --max-rtt-timeout 100ms  ‹24 targets›                     │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│  ↑↓ move  ↵ choose  ← back  ? help  ^S finish  Esc leave                                 │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

**Below 120 columns**, the step list becomes one line ("Step 4 of 7 · Reach  ✓✓✓●○○○"), and the help opens over the content with `?`. **At 60×18** the content scrolls, and the step line, the command and the key line stay on screen (the `_Fits` rule).

The UX rules are drawn from the TUI design guide, and each is held by a test:

- **Where am I.** The step list shows done `✓`, current `●`, ahead `○` and skipped `–`, in characters, never by colour alone. A done step can be revisited with its number or by clicking it.
- **One decision per step**, in reading order. The recommended choice says `recommended` in words, and the reason is on its `+` line.
- **Trade-offs in the same shape everywhere:** a `+` line for what the choice gains and a `−` line for what it costs, dim, under the choice. The options a choice adds are shown inline, so the user learns the flags.
- **The command is always visible.** The targets are folded to `‹24 targets›`, because the command step shows them in full. The command changes the moment a choice is highlighted, before it is taken, so every choice is previewed.
- **Fine-tune** is a grouped list:
  - the eleven groups are section headings with counts of the options set;
  - a row reads `[x] -Pn` for a flag, or `--max-retries  2  ‹profile: fast›` for a value;
  - `/` filters by name or description, `Space` toggles a flag, and `↵` edits a value in place;
  - an invalid value shows `✗ expected a time, e.g. 30m or 900s` under the row and stays out of the command;
  - `r` returns a value to the derived one;
  - options seek controls are dimmed with their reason;
  - set options can be shown first with `s`.
- **Help** for the focused choice or option: its description, value form, default, root, conflicts and source page. It sits beside the content when wide, behind `?` when narrow.
- **States:**
  - measuring shows a progress line and `Esc cancel`;
  - a failed measurement says why and offers defaults;
  - no data says "nothing measured" in the Network step;
  - an empty selection still has two commands, because both are always produced.
- **Leaving:** `Esc` on an untouched builder closes it; with answers given, it asks "Discard the answers? d discard · c continue" (a `ChoiceScreen`).
- **Finishing** (`^S`, or `↵` on Choose) passes the chosen command, with the targets, to `CommandScreen`, then to the review, unchanged.

Keys:

| Key | Action |
|---|---|
| `↑↓` `j` `k` | move within the step |
| `↵` | take the choice and go on; in fine-tune, edit the value |
| `←` `h` `Backspace` | back one step, keeping the answers |
| `→` `l` | forward to the next step already done |
| `1`–`7` | jump to a done step |
| `Space` | toggle a flag (fine-tune) |
| `/` | filter options (fine-tune) |
| `r` | reset to the derived value (fine-tune) |
| `s` | show set options first (fine-tune) |
| `?` | help for the focused item |
| `^S` | finish: go to Choose |
| `Esc` | leave, asking if answers were given |

They are bound on `BuilderScreen`, so no `priority=True` app binding is involved (the modal-leak rule). `?` opens the builder's help, not the app's.

The **chooser** (`ChooserScreen`, replacing `PresetScreen` as the entry) is one `OptionList` with section headings as disabled options:
- `Build a command…` (with "guided, explains each option");
- `Recent` (5);
- `Frequent` (5, with a "used 12×" count);
- `Presets` (the existing two-line rendering).

Each earlier command shows its arguments and, dim, where it came from: "this engagement · 2026-11-08 14:02" or "history · used 7×". Typing filters the whole list.

### 8. Recent and frequent, without targets

`strip(argv)`:
- drops the program;
- drops every option whose `owner` is set, with its value;
- drops `--exclude`/`--excludefile` and their values;
- drops positional targets, using the catalogue's arity to tell a value from a target. An unknown option is assumed to take no value, and a following target-like token is dropped, so the rule errs towards forgetting an argument and never towards storing a target.

The sources: the session's `ScanFile.args` (newest first by `<nmaprun start>`) and `nmap-commands.json` in the state directory (`{args: {count, last}}`, at most 200, least recent dropped, written when `Session.start_scan` succeeds). `{ports}` is restored where the port list equals the known open ports.

This history is the viewer's one exception to "stateless". It records the user's habits and nothing about the engagement. AGENTS.md records the exception.

### 9. The browser

- `GET /api/v1/builder` takes the `State` as JSON in the query and returns the steps, the current step's view, the command and the help.
- `POST /api/v1/builder/measure` sends nothing unless `confirmed: true` is in the body.
- `GET /api/v1/scans/recent` returns the earlier commands.

The dialog follows the same regions: a stepper (`<ol>` with `aria-current="step"`), the content, the command and the key bar. Choices are a radio group: arrow keys move, and each `+`/`−` line is in the option's description (`aria-describedby`). Fine-tune is a `<details>` per group with a filter box. Errors are `aria-invalid` with the message in `aria-describedby`. The builder's keys go into `keys.js` as a dialog scope, following the parity rule.

## Risks / Trade-offs

- [The catalogue goes stale as nmap adds options] → every entry cites its page, the parity test compares the catalogue with [S]'s list, and the command editor (`CommandScreen`) still accepts any option the catalogue does not know. The builder is a guide, not a gate.
- [Conflict rules that nmap enforces but does not document] (`-F` with `-p`) are marked "refused by nmap" rather than cited, and are kept few.
- [A large surface: about 120 options] → fine-tune is optional, opens with the set options first, filters on `/`, and the guided steps cover the common decisions. Most users never open it.
- [A value with shell characters (`--data-string 'a$b'`)] → `parse_command` refuses `$` and backticks. The field says so at once instead of failing at the command step.
- [A measurement on a filtered network sees nothing] → no data, labelled, and the defaults apply.
- [One far host inflates the RTT] → the timing sentence names it, so the user can see why.
- [Explanations drift from the docs] → the texts live beside the rules, each with its source, and a test pins the documented figures (78/93 %, 39/49 %, 12.92 s vs 3691.89 s, intensity 7/2/9, T4 1250 ms / 6 retries).

## Open Questions

- The fast profile's `--host-timeout` values (30m / 3h) follow the shipped presets. They can be tuned after use without changing the specs or the structure.
