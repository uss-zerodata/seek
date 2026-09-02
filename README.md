# seek

Interactive terminal search for files, directories, and file contents — one
persistent TUI that fuzzy-matches filenames, directory names, and file contents
at the same time.

> Status: in development. See `openspec/changes/terminal-search-app/` for the
> specification this implements.

## Install & run

`seek` is distributed for now as a source checkout run through
[uv](https://docs.astral.sh/uv/):

```bash
# from a clone
uv run seek

# or straight from git
uvx --from git+https://github.com/<you>/search seek
```

## Reading nmap scans

```bash
seek nmap scan.xml                       # one scan
seek nmap discovery.xml services.xml     # consolidated
seek nmap scans/                         # every scan in a directory
```

Reads nmap XML output as *records* rather than lines. Several scans are
consolidated into one model — a host seen in five files is one host, its services
unioned, and each row records which scans it came from. Stateless: no import
step, no database, nothing written. Parsing is ~11 ms per MB, so a five-scan
engagement opens in well under a second.

The overviews are tabs — **Hosts**, **Services**, **Statistics**, **By service**,
**By product**, **By port**, **Names**, **Scans** — clickable, or `v`/`V` to
cycle and `s`/`b`/`u` to jump. Hosts shows address, hostname, OS and service count; Services shows port,
protocol, name, product, version, extra info, host count and vulnerabilities,
grouped across every host. `Enter` drills in both directions and keeps going:
a host opens its services, a service opens every host running it, and a host in
that list opens its record again — so any angle on the data is reachable by
digging on rather than by unwinding first. Grouping rows and the per-service
lines of the statistics view open the hosts behind them the same way. The
statistics tab is divided into headed sections — **Coverage** (targets, asserted
up, reachable by evidence, hosts with open ports and the two distinct totals),
**Services** and **Ports**, one line per name and per open port with how often it
occurs — ordered by count, and sorting reorders the lines inside each section
rather than scrambling them together. `Esc`
unwinds one level per press, as in a search session, landing back on the row the
level was opened from. The tab row follows the jump: a drill-down that lands on
another overview's subject — a service across every host, the hosts in a bucket —
marks that tab, while the breadcrumb keeps the path back. Only a tab you select
yourself replaces the drill-down. The filter box uses the same fuzzy grammar (`'exact`,
`^prefix`, `!negate`, AND terms).

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k` | select a row — the detail below follows |
| `←` `→` | scroll the detail of the selected row |
| `PageUp` `PageDown` | page the list |
| `Home` `End` / `g` `G` | first / last row |
| `Enter` | open the selected row — press again to keep digging |
| `v` `V` | next / previous overview tab |
| `/` | filter (`Enter` or `Esc` returns to the list) |
| `1`…`9` | sort by that column, ascending — or click its heading |
| `r` | reverse the sort |
| `d` | show / hide the detail pane |
| `s` | statistics · `b` group by · `u` reachable only |
| `m` `M` | mark the selected row · clear every mark |
| `n` | new scan · `o` report view · `p` freeze log · `c` cancel |
| `x` | export · `?` help · `q` quit |
| `Ctrl+P` | command palette — every action above, searchable by name |
| `Esc` | leave filter → clear it → back one level → quit |

**Marking and export.** `m` marks the selected row and `M` clears every mark. A
row marks what it *stands for*, so `m` on the `https` row of **By service** marks
every host running it, and marks survive filtering, sorting, drilling down and
switching tabs — the set you want is usually collected across several views.
`x` exports the marked records when there are any and the rows on screen when
there are none, saying which before it writes anything. Pick one of the named
lists (hosts, ports, `host:port`, URLs) or `custom…` to choose fields — address,
hostname, OS, state, reachability, source scans, port, protocol, service,
product, version, tunnel, vulnerability count, URL — and write it as plain text,
CSV with a header row, or JSON. Two worked examples:

```bash
# every reachable host, for a focused re-scan
#   Hosts tab → u (reachable only) → x → All hosts → text → file
nmap -sV -iL up-hosts.txt

# every web service, for screenshots
#   By service tab → m on http and on https → x → HTTP/HTTPS URLs → text → file
gowitness file -f urls.txt
```

When a filter leaves nothing, the list says what matched nothing and how to get
back — `Esc` clears it. Modals (export, fields, format) move with `↑`/`↓`, choose
with `↵` and cancel with `Esc`, and say so on their own last line.

**Running scans.** With nmap on the path (the status line says `⌁ nmap 7.94`, or
`⌁ nmap not found`), `n` starts one: a scope editor — one target per line,
addresses, `10.0.0.0/24`, `10.0.0.1-20`, hostnames or URLs — then a preset, then
the full command as editable text, then a review showing the exact argument
vector, the scope, the file it will write and whether it will be elevated.
Nothing runs until that review is confirmed. Opened on a directory with no scans
in it, the viewer starts at the editor instead of exiting.

The **Scans** tab is a **history**: every scan file present — whether this
session ran it or it was there on disk — ordered by the time it started, each
diffed against the state before it. So a fresh scan dropped into the directory
reads as *what changed*: a new host, a newly open port, a service finally
identified. The first scan is the baseline. `o` cycles a scan's report between an
overview, that diff, and the raw output (the sibling `.nmap` when present, else
reconstructed from the XML); `p` freezes a running scan's log so you can read it
— **the scan keeps running**; `c` cancels for real. A scan run here writes to the
launch directory with `-oA`, leaving the same three files an external one leaves,
and rejoins the history as its file when it finishes.

Presets live in the config file, and defining any replaces the shipped set:

```toml
[nmap_presets]
"01 · Discovery (ICMP, TCP and UDP pings)" = "-vv -T4 -n -sn -PE -PP -PS22,80,445 -PA80 -PU53,123,161,500,31347"
"02 · Services, top 1000 TCP"              = "-vv -T4 -n -Pn -sS --host-timeout 30m"
"02 · Services, versions on the ports already found" = "-vv -T4 -n -Pn -sS -A --host-timeout 30m -p{ports}"
"03 · SMB vulnerabilities (139, 445)"      = "-vv -T4 -n -Pn -p139,445 --script smb-vuln*"
```

**Finding the names a host serves.** An address cannot be asked which names
point at it — DNS resolves names to addresses, and a `CNAME` is only visible to
someone who already knows the alias. A reverse lookup returns at most the one
`PTR` the address owner published, which is why a host running six sites usually
looks like it has one name. What the *server* gives away is another matter, and
four presets read it:

| Preset | What it finds |
| --- | --- |
| `03 · DNS names (reverse lookup, sends nothing)` | the published `PTR` — `-sL -R` sends the targets nothing |
| `03 · Names the services reveal (certs, redirects, NTLM)` | certificate subjects and SANs (the vhost list itself), where HTTP redirects, and the FQDN Windows services announce |
| `03 · Names from certificate transparency (queries crt.sh)` | names issued under the domain — **this queries a third party, not the target** |
| `03 · Virtual hosts (brute force, noisy)` | `http-vhosts` against common names |

Every name is kept with what revealed it, so `shop.example.test` reads
`redirect on 80/tcp, certificate on 443/tcp` — corroborated twice — while a name
seen once says so. Names are then visible everywhere they matter — the
**Names** tab lists each one with where it came from and opens the hosts that
answer to it, the hostname column reads `web.example +2` when a host has more,
a host's record lists every name with its source, a service's record shows the
names its certificate claims and every URL it answers on, and the filter matches
all of them. The **URLs** export then covers the address *and* every
name a host is known by — resolved names and the ones a TLS service claims in
its certificate (`ssl-cert` subject and subject-alternative names, wildcards
excluded) — which is the combined endpoint list a screenshotting tool wants. The
`names` field carries the same list into a CSV or JSON export; the `url` field
stays the address-only form.

Leave out `-iL`, `-oA` and `sudo`: the scope, the output and any elevation are
added for you. `{ports}` expands to the open ports already in the model — the
step you would otherwise grep out of the previous scan's `.gnmap`.

Whether a preset needs root is worked out from its flags, not declared. When it
does and you are not root, the command runs under `sudo -n`, which never
prompts: if sudo would have asked for a password the run fails and says so, and
you can warm the timestamp with `sudo -v` elsewhere, run seek as root, or give
nmap the capability and run unelevated. The command box is not a shell — it is
split into arguments and executed directly, so pipes and redirections are
refused rather than silently ignored.

Every action is a bare key. The list holds focus (so the selected row is always
visible) and the filter is opened deliberately with `/`. Nothing uses `Tab`,
`Alt`+digit or `Ctrl+S` — terminal emulators claim those for focus traversal,
tab switching and flow control.

**Address ranges in the filter.** A term in CIDR notation is treated as a range
rather than as text, and composes with the fuzzy terms:

```
10.10.10.5                  that host exactly (same as 10.10.10.5/32)
10.10.10.32/26              hosts in 10.10.10.0–10.10.10.63
10.10.10.0/24 apache        in that range AND matching apache
10.0.0.0/8 'http !ssl       in that range, exact "http", not ssl
!10.10.10.0/28              everything outside that range
10.0.0.0/8 192.168.0.0/16   in either range
```

Several ranges are a **union** — the way a target list reads — while the fuzzy
terms still AND on top, and a negated range subtracts from whatever the positive
ones admitted.

A prefix is resolved to the network containing it (`10.10.10.32/26` →
`10.10.10.0/26`) and the status line shows which range is applied. A *complete*
address means that host alone; while you are still typing one (`10.10.10.`) it
stays an ordinary fuzzy term and matches everything under it.

Rows are clipped to fit the terminal rather than overflowing — the full value is
in the detail pane, which scrolls with `←`/`→` when a record is long.

Choosing a column and reversing are separate: a number always sorts ascending,
`r` alone reverses. Addresses sort numerically, so `10.0.0.2` comes before
`10.0.0.11`. While a filter is active the matched characters are highlighted in
the list, so you can see why a row survived.

**The detail pane follows the selection.** A table only has room for a few
columns, so everything else a scan carried is shown below it for whatever row
the cursor is on: a host's OS, the state *and the reason* it was recorded with,
which scans saw it; a service's product, version, how it was detected; and the
full text of script results and complete vulnerability records — identifier,
title, state, CVSS where a script gave one, cross-reference ids, disclosure date
and reference URLs. `Ctrl+D` hides it; it drops itself on a short terminal.

**Export** produces the lists you feed to the next command, from whatever the
filter has narrowed to: host addresses, open ports comma-separated (the form
`-p` takes), `host:port` pairs, and HTTP/HTTPS URLs with non-standard ports.

### `-Pn` scans are not taken at their word

With `-Pn` nmap marks *every* target `up`, with the status reason `user-set` —
an assumption, not an observation. On a real /24 scan that means 255 hosts
reported up when only 9 responded to anything.

`seek` classifies each host by the evidence actually present — any responding
port, service, OS match or script result — and lists by that, showing `up*` for
a state that was merely asserted and `no evidence` for the rest. It says so
rather than quietly substituting a different number:

```
⚠  scan asserted 255 hosts up (-Pn) but only 9 show any evidence — listing by evidence
```

The raw state and reason stay visible in the host detail, and a scan run *with*
host discovery is unaffected.

## Shell integration

To let a chosen directory change your shell's working directory, add to
`~/.zshrc` (or `~/.bashrc`):

```bash
eval "$(seek init zsh)"
```

This defines a `seek` shell function that wraps the program and performs the
`cd` when you pick a directory. It is safe to keep in your rc file even if
`seek` is not installed.

## Usage

```
seek [OPTIONS] [PATTERNS]...

  -f, --file          search filenames
  -d, --directory     search directory names
  -c, --content       search file contents
                      (with no mode flag, all three are active)
  -r, --regex         treat PATTERNS as regexes instead of globs
      --gitignore     honor .gitignore / .ignore while walking
      --config-path   print the config file path and exit
      --init-config   write a starter config to that path and exit

Examples:
  seek
  seek '*.py' '*.toml'
  seek -c 'src/**'
  seek -r '2026-.*\.log$'
```

`seek` scans the tree once at startup and treats it as unchanged for the rest of
the session, so re-rooting (`Ctrl+R`) and going back up (`Alt+←`) are instant
rather than re-scanning. Press `Ctrl+G` to re-read the filesystem after changing
files on disk.

Patterns without a `/` match a path's basename at any depth; patterns with a
`/` match the path relative to the search root. Matching is smart-case (case
insensitive unless the pattern has an uppercase letter).

The walk includes hidden files, follows symlinks (with loop detection), always
skips `.git`, and by default also skips `node_modules`, `.venv`, `__pycache__`,
`target`, and `dist`. `.gitignore` is **not** applied unless `--gitignore` is
given.

## Layout

Like `fzf`'s default: the `❯` query prompt is at the **bottom**. Directly above
it a one-line **hint bar** shows the keys that matter right now (and what `Esc`
will do next); above that a status line carries the match modes
(`files·dirs·content`, bright = on, plus the keys that toggle them) on the left
and the `shown / total` count on the right. While results are still coming in
the `❯` turns into a spinner and the status line shows `scanning …` (walking the
tree) or `searching …` (scanning file contents); both clear once the list
settles. A thin blue rule under the result
list separates it from that bottom cluster. The result list fills the space with
the **best match on the bottom row** (next to the query) and weaker matches
further up, and the preview sits on top. On a short terminal the preview is
dropped so the result list stays readable; the hint bar is always kept. Colours
(result markers, matched text, path vs. content, the tree view, the preview) are
overridable in the `[theme]` config table.

With an empty query the result list is replaced by a tree of the current root,
headed by a line naming the root and the walk semantics in effect.

## Keybindings

The query box is always focused, so actions use modifier keys or the action
menu (`Ctrl+K`). You do not need to memorise them: the hint bar above the prompt
shows the relevant keys for whatever you are doing, and `?` (on an empty query)
opens the full reference, including the query syntax.

| Key | Action |
| --- | --- |
| `←` `→` | move the query cursor |
| `↑` `↓` | move the highlighted row (cursor starts on the best match) |
| `PageUp` `PageDown` | page the list |
| `Enter` | open the full-screen detail view |
| `Esc` | close overlay/detail → clear a non-empty query → pop breadcrumb → quit |
| `Tab` | mark / unmark the row |
| `Shift+Tab` | clear all marks |
| `Alt+↑` `Alt+↓` | recall previous / next query |
| `Ctrl+F` `Ctrl+_` `Ctrl+T` | toggle filename / directory / content mode |
| `Ctrl+N` | toggle re-indenting of minified files |
| `Ctrl+R` | re-root the search at the highlighted directory |
| `Alt+←` | pop one breadcrumb level |
| `Ctrl+G` | refresh (re-walk from disk) |
| `Ctrl+K` | action menu |
| `Ctrl+O` | open in the OS default application |
| `Ctrl+E` | open in the configured editor |
| `Ctrl+B` | open in `code` |
| `Ctrl+Y` | copy path(s) |
| `Ctrl+X` | export (stdout / clipboard / file) |
| `Alt+C` | go to directory (a file result → its parent; needs the shell wrapper) |
| `Ctrl+P` | command palette — every action above, searchable by name |
| `?` | help |

In the **detail view** (`Enter`): `↑`/`↓` or `j`/`k` scroll, `Ctrl+U`/`Ctrl+D`
half-page, `PageUp`/`PageDown` or `b`/`Space` page, `g`/`G` jump to top/bottom,
`Esc`/`q` back. The same open keys as the list (`Ctrl+E` editor, `Ctrl+O`
default app, `Ctrl+B` `code`) act on the file you are viewing, and the view
shows these controls along its bottom edge. Query matches stay highlighted while
scrolling.

Long result rows are **shortened to one line** (windowed to keep the match
visible); set `wrap_results = true` in the config to wrap them instead. The list
shows at most `max_results` rows (default 500); the status line shows
`shown / total` when there are more.

## How matching differs from ripgrep / fd

- The query box is **fuzzy** (fzf extended syntax), not a regex. `main fn` means
  "fuzzy-match `main` AND fuzzy-match `fn`". Use `'exact`, `^prefix`, `suffix$`,
  and `!negate` for precision. Content lines are matched with the same fuzzy
  query, so `seek` finds lines `rg` would miss (scattered characters) and orders
  them by a fuzzy score rather than file/line order.
- **Smart-case** matches `rg`/`fd`: a query or pattern is case-insensitive
  unless it contains an uppercase character.
- `.gitignore` is **ignored by default** (opposite of `rg`/`fd`); pass
  `--gitignore` to honour it. `.git` and common build/vendor directories are
  always skipped.
- Binary files are skipped for content search (like `rg`) but still match by
  name. Detection reads only the file's first few KiB, so a large binary costs
  a header read rather than a full one.
- **Minified files are re-indented before being indexed.** A `.json`, `.xml`,
  `.html`, `.svg`, `.css`, `.js` or `.yaml` file containing a line longer than
  `format_min_line` (default 500 chars) is broken into short indented lines at
  its structural boundaries. This matters for more than readability: because the
  query is a fuzzy *subsequence* test, one 50,000-character line contains every
  character in every order and so matches essentially any query, crowding out
  real results. The result row, preview and detail view all show the re-indented
  text, and the preview header marks it `· formatted`. Reported line numbers
  still refer to the file as stored, so `path:line` and "open in editor" stay
  correct. Toggle it with `Ctrl+N`, or set `format_content = false`; tune with
  `format_min_line` and `format_extensions`.
- Only the first `content_size_cap` bytes of a file (default 5 MiB) are searched
  for content matches, so one huge log or database file in the tree cannot stall
  the session. Matches beyond that point are not reported; raise the setting if
  you need them.

## Configuration

Optional TOML file at `~/.config/seek/config.toml` (Linux; `seek --config-path`
prints the exact location). Install a fully-commented starter there with

```bash
seek --init-config      # writes the file; won't overwrite an existing one
```

then edit that file — the app reads it on the next run. The shipped
[`config.example.toml`](config.example.toml) is the same content for reference;
editing the example does nothing, because the app reads the installed copy.

## Development

```bash
uv sync
uv run pytest
uv run ruff check
```

## Migrating from the `s` / `f` / `d` functions

Keep the old functions during the transition, then replace them with thin
wrappers:

```bash
s() { seek "$@"; }
f() { seek -f "$@"; }
d() { seek -d "$@"; }
```

Rollback is just restoring the old function bodies — this change deletes
nothing.
