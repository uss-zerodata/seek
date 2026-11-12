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
seek nmap                                # every scan under the working directory
seek nmap scan.xml                       # one scan
seek nmap discovery.xml services.xml     # consolidated
seek nmap scans/                         # every scan under a directory
seek nmap site-a/ site-b/ day2/          # several directories, one merged view
```

Several directories are read as one engagement. A scan found through two of
them (a directory and one of its subdirectories, say) is read once. Their scans
are then named by where they sit below the directories' common parent —
`site-a/scan.xml`, `site-b/scan.xml` — everywhere a scan is named, because tools
write the same file names into every directory and a bare `scan.xml` could be
either. gowitness captures are found the same way as the scans — any results
database at any depth, under any name (a database named on the command line is
read as a capture) — and each screenshot is looked up from where its database
is: its `screenshots/`, its own directory, anywhere below it, then anywhere
below the directories given, so a database copied away from its images still
opens them. Scans
and captures started in the viewer write into the **first** directory; the
status line, the scan review and the capture entry say so before anything runs.

A directory is searched all the way down, so an engagement directory whose scans
sit in per-phase or per-target subdirectories can be named instead of its files,
and with no argument at all the working directory is searched. Discovery keeps
the `.xml` files that open as nmap output and passes over the rest, so a stray
`pom.xml` is not reported as a skipped scan; a file you name yourself is always
read, and told about if it cannot be. A search that takes more than a moment
says how many scans it has found, on one line that clears itself before the
viewer opens — and prints nothing when the output is piped.

Reads nmap XML output as *records* rather than lines. Several scans are
consolidated into one model — a host seen in five files is one host, its services
unioned, and each row records which scans it came from. Stateless: no import
step, no database, nothing written. The viewer opens on the files rather than
after them, so a five-scan engagement is on screen immediately and a hundred
and twenty scans fill in as they are read.

The overviews are tabs — **Hosts**, **Services**, **Statistics**, **By service**,
**By product**, **By port**, **Inventory**, **Findings**, **Names**, **Scans** — clickable, or `v`/`V` to
cycle and `s`/`b`/`u` to jump. Hosts shows address, hostname, OS and service count; Services shows port,
protocol, name, product, version, extra info, host count and vulnerabilities,
grouped across every host. `Enter` drills in both directions and keeps going:
a host opens its services, a service opens every host running it, and a host in
that list opens its record again — so any angle on the data is reachable by
digging on rather than by unwinding first. Grouping rows and the per-service
lines of the statistics view open the hosts behind them the same way. The
statistics tab is divided into headed sections — **Coverage** (targets, asserted
up, actually up, hosts with open ports and the two distinct totals),
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
| `←` `→` / `h` `l` | move the detail pane's line cursor · `o` opens an underlined line |
| `PageUp` `PageDown` | page the list |
| `Home` `End` / `g` `G` | first / last row |
| `Enter` | open the selected row — press again to keep digging |
| `v` `V` | next / previous overview tab |
| `/` | filter (`Enter` or `Esc` returns to the list) |
| `1`…`9` | sort by that column, ascending — or click its heading; again reverses it |
| `r` | hosts with at least one open port only (on a host: open ports only) |
| `d` | open the detail full-screen: searchable, `o` follows links, `←`/`→` steps entries (or scans, in nmap's text) · `D` show / hide the pane |
| `s` | statistics · `b` group by · `u` up hosts only (on a host: open ports only) |
| `m` `M` | mark the selected row · clear every mark |
| `n` | new scan · `o` report view · `p` freeze log · `c` cancel |
| `U` | scan the open ports that have no version yet (`-sV --version-all`) |
| `A` | update the local vulnerability database (asks first, says what it downloads) |
| `x` | export, or capture the URLs with gowitness · `?` help |
| `i` | open a capture's screenshot · `W` serve gowitness's report · `w` open the web interface |
| `Ctrl+P` | command palette — every action above, searchable by name |
| `Esc` `q` | leave filter → clear it → back one level → quit · `Ctrl+Q`/`Ctrl+C` quit from anywhere |

**Marking and export.** `m` marks the selected row and `M` clears every mark. A
row marks what it *stands for*, so `m` on the `https` row of **By service** marks
every host running it, and marks survive filtering, sorting, drilling down and
switching tabs — the set you want is usually collected across several views.
`x` exports the marked records when there are any and the rows on screen when
there are none, saying which before it writes anything. Pick one of the named
lists (hosts with open ports, up hosts, all hosts, ports, `host:port`, URLs) or
`custom…` to choose fields — address, hostname, OS, state, up, source scans, port, protocol, service,
product, version, tunnel, vulnerability count, URL — and write it as plain text,
CSV with a header row, or JSON. Two worked examples:

```bash
# every up host, for a focused re-scan
#   Hosts tab → x → Up hosts → text → file   (the same list as u → All hosts;
#   r → All hosts gives the hosts with open ports)
nmap -sV -iL up-hosts.txt

# every web service, for screenshots
#   By service tab → m on http and on https → x → HTTP/HTTPS URLs → text → file
gowitness file -f urls.txt
```

**Software inventory.** The **Inventory** tab lists every product and version
running anywhere, one row per `(product, version)` with its kind, CPE, how
many hosts and services run it, and how sure the identification is. It is built
from everything already read — nmap's version probe and the `<cpe>` identifiers
it writes, OS detection, the scripts that name a service's own software
(`http-server-header`, `Server:` / `X-Powered-By:` lines and SSH, FTP and SMTP
greetings in `fingerprint-strings` and `banner`, `http-generator`,
`smb-os-discovery`, the CPEs `vulners` keys on) and gowitness captures of the
service (detected technologies such as `PHP:7.4.33`, response headers, the
page's `<meta name="generator">`). Nothing is sent over the network to build it.
A web port lists its whole stack — nginx 1.16.1, PHP 7.4.33 and jQuery 2.1.3 are
three components of one service. When two sources name the same product the
more trusted one's version is shown (probe, then banner, then header, then
detection), a more specific version (`8.9p1` over `8.9`) fills in rather than
conflicts, and a real disagreement is marked `conflict` with every version
listed in the service's **Software** block. A CPE comes from nmap or from a
curated table of common products and is never guessed; anything else says
`no CPE`. Filter by source (`gowitness`, `banner`), by `conflict`, `unversioned`
or `no-cpe`. `x → Software inventory` writes it as CSV or as a versioned JSON
document (`"schema": "seek.inventory", "version": 1`), and the web interface
serves the same document at `/api/v1/inventory`. `U` drafts one
`-sV --version-all` scan of the open ports nothing has versioned yet — over the
marks, or the rows on screen — and says how many extra host/port pairs the
shared port list adds before you review it.

**Vulnerabilities and end of life.** With a local vulnerability database, the
Inventory tab answers the two questions a review asks of every product at a
glance: **Support**, coloured by its answer — green `current (2024-08-14)` with
the release date, yellow `behind · 2.4.62` or `mixed` (a version family such
as Linux 5 where some lines are still supported), red `EOL 2022-11-28`, dim
`—` when no version or no source is known; `· ends soon` within 90 days of the
end date. Products are matched to endoflife.date by the CPEs it declares;
OpenSSH and Exim, which support only their latest release, are judged against
the newest release NVD knows and **Vulns** / **Max** (how many
known vulnerabilities affect *this* version, and the worst of them). It opens
sorted worst first. The **Findings** tab lists every CVE or advisory that
affects something in the engagement, and `Enter` lists the services it affects.
Filter by `eol`, `behind`, `unsupported`, `critical`, `high`, or a CVE id.

What nmap itself *tested* (the NSE `vuln` scripts, host scripts such as
`smb-vuln-ms17-010` included) is always shown first, as **Confirmed by nmap**,
whatever the database says. When a version names only a family — `Python/3.8`
from a header — each CVE is checked against every 3.8.x release NVD knows: if
all are affected it is a finding, if none it is dropped, and otherwise it is a
**most likely** candidate with its share (`20/21 known 3.8.x`), so the obvious
ones to verify come first.

The data is public and local: NVD's CVE feeds and CPE dictionary (every known
release per product), OSV advisories for client-side libraries (jQuery,
Lodash, Vue.js, …) and endoflife.date release cycles, stored
in one SQLite file in the state directory. Only an explicit update touches the
network, and it never sends anything about the engagement — every request is a
whole public feed:

```bash
seek vulndb update          # first run: several hundred MB; later runs: what changed
seek vulndb status          # where it is, how old, what it holds
```

The viewer offers the update when the database is missing or older than
`vulndb_stale_days` (7), and `A` runs it after saying what it will download.
For an offline machine, copy the file and point `vulndb_path` at it. The CVEs
the scan's own `vulners` script reported are kept and shown with their source.
Matching is by version: a version the ranges cannot place is shown as
*undecided*, never as safe — so is a version that names only a family (`4`
against a range ending at `4.4.1`); operating systems from nmap's fingerprint
get their support status but no CVE list, since a guessed kernel family would
bury everything else under thousands of kernel CVEs; a product without a
version gets no findings, only
how many exist for it (and `U` to scan for the version); and a distribution
that backports a fix without changing the version number (`8.9p1
Ubuntu-3ubuntu0.6`) is still listed — every record says so. The inventory
export (document version 2) and `/api/v1/inventory` carry support and findings
per entry; `/api/v1/findings` lists them by finding.

When a filter leaves nothing, the list says what matched nothing and how to get
back — `Esc` clears it. Modals (export, fields, format) move with `↑`/`↓`, choose
with `↵` and cancel with `Esc`, and say so on their own last line.

**Tagging hosts.** A tag names a kind of host or service - `printer`,
`zebra-zd420`, `explored` - and can carry known issues, so a weakness that a
whole model of device shares is flagged on every host that is that model. A tag
is granted by rules in a YAML file, or by hand. Rules read the scans and the
gowitness captures: ports, products, versions, scripts, certificates, page
titles and bodies, redirects, headers and names.

```yaml
tags:
  zebra-zd420:
    description: Zebra ZD420 label printer
    issues:
      - title: Admin interface protected only by a 4-digit PIN
        severity: medium            # info, low, medium, high or critical
    rules:
      - name: ZD420 status page, no ssh
        when:                       # every condition must hold
          - port: 80/tcp
            body: {literal: "ZD420"}
          - port: 9100/tcp
          - not: {port: 22/tcp}     # no port of the host is 22/tcp open
```

A tag is granted when any of its rules matches, and its issues go to every host
it is granted to - so keep issues on narrow tags, and a broad tag like `printer`
without them. Keys in one condition describe one port: `{port: 80, product:
nginx}` is nginx on port 80, not nginx somewhere. `port:` also takes a list -
`"80,443,8000-8999/tcp"` or `[80, 8080]` - and then one port of the list must
meet every key. Without `state:` a port must be open. `not:` takes one condition and means that no port of the host
satisfies it. `any:` and `all:` group conditions, `tag:` asks for another tag,
and `grant: service` (or `both`) tags the matching ports instead of the host.
Text is a regular expression matched anywhere and ignoring case; `{regex:
"READY", case: true}` respects case, `{literal: "Jetty(i-jetty)"}` matches
the text as written anywhere in the value, and `{equals: "Zebra httpd"}` must be
the whole value (ignoring case unless `case: true`). Quote values YAML would read as something else: `"no"`,
`"1.10"`.

The rule files of the colleague's tool `categorize_systems` are read as they
are - `rules:` with `nmap_port`, `html_title`, `html_body`, `html_redirect`,
`service_match`, `has_tag`, `all` and `any` - and can sit in one file with a
`tags:` section. Two things differ there on purpose: text ignores case and is
searched, and a service tag goes to every port a condition matched, where
`categorize_systems` tags only the ports common to every pattern of a rule.
`examples/seek-rules.yaml` is a starting point.

**Where rules live.** seek reads every `seek-rules.yaml` (or `.yml`) and every
`seek-tags.yaml` in the opened folders and every folder below them, by the rules
that find scans - folders whose name starts with a dot are not searched - and
`rules.yaml` and `tags.yaml` in the config directory. All of them apply to every
scan that is open, so opening the parent of everyone's scan folders tags them
all the same way. `seek-rules.yaml` is yours: seek reads it and never writes
it. `seek-tags.yaml` is seek's: manual tags and the definitions made in the
viewer go there, in the first opened folder; edit it if you like, but comments
do not survive seek's next write. A file seek cannot read is skipped with a
problem that names it and the line, and never rewritten. When two files define
the same tag differently:

| The files | Which definition applies |
| --- | --- |
| One in a folder below the other's | the deeper one, with a warning |
| A project file and a global file | the project's, with a warning |
| Side by side, or in unrelated folders | both: rules and issues combined, with a warning |
| Identical definitions | one, without a warning |

**When a tag is an assumption.** `not: {port: 22/tcp}` is only certain where
some scan probed port 22 on that host - nmap names the ports each scan probed,
and seek reads that. Where no scan did, or the host timed out, the tag is still
given but marked `?`, and the record says what is missing (`22/tcp not
scanned`), so you can scan exactly that. The same holds for a negated test of a
page title or body where there is no capture. A negation without a port -
`not: {service: ssh}` - cannot know about ports nobody scanned and counts as
certain. A positive test without its data simply does not match; a body test on
a capture made without bodies is reported as not evaluated. Bodies are read
from the capture database only for ports that pass a rule's other tests, and
only the first megabyte of each page is searched. Expressions run without a
time limit, so avoid nesting quantifiers such as `(a+)+`.

**Tagging by hand, and building a rule.** `t` tags the marked rows, or the
selected one: pick a tag (picking one they all carry removes it), type a new
name, give a tag a description and issues, or copy a tag's definition to the
global `tags.yaml` - a copy never carries an address. Tags are saved in
`seek-tags.yaml` in the first opened folder, so `explored` and `high-value`
survive the session. `T` turns marked hosts into a rule: it lists what they all
share, each with how many other hosts share it too, rarest first, and offers the
common start or end of values that differ (` - READY`). Tick the facts; when
they also match hosts you did not mark, it lists what those hosts have and yours
do not - `not 22/tcp open, excludes 500/500` - and says when an exclusion is
only an assumption for one of yours because port 22 was never scanned there.
The preview counts the result before you save it to a tag. A tag marked `?`
names what is missing: filter `tag:zebra-zd420`, mark the uncertain hosts and
send them to a scan of exactly that port from the export dialog. `R` reads the
tag files again; `tag:` filters, `b` groups by tag.

**Running scans.** With nmap on the path (the status line says `⌁ nmap 7.94`, or
`⌁ nmap not found`), `n` starts one: a scope editor — one target per line,
addresses, `10.0.0.0/24`, `10.0.0.1-20`, hostnames or URLs — then a preset, then
the full command as editable text, then a review showing the exact argument
vector, the scope, the file it will write and whether it will be elevated.
Nothing runs until that review is confirmed. Opened on a directory with no scans
in it, the viewer starts at the editor instead of exiting.

**Building a command.** After the scope, `n` opens a chooser:
- **build a command…**, a guided builder;
- your **recent** and **frequent** commands;
- the presets.

Type to filter all of them at once. The builder asks one question per step:
goal → protocol → ports → how hosts are reached → names → network → fine-tune
→ choose. Every choice says what it gains (`+`) and what it costs (`−`), with
nmap's own figures (top 100 ports find about 78 % of open TCP ports, top 1000
about 93 %). The command updates as you move, so each choice is previewed.

The network step takes RTT timeouts from what earlier scans of the targets
measured. If nothing covers them, it offers to measure now. Before anything is
sent it says what it will send, to how many hosts, and for how long: a few TCP
connects to ports known open, or a bounded `nmap -sn`. Every derived value says
where it came from, for example "earlier scans: slowest of 12 hosts 1.2 ms,
raised to the 100 ms floor".

**Fine-tune** lists every option nmap documents, in nmap's own eleven groups:
- `Space` turns a flag on or off; `↵` edits a value, checked as you type;
- `/` filters; `r` resets a value; `s` lists set options first;
- options seek controls itself (output files, `-iL`) are shown with the reason.

A value you set always wins. **Choose** shows a **fast** and a **reliable**
command for the same answers, with what the fast one may miss. Either goes to
the editable command and the review. Keys: `←` back, `1`–`8` a done step, `?`
help, `^S` finish, `Esc` leave (it asks before discarding answers). The browser's
new-scan dialog offers the same chooser and builder.

Earlier commands come from this engagement's scan files, and from
`nmap-commands.json` in the state directory. That file holds **arguments only**:
targets, paths and output options are removed before anything is written, so
one engagement's scope never reaches the next.

**Notifications.** Set `notify_url` in the config (for example
`notify_url = "notify.hektor.cc/test"`; `https://` is added when no scheme is
given) and seek POSTs an [ntfy](https://ntfy.sh)-format message there when a
scan or a gowitness capture finishes, fails or is cancelled. With
`notify_progress = true` it also sends one at 25, 50 and 75 % done, as the tool
reports it. Every review shows both, so one run can use another URL, or none.
A message names the preset (or "gowitness capture"), the outcome and the time
taken, and nothing else: no target, address, host name, URL, path or tool
output leaves the machine. A failed delivery never changes the run; it is a
line in the run's log.

**Scanning from another machine.** The review — for a scan, and for a gowitness
capture — also copies the command: `y` copies a snippet for another machine,
`Y` the command exactly as it would run here. The snippet calls plain `nmap` or
`gowitness` (never docker), uses `sudo` when the flags need root, writes to
paths relative to where you paste it, and for a capture writes its own URL list —
no path of this machine is in it. This works without nmap or gowitness
installed here: the review says why it cannot start, and copying still works.
To bring the results back, copy the `.xml`/`.nmap`/`.gnmap` files, or the
`gowitness/` directory, into a scan directory; they are read like any scan made
outside seek. If no clipboard is available, the text is shown to select by hand.
The browser's review dialogs have the same two buttons and keys.

The **Scans** tab is a **history**: every scan file present — whether this
session ran it or it was there on disk — ordered by the time it started, each
diffed against the state before it. So a fresh scan dropped into the directory
reads as *what changed*: a new host, a newly open port, a service finally
identified. The first scan is the baseline. `o` cycles a scan's report between an
overview, that diff, and the raw output (the sibling `.nmap` when present, else
reconstructed from the XML); `p` freezes a running scan's log so you can read it
— **the scan keeps running**; `c` cancels for real. A scan run here writes to the
launch directory with `-oA`, leaving the same three files an external one leaves,
and rejoins the history as its file when it ends.

**Results while a scan runs.** nmap scans in host groups and writes each group
to its files when the group is done, so a two-day scan has most of its results
on disk long before it ends. seek reads them in as it goes: when nmap reports
finished hosts, the model is re-read a few seconds later - quietly, the list
and the cursor stay where they are, and the status line says what the scan has
added so far. At most once a minute (less often at a scale where a re-read takes
long), and only when the file grew. A cancelled or failed scan keeps the hosts it
finished. Several scans can run at once: the review names the running ones and
says what that costs - they share the network path, each one's timing adapts to
the other's traffic, both take longer, and rate-limited targets drop more probes.
`c` cancels the run under the cursor in the Scans tab, or asks which.

**Progress of the whole scan.** nmap's own percentage covers one phase of the
current host group, so it starts over with every group. A running scan shows
the whole scan instead, for example `≈ 31% · port scan 50% · 128/512 hosts ·
≈ 1h 20m left`. The total is nmap's own count of the targets: `nmap -sL -n`,
which lists them without sending anything, and so honours ranges, `-iL` and
`--exclude`. Hosts finished are the ones nmap has reported, down ones included,
and the current group adds its share. That needs `-v`: without it nmap
does not report down hosts, so seek shows the hosts reported and says so. The
progress notifications use the same figure. `--stats-every` prints nothing under
seek: nmap prints those statistics only to an interactive terminal.

**Large engagements.** Measured on 120 scan files covering 24 200 hosts
(106 MB of XML), which is where every figure below comes from; the numbers are
reproducible with `benchmarks/gen_nmap_corpus.py` and `benchmarks/bench_nmap.py`.

*The viewer opens before the scans are read.* `seek nmap` finds the candidate
files — a walk of tens of milliseconds — and hands them over; the reading
happens with the interface already up, and the model is published on a cadence
of about a second rather than once per file, because re-projecting an overview
costs more than reading a file. A batch never takes the list away: the rows
already there were built from part of the same model and every one of them is
still true, so they stay and the rebuild reports in the status line — the list
is scrollable, filterable and drillable throughout, `Esc` keeps its ordinary
meaning, and the cursor stays on the record you left it on — found by what the
row is rather than by its number, since folding a scan in moves every row below
the hosts it added. The next batch is
taken no sooner than the last one took to put on screen, so the interface never
spends more time replacing the list than answering you. The status line says
how many files have been read and how many hosts are known so far. A read short enough
not to matter says nothing at all. If candidate files were found and none of
them could be read, the list says so and names them, and the process exits
non-zero.

*The record shows what nmap wrote.* A host's record and a service's record
list the scans that recorded them, one per line, saying what each one found.
`o` opens the one under the pane's cursor and the pane switches to that scan's
own text, scoped to that host or that port — not the whole file, which runs to
tens of thousands of lines. That is where the things nmap reports only in its
text are readable: `Not shown: 984 filtered tcp ports (no-response)`, the
`REASON` a port was called open, the timing of the scan. The heading says which
of how many scans you are on; the record lists the others. `Esc` goes back to
the record, at the entry it was opened from, and `d` opens whichever of the two the pane is showing full-screen
with search and paging. A scan handed over as XML
alone left no `.nmap` file; its entry shows a report rebuilt from what was
parsed and says so, rather than the feature quietly disappearing.

*The detail pane has a line cursor, like a text editor.* `←`/`→` (or `h`/`l`)
move it up and down one line and the record scrolls to keep it in view, while
`↑`/`↓` (or `j`/`k`) keep moving the list. Every line is a stop; lines that open
something - the scans that saw a host or port - are underlined, and `o` opens
the one under the cursor. Where the cursor has nowhere to go, a scan's report
being one block, the keys scroll instead. To go through the rows' records one
after another, use the full-screen reader (`d`), where `↑`/`↓` scroll and
`←`/`→` step to the previous and next row.

*Every long step reports the same way.* Reading files, folding them together,
building the scan history and projecting an overview all report work done
against work total and name what they are counting — files, scans, hosts — so
each shows a bar with real figures rather than a bare spinner. A step that
cannot count itself yet, such as the directory walk, shows that it is running
instead of a bar at zero. `Esc` stops waiting on any of them; nothing already
read is lost and the tab builds again next time it is opened.

*Nothing long runs on the event loop.* Reading and projecting each run in a
thread with the cycle collector held out of the way and the built model frozen
once it is published — which is what removes the pauses, rather than merely
deferring them: worst-case input latency during a build fell from 1962 ms to
2.4 ms, and the pipeline as a whole from 36.8 s to 15.7 s. Each overview is
projected once per model and kept, so sorting, resizing, drilling in and
filtering never rebuild it, and long lists are handed to the table a chunk per
frame with the status line saying how far the rest has got. Re-reading after a
scan finishes runs the same way, except that the rows already on screen stay:
they are one scan out of date, not wrong, and the status line carries the
progress instead of the list.

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
does and you are not root, seek takes the first route that works, and the
review says which one:

- **nmap's own capabilities.** If the nmap binary has them
  (`sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)`),
  the scan runs as you, with `--privileged` added, and no sudo.
- **sudo.** Before the scan starts, seek checks whether sudo would run nmap
  without asking. If sudo would ask, the viewer steps aside and **sudo itself**
  asks for the password on the terminal; seek never sees it. The scan then runs
  under `sudo -n`. A scan started from the browser cannot let sudo ask, so it is
  refused before it runs, with these same options.

Running seek as root needs neither. The command box is not a shell — it is
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

**Querying the scan.** Field terms ask the model rather than the row's text,
and combine with uppercase `AND` / `OR` / `NOT` (also `|` and `!`) and
parentheses; a space is still AND:

```
open:22                                  port 22 found open (not "22" anywhere in the row)
open:80/tcp                              with the protocol
closed:443                               443 recorded and not open: closed, filtered, open|filtered
service:ssh OR service:telnet            either service
service:http product:nginx               an http port served by nginx - the same port
service:^http$                           exactly http, not https or http-proxy
NOT service:ssh                          no ssh on the host at all
service:http AND NOT (product:apache | product:iis)
10.0.0.0/24 open:445 !printer            ranges and plain words mix in
```

Terms joined by AND describe **one port**, and NOT means **none of the ports**,
so a host with Apache serving http on 80 and nginx serving `https` on 8443 does not match
`service:^http$ product:nginx`. A port no scan recorded is neither `open:` nor
`closed:`. The keys say `open`/`closed` rather than `up`/`down` on purpose: "up"
is the host rule behind `u`. Lowercase `and`/`or`/`not`, and any `key:` that is
not one of the four fields (a pasted `http://…`), stay ordinary search words.
The filter is applied as you type, so a half-finished query never empties the
list: a missing `)` is implied, and a dangling operator or an empty field is
left aside. The status line shows how the query was read, grouping spelled out,
and names anything it left aside. A filter that uses none of this works exactly
as before.

Rows are clipped to fit the terminal rather than overflowing — the full value is
in the detail pane, which `←`/`→` move through when a record is long.

A number (or a click on the heading) sorts by that column, ascending; the same
column again reverses it, and again flips it back. The arrow in the heading and
the status line say which column is sorted, so a list that opens sorted by its
first column reverses on the first `1`. Addresses sort numerically, so `10.0.0.2` comes before
`10.0.0.11`. While a filter is active the matched characters are highlighted in
the list, so you can see why a row survived.

**The detail pane follows the selection.** A table only has room for a few
columns, so everything else a scan carried is shown below it for whatever row
the cursor is on: a host's OS, the state *and the reason* it was recorded with,
which scans saw it; a service's product, version, how it was detected; and the
full text of script results and complete vulnerability records — identifier,
title, state, CVSS where a script gave one, cross-reference ids, disclosure date
and reference URLs. `D` hides it; it drops itself on a short terminal.

**`d` opens that same record full-screen and searchable** — the pane is right
for a glance, but caps out on anything taller than a few lines, above all a
scan's raw nmap output. `/` inside the reader highlights every occurrence in
place rather than filtering lines away, so the context around a hit is never
lost; `n`/`N` jump between matches, with a running count. Opened on a scan that
is still running, the raw view keeps streaming as output arrives, and an active
search keeps matching the new lines; `p` freezes it to read without the scan
stopping, exactly as it does in the pane. `Esc` clears a search first, then
leaves the reader.

The reader has the pane's two levels. On a record, `↑`/`↓` move a line cursor
and `o` follows an underlined link into that scan's text; there, `↑`/`↓`
scroll, `←`/`→` switch to the other scans of the same host or port, and `Esc`
comes back to the record at the link - a second `Esc` leaves the reader. On a
record, `←`/`→` read the previous and next entry in the list
without leaving it, so a record can be compared against its neighbours - and an
active search carries across, recounted against each entry, which is the fast
way to find which host a term actually appears on. The list moves with you:
leaving the reader lands on the entry you last read, not the one you opened it
from.

**Screenshot the web servers with gowitness.** The export dialog's last entry
hands the URL list to [gowitness](https://github.com/sensepost/gowitness)
instead of writing it to a file — after a review of the command, which can also
copy it to run elsewhere — and what comes back lands on the host and
service records themselves: HTTP status, page title, server, detected
technologies, a TLS summary, and the screenshot's path. `i` opens one
screenshot in your image viewer; `W` serves the report and opens a browser at
the selected result itself, or at the gallery when the row covers several. A running capture appears in the Scans tab beside nmap runs, streams
its output, and can be cancelled — and it may run *while* a scan runs, since
screenshotting and port scanning do not contend.

Results are read from the capture's own SQLite database, which is what
gowitness leaves behind whether or not seek ran it — so a capture you made by
hand with `--write-db` is picked up from the capture directory on start up,
with its screenshots, exactly like an nmap file you did not run here. The
record shows the identifying facts inline (status, title, server, technologies,
TLS, and which security headers were *absent*); `d` opens the same record
full-screen with every header, cookie and console message laid out — the reader
shows everything the pane shows and more, never something different.
`gowitness_collect_all` additionally records per-request network logs and
response bodies, off by default because it makes the capture directory grow
without a useful bound.

A screenshot is taken when the page has settled, not after a fixed delay: once
it has loaded, its images are in and nothing has changed for
`gowitness_settle_ms` (2 s), or after `gowitness_settle_cap_ms` (20 s) at the
latest. Raise the first for pages that sit blank before one late response draws
them; `0` puts back gowitness's fixed three-second delay. Watching starts after
`gowitness_settle_delay_s` (1 s), so a page that sends the browser on to its
login as it loads is photographed where it lands, not blank; raise it for
slower redirects, or set `0` to start watching at once.

It runs in docker by default (`ghcr.io/sensepost/gowitness`, pulled on first
use) and falls back to a `gowitness` on `PATH`; `gowitness_mode` pins one or
the other, and a pinned backend never silently falls back. The status bar names
which is in use, or says `not found` — the export entry stays visible either
way, with the reason, rather than disappearing. Artefacts go to a `gowitness/`
directory beside your scans, in gowitness's own formats, so
`gowitness report server` works on them exactly as it would on a capture you
ran yourself — and a capture directory produced outside seek is read on start
up, the same way external scan files are.

The URLs seek sends carry a scheme and an explicit port, which matters more
than it looks: given a bare name gowitness probes it across http/https × 80/443
on its own, so two names become seven probes. Sending complete URLs means one
probe per open port you actually found, and one result per service — and since
gowitness records results under the port it probed, spelling the port out is
also what lets a result be matched back to the service it came from. Captures
are matched on `scheme://host:port` with the default port made explicit, so a
capture made by hand under either spelling still links up.

**The web interface.** gowitness's report server reads one database at a time;
an engagement usually has several. `w` opens seek's own web interface instead:
every capture from every database the viewer found, beside the hosts, ports and
services they show. It runs inside the viewer's own process, on `127.0.0.1:7272` by default
(`web_host` / `web_port`; anything but a loopback address is refused), reads the
same model the terminal shows - a scan or capture that finishes while it is open
appears on the next reload - and stops when the viewer quits. `w` opens the
browser at the selected row: a host at its page, a service at that service
across hosts, a port with exactly one capture at that capture. When `i` finds
several captures for a row, its first choice opens them side by side in the
gallery instead of one at a time in an image viewer.

| Page | What it shows |
| --- | --- |
| `/` | the Hosts tab; an older gallery link with its filter, sort or grouping still opens the gallery |
| `/gallery` | every screenshot, with URL, status, title and the database it came from; failures say why. Sortable by address, host name, port, HTTP status, URL, title, time taken or database, either way; groupable by host, service, page title or look (screenshots that look alike, from gowitness's perceptual grouping) - one click or `b` switches; a card whose service was captured more than once links to all of them together |
| `/hosts`, `/hosts/<address>` | hosts; one host's ports with each port's screenshots beside it |
| `/services`, `/services/<proto>/<port>` | services by port number; one service with every host's screenshot |
| `/captures/<id>` | the screenshot full size, headers, cookies, console log, technologies, TLS names |

Every filter box takes the viewer's own filter syntax (`'8443`, `open:443`,
`10.0.0.0/24`, `AND`/`OR`/`NOT`) and filters on the server as you type. Everything
a page shows is also JSON under `/api/v1/` (`hosts`, `services`, `captures`), with
`q`, `offset` and `limit`; `/api/openapi.json` describes it. Nothing is loaded
from the internet, so it works on an isolated network, and browsing writes nothing.
FastAPI, uvicorn and Jinja2 ship with seek; there is nothing extra to install.

**Everything the terminal viewer does, in the browser.** Every overview is a
tab at `/v/<tab>` - hosts, services, statistics, the three groupings, names and
scans - with the same columns, order, filter syntax and drill-down, and the
selected row's record beside the list, rendered from the very same record the
terminal shows. Links in a record open nmap's own text for that host or port;
`←`/`→` step to the other scans of it. Marks, export (every recipe, field and
format, downloaded or copied), new scans (preset, scope, editable command, the
same review and elevation rules; a scan that sudo would only run after a
password has to be started in the terminal) and gowitness captures all work from the
browser, and the Scans tab streams a running scan's log as nmap writes it.

Everything is linked: a host leads to its ports and their state, a port to its
full record - scripts, vulnerabilities, names, each scan's own text - and a
screenshot is shown as a thumbnail wherever it is named, in a list row or beside
the line of a record, opening its capture page, which leads back to the host and
port it shows.

**Searching.** The box in the header (`Ctrl+K`) searches everything at once -
hosts, services, names and screenshots - and lists the best matches grouped as
you type; `↓`/`Enter` opens one. Every list has its own filter with the same
syntax, and under each the query is said back in words, so you can see how it
was read. The `?` beside any search box opens the syntax with examples to click:

| Type | Finds |
| --- | --- |
| `nginx`, `synology login` | anything mentioning the words - including screenshot titles, URLs, technologies and status |
| `10.10.10.1` / `=10.10.10.1` / `10.10.10.0/24` | addresses beginning with it / that host alone / a range |
| `:443`, `443/tcp`, `53/udp` | a port with that number, in any state; `open:443`, `closed:22` ask for the state |
| `10.10.10.10:8080` | that host with that port |
| `service:http AND NOT product:nginx` | structured terms, `AND`/`OR`/`NOT`, `( )` |
| `'exact`, `^start`, `end$`, `!not` | text as written, anchored, or excluded |

Rows containing your words come first and alone; rows that only contain the
letters, scattered, are counted as "looser" - add `~` to list them too. The
terminal filter follows exactly the same rules.

The terminal and the browser share one session: a scan started in either shows
in both, a mark made in either is a mark in both, and quitting the terminal asks
about a scan the browser started. Each keeps its own tab, filter, sort and
cursor - the browser keeps them in the URL, so its back button returns to the
level you left with its filter and row, and two windows are independent.

The keys are the terminal's: `j`/`k` and the arrows move the list, `h`/`l` move
through the record, `Enter` opens, `Esc` backs out, `/` filters, `1`-`9` sort,
`v`/`V` switch tabs, `m`/`M` mark, `x` exports, `n` scans, `c` cancels, `p`
freezes the log, `d` widens the record, `?` lists them all.

`seek nmap serve PATHS…` (or `seek nmap --serve`) runs the same session and
web interface without the terminal viewer - on a box with no terminal to spare,
or for a browser on a second screen. `--open` opens the browser once it
listens; Ctrl+C cancels any scan or capture still running, says which, and
stops. A directory that happens to be called `serve` is named `./serve`.

**Stopping it.** While the web interface runs in the viewer, `w` asks whether to
open it at the selected row, copy its address, or stop it. The command palette
also has "Stop the web interface". Stopping closes the port and leaves the
viewer and any running scan alone; `w` starts it again. The browser has a Stop
button (`Q`), confirmed first. In the viewer it stops only the web interface.
For `seek nmap serve` it ends the server exactly as Ctrl+C does, and the
confirmation says so. Pages still open say the interface was stopped and stop
reconnecting.

State-changing requests are accepted only from the interface's own pages, so a
page on another site cannot drive it through your browser. There are no
accounts: it listens on loopback only.

**Export** produces the lists you feed to the next command, from whatever the
filter has narrowed to: host addresses, open ports comma-separated (the form
`-p` takes), `host:port` pairs, and HTTP/HTTPS URLs with non-standard ports.

### `-Pn` scans are not taken at their word

With `-Pn` nmap marks *every* target `up`, with the status reason `user-set` —
an assumption, not an observation. On a real /24 scan that means 255 hosts
reported up when only 9 responded to anything.

`seek` uses one rule everywhere — the host list, `u`, the statistics and the
"Up hosts" export: a host is **up** when it has an open port, however it was
scanned, or when a scan *with* host discovery recorded it up. A `-Pn` assertion
counts for nothing on its own; closed or filtered ports, an OS guess or script
output do not make a host up. The State column says which part applies: `up`
(host discovery), `up*` (only an open port says so), `unconfirmed` (asserted by
`-Pn`, no open port) or `down`. It says so rather than quietly substituting a
different number:

```
⚠  scan asserted 255 hosts up (-Pn) but only 9 are up — an open port or host discovery
```

When scans disagree, a host that any discovery scan recorded up is up. The raw
state and reason stay visible in the host detail.

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
headed by a line naming the root and the walk semantics in effect. The tree is
a list like any other: `↑`/`↓` move through it, `Tab` marks an entry, and the
open, copy and export keys act on the entry under the cursor (or on the marked
ones) without a query having been typed. `Enter` views a file and steps into a
directory; `Esc` steps back out.

Opening a file does not end the session. An editor takes over the terminal and
`seek` is back, where you left it, when the editor exits - the same query, the
same row, the same detail view; file contents are re-read, since the editor may
have changed them. The OS default application and `code` open in their own
windows while `seek` stays on screen.

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
| `Enter` | open the full-screen detail view (in the tree: step into a directory) |
| `Esc` | close overlay/detail → clear a non-empty query → pop breadcrumb → quit |
| `Tab` | mark / unmark the row |
| `Shift+Tab` | clear all marks |
| `Alt+↑` `Alt+↓` | recall previous / next query |
| `Ctrl+F` `Ctrl+D` `Ctrl+C` | toggle filename / directory / content mode |
| `Ctrl+N` | toggle re-indenting of minified files |
| `Ctrl+R` | re-root the search at the highlighted directory |
| `Alt+←` | pop one breadcrumb level |
| `Ctrl+G` | refresh (re-walk from disk) |
| `Ctrl+K` | action menu |
| `Ctrl+O` | open in the OS default application; `seek` stays open |
| `Ctrl+E` | open in the configured editor; `seek` resumes when it exits |
| `Ctrl+B` | open in `code`; `seek` stays open |
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
