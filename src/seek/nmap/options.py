"""Every option nmap documents, as data: the one source the builder, the
history stripper and the privilege check read.

**Where it comes from.** nmap's reference guide (nmap.org/book), version 7.99:
the option summary (`man-briefoptions`, the text of `nmap --help`) and the man
page sections it summarises. Each entry names its page, so the catalogue can be
held against a newer nmap. Options found only in nmap's source are not here:
the builder is a guide, and the command editor still takes anything.

**What it is not.** No logic beyond reading a value: whether a combination
makes sense lives in `RULES`, how a command is assembled lives in `builder`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# nmap's own eleven groups, in the summary's order.
GROUPS = (
    "Target specification", "Host discovery", "Scan techniques",
    "Port specification and scan order", "Service and version detection",
    "Script scan", "OS detection", "Timing and performance",
    "Firewall/IDS evasion and spoofing", "Output", "Miscellaneous",
)
(TARGET, DISCOVERY, TECHNIQUE, PORTS, VERSION, SCRIPT, OSDET, TIMING, EVASION,
 OUTPUT, MISC) = GROUPS

_BOOK = "https://nmap.org/book/"
PAGES = {
    "S": "man-briefoptions", "TS": "man-target-specification", "HD": "man-host-discovery",
    "PT": "man-port-scanning-techniques", "PS": "man-port-specification",
    "VD": "man-version-detection", "OS": "man-os-detection", "NSE": "man-nse",
    "P": "man-performance", "FW": "man-bypass-firewalls-ids", "O": "man-output",
    "M": "man-misc-options",
    # The book chapters the builder's explanations quote.
    "T": "performance-timing-templates", "ALG": "port-scanning-algorithms",
    "UDP": "scan-methods-udp-scan", "PSel": "performance-port-selection",
}


def page_url(key: str) -> str:
    return f"{_BOOK}{PAGES[key]}.html"


@dataclass(frozen=True, slots=True)
class Value:
    """What an option takes. `attach`: `space` (`--max-retries 2`), `attached`
    (`-T4`, `-PS22,80`) or `equals` (`--script-args-file=f`). `optional`: the
    option is complete without one (`-PS` alone probes port 80)."""

    form: str
    hint: str
    attach: str = "space"
    optional: bool = False
    lo: float | None = None
    hi: float | None = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Option:
    names: tuple[str, ...]
    group: str
    about: str
    source: str
    value: Value | None = None
    repeat: bool = False          # -v, -d, -f: given more than once means more
    default: str = ""
    root: bool | None = None      # True: raw packets; False: works unprivileged; None: not stated
    owner: str = ""               # why seek sets this itself and the user cannot

    @property
    def name(self) -> str:
        return self.names[0]

    @property
    def flag(self) -> bool:
        return self.value is None


# --- value forms ----------------------------------------------------------------------

def _num(hint: str, lo: float, hi: float | None = None, **kw) -> Value:
    return Value("number", hint, lo=lo, hi=hi, **kw)


_TIME = Value("time", "a time: 500ms, 30s, 15m, 2h (no unit: seconds)")
_PORTS = Value("ports", "ports: 22,80,8000-8100, -, U:53,T:443, http*")
_PORTLIST = Value("portlist", "ports: 22,80,443 (no T:/U: prefixes)", attach="attached",
                  optional=True)
_HOSTS = Value("hosts", "hosts: 10.0.0.5,10.0.0.0/24,db.example")
_FILE = Value("text", "a file name")


def _o(names, group, about, source, value=None, **kw) -> Option:
    return Option(tuple(names.split()), group, about, source, value, **kw)


SEEK_WRITES = ("seek writes the normal, XML and grepable output beside the scans "
               "itself - that is what makes a scan run here read like one run outside")
SEEK_TARGETS = "targets come from the scope step"
NOT_A_SCAN = "does not scan - run it outside the builder"

OPTIONS: tuple[Option, ...] = (
    # --- target specification [TS] ---
    _o("-iL", TARGET, "Read targets from a file ('-' for standard input)", "TS", _FILE,
       owner=SEEK_TARGETS),
    _o("-iR", TARGET, "Choose random targets (0 for a never-ending scan)", "TS",
       _num("a number of hosts", 0), owner=SEEK_TARGETS),
    _o("--exclude", TARGET, "Exclude hosts or networks, even inside a scanned range", "TS",
       _HOSTS),
    _o("--excludefile", TARGET, "Exclude the hosts listed in a file", "TS", _FILE),
    _o("--resolve-all", TARGET, "Scan every address a host name resolves to", "TS",
       default="only the first address"),
    _o("--unique", TARGET, "Scan each address once, however often it appears", "TS"),
    # --- host discovery [HD][TS] ---
    _o("-sL", DISCOVERY, "List scan: list the targets, send nothing to them", "HD", root=False),
    _o("-sn", DISCOVERY, "Ping scan: find live hosts, no port scan", "HD"),
    _o("-Pn -P0 -PN", DISCOVERY, "Treat all hosts as online: skip host discovery", "HD"),
    _o("-PS", DISCOVERY, "TCP SYN discovery probes to the given ports", "HD", _PORTLIST,
       default="port 80"),
    _o("-PA", DISCOVERY, "TCP ACK discovery probes to the given ports", "HD", _PORTLIST,
       default="port 80"),
    _o("-PU", DISCOVERY, "UDP discovery probes to the given ports", "HD", _PORTLIST,
       default="port 40125", root=True),
    _o("-PY", DISCOVERY, "SCTP INIT discovery probes to the given ports", "HD", _PORTLIST,
       default="port 80", root=True),
    _o("-PE", DISCOVERY, "ICMP echo request discovery", "HD", root=True),
    _o("-PP", DISCOVERY, "ICMP timestamp request discovery", "HD", root=True),
    _o("-PM", DISCOVERY, "ICMP address mask request discovery", "HD", root=True),
    _o("-PO", DISCOVERY, "IP protocol ping", "HD",
       Value("protocols", "protocol numbers: 1,2,4", attach="attached", optional=True),
       default="ICMP, IGMP, IP-in-IP", root=True),
    _o("-PR", DISCOVERY, "ARP ping on the local network", "HD", root=True),
    _o("--disable-arp-ping", DISCOVERY, "No ARP or IPv6 neighbour discovery ping", "HD"),
    _o("--discovery-ignore-rst", DISCOVERY, "Ignore RST replies during host discovery", "HD"),
    _o("--traceroute", DISCOVERY, "Trace the hop path to each host", "HD", root=True),
    _o("-n", DISCOVERY, "Never do reverse DNS resolution", "TS"),
    _o("-R", DISCOVERY, "Always do reverse DNS resolution", "TS",
       default="only responsive hosts"),
    _o("--dns-servers", DISCOVERY, "Use these DNS servers", "TS",
       Value("list", "servers: 192.0.2.53,192.0.2.54")),
    _o("--system-dns", DISCOVERY, "Use the operating system's resolver (slower)", "TS"),
    # --- scan techniques [PT] ---
    _o("-sS", TECHNIQUE, "TCP SYN scan", "PT", root=True,
       default="the default when privileged"),
    _o("-sT", TECHNIQUE, "TCP connect scan", "PT", root=False,
       default="the default without privileges"),
    _o("-sA", TECHNIQUE, "TCP ACK scan: map firewall rules", "PT", root=True),
    _o("-sW", TECHNIQUE, "TCP Window scan", "PT", root=True),
    _o("-sM", TECHNIQUE, "TCP Maimon scan", "PT", root=True),
    _o("-sU", TECHNIQUE, "UDP scan", "PT", root=True),
    _o("-sN", TECHNIQUE, "TCP NULL scan", "PT", root=True),
    _o("-sF", TECHNIQUE, "TCP FIN scan", "PT", root=True),
    _o("-sX", TECHNIQUE, "TCP Xmas scan", "PT", root=True),
    _o("--scanflags", TECHNIQUE, "Custom TCP flags", "PT",
       Value("text", "flags: URGACKPSHRSTSYNFIN, or a number such as 9")),
    _o("-sI", TECHNIQUE, "Idle scan through a zombie host", "PT",
       Value("text", "zombie host[:probe port]"), root=True),
    _o("-sY", TECHNIQUE, "SCTP INIT scan", "PT", root=True),
    _o("-sZ", TECHNIQUE, "SCTP COOKIE ECHO scan", "PT", root=True),
    _o("-sO", TECHNIQUE, "IP protocol scan", "PT", root=True),
    _o("-b", TECHNIQUE, "FTP bounce scan (deprecated)", "PT",
       Value("text", "[user:pass@]server[:port]"), root=False),
    # --- port specification [PS] ---
    _o("-p", PORTS, "Scan only these ports", "PS", _PORTS, default="the 1000 most common"),
    _o("--exclude-ports", PORTS, "Never scan these ports", "PS", _PORTS),
    _o("-F", PORTS, "Fast: the 100 most common ports instead of 1000", "PS"),
    _o("-r", PORTS, "Scan ports in order instead of randomised", "PS"),
    _o("--top-ports", PORTS, "Scan the N most common ports", "PS", _num("a number, 1 or more", 1)),
    _o("--port-ratio", PORTS, "Scan ports more common than this ratio", "PS",
       Value("real", "a ratio from 0.0 to 1.0", lo=0, hi=1)),
    # --- version detection [VD] ---
    _o("-sV -sR", VERSION, "Probe open ports for the service and its version", "VD"),
    _o("--allports", VERSION, "Version-scan every port, 9100 included", "VD",
       default="TCP 9100 is skipped"),
    _o("--version-intensity", VERSION, "How many probes to try, 0 (light) to 9 (all)", "VD",
       _num("0 to 9", 0, 9), default="7"),
    _o("--version-light", VERSION, "Intensity 2: the most likely probes", "VD"),
    _o("--version-all", VERSION, "Intensity 9: every probe", "VD"),
    _o("--version-trace", VERSION, "Show version scan activity (debugging)", "VD"),
    # --- script scan [NSE] ---
    _o("-sC", SCRIPT, "The default scripts (--script=default)", "NSE"),
    _o("--script", SCRIPT, "Run scripts: names, categories, expressions", "NSE",
       Value("script", "scripts: vuln, http-*, \"default and not intrusive\"")),
    _o("--script-args", SCRIPT, "Arguments for the scripts", "NSE",
       Value("script-args", "name=value,name2={a,b}")),
    _o("--script-args-file", SCRIPT, "Script arguments from a file", "NSE", _FILE),
    _o("--script-trace", SCRIPT, "Show everything scripts send and receive", "NSE"),
    _o("--script-help", SCRIPT, "Describe scripts instead of scanning", "NSE",
       Value("script", "scripts"), owner=NOT_A_SCAN),
    _o("--script-updatedb", SCRIPT, "Update the script database", "NSE", owner=NOT_A_SCAN),
    # --- OS detection [OS] ---
    _o("-O", OSDET, "OS detection", "OS", root=True),
    _o("--osscan-limit", OSDET, "OS detection only on hosts with an open and a closed port",
       "OS"),
    _o("--osscan-guess --fuzzy", OSDET, "Guess the OS more aggressively", "OS"),
    _o("--max-os-tries", OSDET, "OS detection attempts per host", "OS",
       _num("a number, 1 or more", 1), default="5, or 2 when conditions are poor"),
    # --- timing and performance [P] ---
    _o("-T", TIMING, "Timing template, 0 (paranoid) to 5 (insane)", "P",
       Value("choice", "0-5 or paranoid, sneaky, polite, normal, aggressive, insane",
             attach="attached",
             choices=("0", "1", "2", "3", "4", "5", "paranoid", "sneaky", "polite",
                      "normal", "aggressive", "insane")), default="3 (normal)"),
    _o("--min-hostgroup", TIMING, "Scan at least this many hosts in parallel", "P",
       _num("a number of hosts", 1), default="dynamic"),
    _o("--max-hostgroup", TIMING, "Scan at most this many hosts in parallel", "P",
       _num("a number of hosts", 1), default="dynamic"),
    _o("--min-parallelism", TIMING, "At least this many probes outstanding", "P",
       _num("a number of probes", 1), default="dynamic"),
    _o("--max-parallelism", TIMING, "At most this many probes outstanding", "P",
       _num("a number of probes", 1), default="dynamic"),
    _o("--min-rtt-timeout", TIMING, "Shortest probe timeout (rarely needed)", "P", _TIME,
       default="100ms"),
    _o("--max-rtt-timeout", TIMING, "Longest probe timeout", "P", _TIME, default="10s"),
    _o("--initial-rtt-timeout", TIMING, "Probe timeout to start with", "P", _TIME,
       default="1s"),
    _o("--max-retries", TIMING, "Retransmissions per port at most", "P",
       _num("a number, 0 or more", 0), default="10"),
    _o("--host-timeout", TIMING, "Give up on a host after this long (no results for it)",
       "P", _TIME, default="none"),
    _o("--script-timeout", TIMING, "Stop a script after this long", "P", _TIME,
       default="none"),
    _o("--scan-delay", TIMING, "Wait at least this long between probes to a host", "P",
       _TIME, default="0"),
    _o("--max-scan-delay", TIMING, "Never wait longer than this between probes", "P", _TIME,
       default="1s"),
    _o("--min-rate", TIMING, "Send at least this many packets per second", "P",
       Value("real", "packets per second", lo=0)),
    _o("--max-rate", TIMING, "Send at most this many packets per second", "P",
       Value("real", "packets per second", lo=0)),
    _o("--defeat-rst-ratelimit", TIMING, "Ignore RST rate limits (closed may read filtered)",
       "P"),
    _o("--defeat-icmp-ratelimit", TIMING,
       "Ignore ICMP rate limits on UDP (open|filtered may read closed|filtered)", "P"),
    _o("--nsock-engine", TIMING, "Force an I/O engine", "P",
       Value("choice", "iocp, epoll, kqueue, poll or select",
             choices=("iocp", "epoll", "kqueue", "poll", "select")),
       default="the best available"),
    # --- firewall/IDS evasion and spoofing [FW] ---
    _o("-f", EVASION, "Fragment packets (twice: 16-byte fragments)", "FW", repeat=True,
       root=True),
    _o("--mtu", EVASION, "Fragment with this MTU (a multiple of 8)", "FW",
       _num("a multiple of 8", 8), root=True),
    _o("-D", EVASION, "Hide the scan among decoys", "FW",
       Value("text", "decoys: 192.0.2.7,ME,RND:3"), root=True),
    _o("-S", EVASION, "Spoof the source address", "FW", Value("text", "an address"),
       root=True),
    _o("-e", EVASION, "Use this network interface", "FW", Value("text", "an interface: eth0")),
    _o("-g --source-port", EVASION, "Use this source port", "FW",
       _num("a port number", 0, 65535)),
    _o("--proxies", EVASION, "Relay TCP connections through HTTP/SOCKS4 proxies", "FW",
       Value("list", "proxies: http://192.0.2.8:8080,socks4://192.0.2.9:1080")),
    _o("--data", EVASION, "Append these bytes to sent packets", "FW",
       Value("hex", "hex bytes: 0xdeadbeef")),
    _o("--data-string", EVASION, "Append this text to sent packets", "FW",
       Value("text", "text")),
    _o("--data-length", EVASION, "Append this many random bytes to sent packets", "FW",
       _num("a number of bytes", 0)),
    _o("--ip-options", EVASION, "Send packets with these IP options", "FW",
       Value("text", "R, T, U, L <hops>, S <hops> or hex"), root=True),
    _o("--ttl", EVASION, "Set the IP time-to-live", "FW", _num("0 to 255", 0, 255),
       root=True),
    _o("--randomize-hosts", EVASION, "Shuffle the targets before scanning", "FW"),
    _o("--spoof-mac", EVASION, "Spoof the MAC address", "FW",
       Value("text", "0 (random), a MAC, a prefix or a vendor"), root=True),
    _o("--badsum", EVASION, "Send packets with bad checksums", "FW", root=True),
    _o("--adler32", EVASION, "Use Adler-32 for SCTP checksums (deprecated)", "FW"),
    # --- output [O] ---
    _o("-oN", OUTPUT, "Normal output to a file", "O", _FILE, owner=SEEK_WRITES),
    _o("-oX", OUTPUT, "XML output to a file", "O", _FILE, owner=SEEK_WRITES),
    _o("-oS", OUTPUT, "Script kiddie output to a file", "O", _FILE, owner=SEEK_WRITES),
    _o("-oG", OUTPUT, "Grepable output to a file", "O", _FILE, owner=SEEK_WRITES),
    _o("-oA", OUTPUT, "All three formats under one base name", "O", _FILE,
       owner=SEEK_WRITES),
    _o("-v", OUTPUT, "More verbose (repeat for more)", "O", repeat=True),
    _o("-d", OUTPUT, "Debugging output (repeat for more)", "O", repeat=True),
    _o("--reason", OUTPUT, "Say why each port is in its state", "O"),
    _o("--open", OUTPUT, "Show only open (or possibly open) ports", "O"),
    _o("--packet-trace", OUTPUT, "Show every packet sent and received", "O"),
    _o("--iflist", OUTPUT, "List interfaces and routes", "O", owner=NOT_A_SCAN),
    _o("--append-output", OUTPUT, "Append to output files", "O", owner=SEEK_WRITES),
    _o("--resume", OUTPUT, "Resume an aborted scan", "O", _FILE,
       owner="resumes a scan from its own file and takes no other option"),
    _o("--noninteractive", OUTPUT, "No keyboard interaction while scanning", "O"),
    _o("--stylesheet", OUTPUT, "XSL stylesheet for the XML output", "O",
       Value("text", "a path or URL")),
    _o("--webxml", OUTPUT, "Use the stylesheet from nmap.org", "O"),
    _o("--no-stylesheet", OUTPUT, "No stylesheet in the XML output", "O"),
    _o("--stats-every", OUTPUT, "Print timing statistics this often", "O", _TIME),
    # --- miscellaneous [M] ---
    _o("-6", MISC, "IPv6 scanning", "M"),
    _o("-A", MISC, "OS detection, versions, default scripts and traceroute", "M", root=True),
    _o("--datadir", MISC, "Read nmap's data files from here", "M",
       Value("text", "a directory")),
    _o("--servicedb", MISC, "Use this services file", "M", _FILE),
    _o("--versiondb", MISC, "Use this service probes file", "M", _FILE),
    _o("--send-eth", MISC, "Send raw ethernet frames", "M"),
    _o("--send-ip", MISC, "Send raw IP packets", "M"),
    _o("--privileged", MISC, "Assume full privileges", "M", root=True),
    _o("--unprivileged", MISC, "Assume no raw-socket privileges", "M"),
    _o("--release-memory", MISC, "Release memory before exiting (debugging)", "M"),
    _o("-V --version", MISC, "Print the version and exit", "M", owner=NOT_A_SCAN),
    _o("-h --help", MISC, "Print the help and exit", "M", owner=NOT_A_SCAN),
)

BY_NAME: dict[str, Option] = {n: o for o in OPTIONS for n in o.names}


def get(name: str) -> Option:
    return BY_NAME[name]


# --- reading a value --------------------------------------------------------------------

# The command is run without a shell, and `presets.parse_command` refuses these.
_SHELL = ("|", "&", ";", "<", ">", "`", "$")
_TIME_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h)?$")
_PORT_ITEM = re.compile(r"^(?:\d*-\d*|\d+|\[\d*-\d*\]|[A-Za-z][\w*?.-]*)$")
_HEX_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9a-fA-F]+|(?:\\x[0-9a-fA-F]{2})+)$")


def _port_numbers_ok(item: str, hi: int) -> bool:
    return all(not part or int(part) <= hi for part in item.strip("[]").split("-")
               if part.isdigit() or not part)


def check(option: Option, text: str) -> str | None:
    """`None` when `text` is a valid value for `option`, else what is expected."""
    value = option.value
    if value is None:
        return None
    text = text.strip()
    if not text:
        return None if value.optional else f"expected {value.hint}"
    for char in _SHELL:
        if char in text:
            return (f"cannot contain {char!r}: the command runs without a shell, "
                    "and seek refuses shell characters")
    expected = f"expected {value.hint}"
    form = value.form
    if form == "number":
        if not re.fullmatch(r"\d+", text):
            return expected
        number = int(text)
    elif form == "real":
        try:
            number = float(text)
        except ValueError:
            return expected
    elif form == "time":
        return None if _TIME_RE.match(text) else expected
    elif form in ("ports", "portlist", "protocols"):
        body = text
        items = re.split(r",", body)
        hi = 255 if form == "protocols" else 65535
        for item in items:
            if form == "ports":
                item = re.sub(r"^[TUSP]:", "", item)
            elif not re.fullmatch(r"\d*-\d*|\d+", item):
                return expected
            if not item or not _PORT_ITEM.match(item) or not _port_numbers_ok(item, hi):
                return expected
        return None
    elif form == "list":
        return None if all(i.strip() for i in text.split(",")) and " " not in text \
            else expected
    elif form == "hosts":
        from seek.nmap.presets import parse_target
        for item in text.split(","):
            target = parse_target(item)
            if target is None or target.error:
                return expected
        return None
    elif form == "choice":
        return None if text in value.choices else expected
    elif form == "hex":
        return None if _HEX_RE.match(text) else expected
    elif form == "script":
        return None if text.count("(") == text.count(")") else "unbalanced parentheses"
    else:                                   # text, script-args
        return None
    if value.lo is not None and number < value.lo:
        return expected
    if value.hi is not None and number > value.hi:
        return expected
    if option.name == "--mtu" and int(number) % 8:
        return expected
    return None


def tokens(option: Option, value: str | None = None, count: int = 1) -> list[str]:
    """The argv tokens for one option set to `value`."""
    if option.value is None:
        return [option.name] * (count if option.repeat else 1)
    if not value:
        return [option.name]                # an optional value left out
    attach = option.value.attach
    if attach == "attached":
        return [f"{option.name}{value}"]
    if attach == "equals":
        return [f"{option.name}={value}"]
    return [option.name, value]


_SCAN_LETTERS = re.compile(r"-s([SATWMUNFXYZOVCLR]{2,})")


def expand(token: str) -> list[str]:
    """nmap reads `-sUV` as `-sU -sV`: one token, several scan letters."""
    match = _SCAN_LETTERS.fullmatch(token)
    if match is None:
        return [token]
    return [f"-s{letter}" for letter in match.group(1)]


def lookup(token: str) -> tuple[Option, str | None, bool] | None:
    """What a token of a command is: the option, its value when it is in the
    token, and whether the *next* token is its value. `None` when the token is
    not an option seek knows - which, in a list of arguments, may be a target.

    nmap reads options with `getopt_long_only`, so `--opt=value` and a short
    option with its value attached (`-p22`, `-T4`, `-PS22,80`) both work.
    """
    if not token.startswith("-") or token == "-":
        return None
    exact = BY_NAME.get(token)
    if exact is not None:
        takes = exact.value is not None and exact.value.attach == "space" \
            and not exact.value.optional
        return exact, None, takes
    name, eq, rest = token.partition("=")
    if eq and name in BY_NAME and BY_NAME[name].value is not None:
        return BY_NAME[name], rest, False
    # Attached values: the longest known name that prefixes the token and takes
    # a value - `-PS22` is -PS, not -P; `-p22` is -p.
    for length in range(min(len(token) - 1, 24), 1, -1):
        option = BY_NAME.get(token[:length])
        if option is not None and option.value is not None and not token.startswith("--"):
            return option, token[length:], False
    if re.fullmatch(r"-([vdf])\1+|-[vd]\d", token):   # -vv, -ddd, -ff, -v3
        return BY_NAME[token[:2]], None, False
    return None


def split(args: list[str]) -> tuple[list[list[str]], list[str]]:
    """A command's arguments as nmap reads them: each option with its value,
    and the targets - every word that is neither.

    An option the catalogue does not know (or `-sUV`) is taken to have no
    value, so the word after it counts as a target. The scan path never
    reorders the command on the strength of this - it only counts and checks.
    """
    groups: list[list[str]] = []
    targets: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        index += 1
        found = lookup(token)
        if found is None:
            if token.startswith("-") and token != "-":
                groups.append([token])
            else:
                targets.append(token)
            continue
        group = [token]
        if found[2] and index < len(args):
            group.append(args[index])
            index += 1
        groups.append(group)
    return groups, targets


# --- combinations ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rule:
    """How two sets of options combine. `exclusive`: at most one side (or, with
    `right` empty, at most one of `left`) - setting one clears the other.
    `ignored`: both stay, one has no effect. `advice`: a warning only."""

    kind: str
    left: frozenset[str]
    right: frozenset[str]
    message: str
    source: str              # a page key, or "nmap" for a rule nmap enforces at start

    def involves(self, name: str) -> bool:
        return name in self.left or name in self.right


def _r(kind, left, right, message, source) -> Rule:
    return Rule(kind, frozenset(left.split()), frozenset(right.split()), message, source)


_TCP = "-sS -sT -sA -sW -sM -sN -sF -sX -sI -b"
_ANY_SCAN = _TCP + " -sU -sY -sZ"
RULES: tuple[Rule, ...] = (
    _r("exclusive", _TCP, "", "one TCP scan type at a time", "PT"),
    _r("exclusive", "-sY -sZ", "", "one SCTP scan type at a time", "PT"),
    _r("exclusive", "-sO", _ANY_SCAN, "the IP protocol scan runs on its own", "PT"),
    _r("exclusive", "-sL", _ANY_SCAN + " -sO -sn -sV -O -A -Pn -sC --script",
       "a list scan sends nothing, so it cannot scan or detect", "HD"),
    _r("exclusive", "-sn", _ANY_SCAN + " -sO -p -F --top-ports --port-ratio -sV -O -A",
       "a ping scan does not scan ports", "HD"),
    _r("exclusive", "-f", "--mtu", "give either -f or --mtu, not both", "FW"),
    _r("exclusive", "-n", "-R", "never resolve and always resolve contradict", "TS"),
    _r("exclusive", "-F", "-p", "nmap refuses -F with -p; --top-ports works with -p",
       "nmap"),
    _r("exclusive", "--version-intensity --version-light --version-all", "",
       "one version intensity", "VD"),
    _r("exclusive", "--webxml --stylesheet --no-stylesheet", "", "one stylesheet choice",
       "O"),
    _r("ignored", "-sC", "--script", "-sC is ignored when --script is given", "NSE"),
    _r("ignored", "--dns-servers", "--system-dns",
       "--dns-servers is not honoured with --system-dns", "TS"),
    _r("ignored", "-D", "-sV -sT", "decoys do not apply to version detection or a connect "
       "scan", "FW"),
    _r("ignored", "-g", "-sT -sV -sC --script -O",
       "the source port does not apply to connect, version, script or OS scans", "FW"),
    _r("ignored", "--traceroute", "-sT -sI", "traceroute does not work with -sT or -sI",
       "HD"),
    _r("ignored", "-f --mtu", "-sT -b", "fragmentation needs a raw-packet scan", "FW"),
    _r("advice", "--min-rate", "", "nmap: \"Any use of --min-rate is at your own risk\" - "
       "faster than the network can carry loses accuracy", "P"),
    _r("advice", "--defeat-rst-ratelimit", "", "closed ports may be reported as filtered",
       "P"),
    _r("advice", "--defeat-icmp-ratelimit", "",
       "UDP ports may be reported closed|filtered instead of open|filtered", "P"),
    _r("advice", "-S", "", "spoofing usually needs -e and -Pn, and the replies go to the "
       "spoofed address", "FW"),
    _r("advice", "--osscan-limit", "", "only matters with -O or -A", "OS"),
)


def rules_for(name: str) -> list[Rule]:
    return [r for r in RULES if r.involves(name)]
