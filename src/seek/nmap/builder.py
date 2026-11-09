"""The guided command builder: steps, trade-offs, and the two commands.

Pure - no Textual, no FastAPI, no I/O. Both front ends hold a `State`, ask
`view(state, facts)` what to show, and turn a key into a new `State`; the web
sends the state back and forth as JSON, so the server keeps none.

**Precedence.** An option's value comes from the first of: the user's own
setting in fine-tune, the answers to the steps, the speed/reliability profile,
a measurement taken now, earlier scans, nmap's default. Every value keeps where
it came from and what it overrode, so the interface can say why it is there.

**Sources.** Every rule cites nmap's reference guide (see `options.PAGES`); the
figures in the explanations are the guide's own, and a test pins them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace

from seek.nmap import options, timing
from seek.nmap.options import BY_NAME, GROUPS, OPTIONS

FAST, RELIABLE = "fast", "reliable"
# Precedence, lowest first. A later layer replaces an earlier one's value.
SOURCES = ("default", "earlier scans", "measured now", "profile", "your answers", "you")


@dataclass(frozen=True, slots=True)
class Facts:
    """What the session knows about the targets."""

    targets: tuple[str, ...] = ()
    tcp_ports: str = ""                 # the known open ports, as `-p` takes them
    udp_ports: str = ""
    up: frozenset[str] = frozenset()    # targets earlier scans saw up
    privileged: bool = True             # root, capabilities or sudo can be used
    rtts: tuple[timing.Rtt, ...] = ()   # from earlier scans of the targets
    measured: tuple[timing.Rtt, ...] = ()


@dataclass(frozen=True, slots=True)
class State:
    answers: tuple[tuple[str, str], ...] = ()
    # The user's own settings, in the order made: (option, value). A value of
    # None turns an option off; "" turns a flag on.
    overrides: tuple[tuple[str, str | None], ...] = ()
    step: str = "goal"

    def answer(self, key: str) -> str | None:
        return dict(self.answers).get(key)

    def answered(self, key: str, choice: str) -> State:
        kept = tuple((k, v) for k, v in self.answers if k != key)
        return replace(self, answers=(*kept, (key, choice)))

    def set(self, name: str, value: str | None) -> State:
        kept = tuple((k, v) for k, v in self.overrides if k != name)
        return replace(self, overrides=(*kept, (name, value)))

    def reset(self, name: str) -> State:
        return replace(self, overrides=tuple((k, v) for k, v in self.overrides if k != name))

    def to_json(self) -> str:
        return json.dumps({"answers": dict(self.answers), "overrides": list(self.overrides),
                           "step": self.step})

    @classmethod
    def from_json(cls, text: str) -> State:
        raw = json.loads(text or "{}")
        overrides = tuple((str(k), None if v is None else str(v))
                          for k, v in raw.get("overrides", []) if str(k) in BY_NAME)
        return cls(tuple((str(k), str(v)) for k, v in raw.get("answers", {}).items()),
                   overrides, str(raw.get("step", "goal")))


@dataclass(frozen=True, slots=True)
class Choice:
    key: str
    label: str
    adds: str                 # the options it puts in the command, as text
    gain: str
    cost: str
    recommended: bool = False
    source: str = ""          # the nmap page key behind the claim


@dataclass(frozen=True, slots=True)
class Setting:
    value: str | None         # None for a flag that is on
    source: str               # one of SOURCES
    why: str = ""
    overrode: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Built:
    args: list[str]
    settings: dict[str, Setting]
    notes: list[str]          # conflicts applied, advice
    misses: list[str]         # what this command may not find


# --- the steps ------------------------------------------------------------------------

GOALS = {
    "live": ("Find live hosts", "-sn"),
    "ports": ("Find open ports", ""),
    "services": ("Identify services and versions", "-sV"),
    "os": ("Identify services and the operating system", "-sV -O"),
    "vulns": ("Check for known vulnerabilities", "-sV --script vuln"),
    "names": ("Find the names hosts answer to", "-sV --script " + "ssl-cert,http-title,"
              "http-headers,rdp-ntlm-info,smb-os-discovery,nbstat,ldap-rootdse,ssl-cert-intaddr"),
}


@dataclass(frozen=True, slots=True)
class Step:
    key: str
    title: str
    question: str


STEPS = (
    Step("goal", "Goal", "What do you want to find out?"),
    Step("protocol", "Protocol", "Which protocol?"),
    Step("ports", "Ports", "How many ports?"),
    Step("reach", "Reach", "How are the hosts reached?"),
    Step("dns", "Names", "Resolve host names?"),
    Step("network", "Network", "What is the network like?"),
    Step("tune", "Fine-tune", "Any option, by nmap's own groups"),
    Step("choose", "Choose", "Fast or reliable?"),
)
STEP_KEYS = tuple(s.key for s in STEPS)


def applies(step: str, state: State) -> bool:
    # Before a goal is chosen every step counts: the step line must not claim
    # six steps and then grow to eight.
    if step in ("protocol", "ports", "reach"):
        return state.answer("goal") != "live"
    return True


def _targets_up(facts: Facts) -> int:
    return len(set(facts.targets) & facts.up)


def choices(step: str, state: State, facts: Facts) -> list[Choice]:
    """The choices of a step, each with what it gains and what it costs."""
    goal, proto = state.answer("goal"), state.answer("protocol") or "tcp"
    if step == "goal":
        return [
            Choice("live", "Find live hosts", "-sn",
                   "fast: no port is scanned, only which hosts answer",
                   "a host that drops every discovery probe looks down", source="HD"),
            Choice("ports", "Find open ports", "-sS (or -sT)",
                   "the map everything else builds on",
                   "no service names beyond nmap's port table guess", source="PT",
                   recommended=not facts.tcp_ports and not facts.udp_ports),
            Choice("services", "Identify services and versions", "-sV",
                   "names the software and version on each open port",
                   "several probes per open port; far slower on UDP", source="VD",
                   recommended=bool(facts.tcp_ports or facts.udp_ports)),
            Choice("os", "Services and the operating system", "-sV -O",
                   "adds an OS guess with a confidence", "needs root, and an open and a "
                   "closed port per host to be reliable", source="OS"),
            Choice("vulns", "Check for known vulnerabilities", "-sV --script vuln",
                   "the NSE vuln scripts test what they can", "intrusive scripts; slow; "
                   "only what a script exists for", source="NSE"),
            Choice("names", "Find the names hosts answer to", "-sV --script ssl-cert,…",
                   "certificate names, redirects, NTLM and NetBIOS names",
                   "only from services that give names away", source="NSE"),
        ]
    if step == "protocol":
        tcp = "-sS" if facts.privileged else "-sT"
        return [
            Choice("tcp", "TCP", tcp, "fast and definite: open, closed or filtered",
                   "misses DNS, SNMP, NTP, IKE and every other UDP service", source="PT",
                   recommended=True),
            Choice("udp", "UDP", "-sU", "finds DNS, SNMP, NTP, TFTP, IKE",
                   "slow: Linux answers one closed port per second, so 1000 ports can "
                   "take 18 minutes a host", source="UDP"),
            Choice("both", "TCP and UDP", f"{tcp} -sU", "the whole picture in one scan",
                   "as slow as the UDP part", source="PT"),
        ]
    if step == "ports":
        udp = proto in ("udp", "both")
        known = facts.udp_ports if proto == "udp" else facts.tcp_ports
        found = []
        if known:
            found.append(Choice("known", "The ports already known open", f"-p {known}",
                                f"exactly the {len(known.split(','))} ports earlier scans "
                                "found open", "finds nothing new", source="PS",
                                recommended=goal in ("services", "os", "vulns", "names")))
        found += [
            Choice("top100", "Top 100", "-F", "fastest broad scan",
                   "finds about 78 % of open TCP and 39 % of open UDP ports",
                   source="PSel", recommended=udp and not known),
            Choice("top1000", "Top 1000 (nmap's default)", "",
                   "about 93 % of open TCP and 49 % of open UDP ports",
                   "ten times the work of top 100", source="PSel",
                   recommended=not udp and not (known and goal != "ports")),
            Choice("all", "All 65535", "-p-", "finds every open port",
                   "about 65 times the work of top 1000; on UDP, hours a host",
                   source="PS"),
        ]
        return found
    if step == "reach":
        up, total = _targets_up(facts), len(facts.targets)
        seen = f"{up} of {total} were seen up in earlier scans" if total else ""
        return [
            Choice("ping", "Ping first (nmap's default)", "",
                   "hosts that do not answer cost nothing",
                   "firewalls drop the pings, so live hosts can look down and are "
                   "not scanned", source="HD", recommended=not up),
            Choice("pn", "Treat all as up", "-Pn",
                   seen or "every target is scanned, whatever the firewall drops",
                   "every target is port-scanned, up or not", source="HD",
                   recommended=bool(up)),
        ]
    if step == "dns":
        return [
            Choice("no", "Do not resolve", "-n", "no DNS round trips; quieter",
                   "no reverse names in the results", source="TS",
                   recommended=goal != "names"),
            Choice("resolve", "Resolve when a host answers (nmap's default)", "",
                   "reverse names in the results", "one DNS query per live host",
                   source="TS", recommended=goal == "names"),
        ]
    if step == "network":
        have = [r for r in facts.rtts if r.host in set(facts.targets)] or list(facts.rtts)
        found = []
        if have:
            slowest = max(have, key=lambda r: r.ms)
            found.append(Choice("scans", "Use what earlier scans measured", "RTT timeouts",
                                f"{len(have)} host(s), slowest {slowest.ms:.1f} ms",
                                "measured at that time; a busy network may be slower now",
                                source="P", recommended=True))
        found += [
            Choice("measure", "Measure now", "RTT timeouts",
                   "the network as it is today",
                   "sends a few probes to up to 8 hosts, up to 8 seconds - you confirm first",
                   source="P", recommended=not have),
            Choice("lan", "Local network", "--max-rtt-timeout 100ms",
                   "no waiting a second on a host a millisecond away",
                   "too short across a WAN or VPN: probes time out and are resent",
                   source="P"),
            Choice("internet", "Internet or VPN", "",
                   "nmap adapts its timeouts as replies arrive",
                   "starts cautious: a 1 s first timeout", source="ALG"),
        ]
        return found
    if step == "choose":
        return [
            Choice(FAST, "Fast", "", "finishes sooner", "may miss what the notes say",
                   source="P"),
            Choice(RELIABLE, "Reliable", "", "nmap's own accuracy",
                   "takes longer on slow or rate-limited hosts", source="P",
                   recommended=True),
        ]
    return []


# --- resolving the options ------------------------------------------------------------


def _goal_layer(state: State, facts: Facts) -> dict[str, str | None]:
    goal = state.answer("goal") or "ports"
    proto = state.answer("protocol") or "tcp"
    layer = parse_args(GOALS.get(goal, ("", ""))[1].split())
    # Verbose: the progress lines ("About 40% done") that the run list, the
    # status and the 25/50/75 % notifications read are printed only then.
    # Without it a built scan said "running" and nothing else until it ended.
    layer["-v"] = None
    if goal == "live":
        return layer
    if not facts.privileged:
        layer.pop("-O", None)
    if proto in ("tcp", "both"):
        layer["-sS" if facts.privileged else "-sT"] = None
    if proto in ("udp", "both"):
        layer["-sU"] = None
    ports = state.answer("ports")
    if ports == "known":
        if proto == "both" and facts.tcp_ports and facts.udp_ports:
            layer["-p"] = f"T:{facts.tcp_ports},U:{facts.udp_ports}"
        else:
            layer["-p"] = (facts.udp_ports if proto == "udp" else facts.tcp_ports) or None
    elif ports == "top100":
        layer["-F"] = None
    elif ports == "all":
        layer["-p"] = "-"
    if state.answer("reach") == "pn":
        layer["-Pn"] = None
    if state.answer("dns") == "no":
        layer["-n"] = None
    if state.answer("network") == "lan" and not facts.measured:
        layer["--max-rtt-timeout"] = "100ms"
    return {k: v for k, v in layer.items() if k in BY_NAME}


def _observations(state: State, facts: Facts) -> tuple[list[timing.Rtt], str]:
    network = state.answer("network")
    if network == "measure" and facts.measured:
        return list(facts.measured), "measured now"
    if network == "scans" and facts.rtts:
        mine = [r for r in facts.rtts if r.host in set(facts.targets)]
        return (mine or list(facts.rtts)), "earlier scans"
    return [], ""


def _profile_layer(state: State, facts: Facts, profile: str,
                   base: dict[str, str | None]) -> tuple[dict[str, str | None], list[str]]:
    """The options a profile sets, and what the fast one may miss as a result."""
    layer: dict[str, str | None] = {}
    misses: list[str] = []
    goal = state.answer("goal")
    udp = "-sU" in base
    scanning = goal != "live"
    many = len(facts.targets) > 1
    measured = bool(_observations(state, facts)[0]) or state.answer("network") == "lan"
    if profile == FAST or measured:
        layer["-T"] = "4"
    if not scanning:
        return layer, misses
    if udp and many:
        layer["--min-hostgroup"] = "100"
    if profile == RELIABLE:
        return layer, misses
    layer["--max-retries"] = "1" if udp else "2"
    state_word = "open|filtered" if udp else "filtered"
    misses.append(f"a port that drops the first probes may read {state_word}: fewer retries "
                  "(nmap: \"You usually lose some information\")")
    if goal == "ports" and "-sS" in base:
        layer["--defeat-rst-ratelimit"] = None
        misses.append("closed TCP ports may read filtered (--defeat-rst-ratelimit)")
    if udp and "-sV" in base:
        layer["--version-intensity"] = "0"
        misses.append("UDP versions only from the most likely probe (--version-intensity 0)")
    layer["--host-timeout"] = "3h" if udp else "30m"
    misses.append(f"a host slower than {layer['--host-timeout']} is dropped with no result")
    few = "-F" in base or ("-p" in base and base["-p"] not in (None, "-"))
    if few and len(facts.targets) > 256 and not udp:
        layer["--min-hostgroup"] = "256"
    if "-O" in base and "-Pn" in base:
        layer["--osscan-limit"] = None
        misses.append("no OS guess for hosts without an open and a closed port")
    return layer, misses


def parse_args(argv: list[str]) -> dict[str, str | None]:
    """Arguments to settings, through the catalogue: `{option: value}`, with
    None for a flag. Unknown tokens are left out - the builder only produces
    what it knows."""
    found: dict[str, str | None] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        index += 1
        for part in options.expand(token):
            hit = options.lookup(part)
            if hit is None:
                continue
            option, value, takes_next = hit
            if takes_next and index < len(argv):
                value = argv[index]
                index += 1
            found[option.name] = value
    return found


def _rank(source: str) -> int:
    return SOURCES.index(source)


def _apply_rules(settings: dict[str, Setting], user_order: list[str]
                 ) -> tuple[dict[str, Setting], list[str]]:
    """Keep the command valid: an exclusive rule keeps the side set with the
    highest precedence - between two of the user's own, the later one."""
    def weight(name: str) -> tuple[int, int]:
        order = user_order.index(name) if name in user_order else -1
        return _rank(settings[name].source), order

    notes: list[str] = []
    for rule in options.RULES:
        present_left = [n for n in rule.left if n in settings]
        present_right = [n for n in rule.right if n in settings]
        if rule.kind == "exclusive":
            if rule.right:
                if not (present_left and present_right):
                    continue
                left_best = max(present_left, key=weight)
                right_best = max(present_right, key=weight)
                losers = present_right if weight(left_best) >= weight(right_best) \
                    else present_left
                winner = left_best if losers is present_right else right_best
            else:
                if len(present_left) < 2:
                    continue
                winner = max(present_left, key=weight)
                losers = [n for n in present_left if n != winner]
            for name in losers:
                settings.pop(name, None)
            notes.append(f"kept {winner}, removed {' '.join(sorted(losers))}: "
                         f"{rule.message}")
        elif present_left and (present_right or not rule.right):
            notes.append(f"{' '.join(sorted(present_left + present_right))}: {rule.message}")
    return settings, notes


def resolve(state: State, facts: Facts, profile: str) -> Built:
    settings: dict[str, Setting] = {}

    def lay(source: str, layer: dict[str, str | None], why: str = "") -> None:
        for name, value in layer.items():
            before = settings.get(name)
            overrode = () if before is None else (*before.overrode, before.source)
            settings[name] = Setting(value, source, why, overrode)

    observations, origin = _observations(state, facts)
    if observations:
        derived = timing.derive(observations, profile, len(facts.targets))
        lay(origin, dict(derived.values), derived.note)
    goal_layer = _goal_layer(state, facts)
    profile_layer, misses = _profile_layer(state, facts, profile, goal_layer)
    lay("profile", profile_layer, f"the {profile} profile")
    lay("your answers", goal_layer, "from your answers")
    user_order = []
    for name, value in state.overrides:
        user_order.append(name)
        if value is None:
            settings.pop(name, None)          # turned off by the user
        else:
            lay("you", {name: value or None}, "set by you")
    settings, notes = _apply_rules(settings, user_order)
    # A miss only stands while the option behind it is still in the command.
    misses = [m for m in misses if _miss_holds(m, settings)]
    return Built(render(settings), settings, notes, misses)


_MISS_OPTION = {"fewer retries": "--max-retries", "--defeat-rst-ratelimit":
                "--defeat-rst-ratelimit", "--version-intensity 0": "--version-intensity",
                "dropped with no result": "--host-timeout", "no OS guess": "--osscan-limit"}


def _miss_holds(miss: str, settings: dict[str, Setting]) -> bool:
    for phrase, name in _MISS_OPTION.items():
        if phrase in miss:
            return name in settings and settings[name].source == "profile"
    return True


_ORDER = {o.name: (GROUPS.index(o.group), i) for i, o in enumerate(OPTIONS)}


def render(settings: dict[str, Setting]) -> list[str]:
    """The arguments in nmap's group order, then the catalogue's - the same
    settings always give the same command, in either front end."""
    argv: list[str] = []
    for name in sorted(settings, key=lambda n: _ORDER.get(n, (99, 0))):
        option = BY_NAME[name]
        value = settings[name].value
        count = int(value) if option.repeat and value and value.isdigit() else 1
        argv += options.tokens(option, None if option.repeat else value, count)
    return argv


def both(state: State, facts: Facts) -> tuple[Built, Built]:
    """The fast and the reliable command for the same answers."""
    return resolve(state, facts, FAST), resolve(state, facts, RELIABLE)


# --- moving through the steps ----------------------------------------------------------


def visible_steps(state: State) -> list[Step]:
    return [s for s in STEPS if applies(s.key, state)]


def status(step: str, state: State) -> str:
    """done, current, ahead or skipped - shown in characters, never by colour."""
    if not applies(step, state):
        return "skipped"
    if step == state.step:
        return "current"
    if step == "tune":
        later = STEP_KEYS.index(state.step) > STEP_KEYS.index("tune")
        return "done" if later else "ahead"
    return "done" if state.answer(step) is not None else "ahead"


def advance(state: State, step: str, choice: str) -> State:
    """Answer `step` with `choice` and move to the next step that applies."""
    state = state.answered(step, choice)
    return replace(state, step=_next(step, state))


def _next(step: str, state: State) -> str:
    keys = [s.key for s in visible_steps(state)]
    index = keys.index(step) if step in keys else -1
    return keys[min(index + 1, len(keys) - 1)]


def back(state: State) -> State:
    keys = [s.key for s in visible_steps(state)]
    index = keys.index(state.step) if state.step in keys else 0
    return replace(state, step=keys[max(index - 1, 0)])


def jump(state: State, step: str) -> State:
    """Only to a step already done, or the current one - never ahead of the answers."""
    if step in STEP_KEYS and status(step, state) in ("done", "current"):
        return replace(state, step=step)
    return state


def recommended(step: str, state: State, facts: Facts) -> str | None:
    found = [c.key for c in choices(step, state, facts) if c.recommended]
    return found[0] if found else None


def preview(state: State, facts: Facts, step: str, choice: str) -> list[str]:
    """The command as it would be with `choice` taken - shown on highlight."""
    return resolve(state.answered(step, choice), facts, RELIABLE).args


@dataclass(frozen=True, slots=True)
class OptionRow:
    """One row of fine-tune."""

    option: options.Option
    setting: Setting | None
    error: str | None = None


@dataclass(slots=True)
class TuneView:
    groups: list[tuple[str, list[OptionRow]]] = field(default_factory=list)


def tune_view(state: State, facts: Facts, profile: str = RELIABLE, query: str = "",
              set_first: bool = False) -> TuneView:
    """Every option by nmap's groups, each with its current setting."""
    built = resolve(state, facts, profile)
    query = query.lower().strip()
    view = TuneView()
    for group in GROUPS:
        rows = [OptionRow(o, built.settings.get(o.name)) for o in OPTIONS if o.group == group
                and (not query or query in " ".join(o.names).lower() or query in o.about.lower())]
        if set_first:
            rows.sort(key=lambda r: r.setting is None)
        if rows:
            view.groups.append((group, rows))
    return view


def help_text(name: str) -> list[str]:
    """What the help pane says about one option."""
    option = BY_NAME[name]
    lines = [" ".join(option.names), option.about]
    if option.value is None:
        lines.append("takes no value" + (" (repeat for more)" if option.repeat else ""))
    else:
        lines.append(f"value: {option.value.hint}"
                     + (" (optional)" if option.value.optional else ""))
    if option.default:
        lines.append(f"default: {option.default}")
    lines.append({True: "needs root (raw packets)", False: "works without root",
                  None: "root: not stated"}[option.root])
    for rule in options.rules_for(name):
        lines.append(f"{rule.kind}: {rule.message}")
    if option.owner:
        lines.append(f"set by seek: {option.owner}")
    lines.append(options.page_url(option.source))
    return lines
