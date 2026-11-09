"""The software inventory: which products and versions run on which service.

Built from everything already read - nmap's identification and CPEs, its OS
detection, the NSE scripts that name software, and gowitness captures joined to
their service - and from nothing else: no connection is made to build it.

Three layers, each replaceable without touching the others:

- **recognisers** turn one source into `Observation`s. They read only text that
  states the software of *this* service - a header line, a greeting, a generator
  string - never a page body or an advisory, the same anchoring rule
  `names.py` follows for redirects;
- **reconciliation** groups observations of one product in one place into a
  `Component`: the version from the most trusted source, every observation
  kept, a conflict marked rather than resolved by throwing one away;
- **`build`** walks the model once and returns an `Inventory`, which every
  consumer (the tab, a record's Software block, the export, the API, the
  unversioned-ports scan) reads. Nothing downstream re-derives any of it.

Pure: no Textual, no session. The session caches the result per model and
capture generation, because captures change without the model changing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache

from seek.nmap import cpe as cpe_mod
from seek.nmap.models import Host, ScriptResult, Service
from seek.nmap.progress import HOSTS, Report, counted

# How far an observation is trusted for a version, best first.
PROBE, BANNER, HEADER, DETECTED = 0, 1, 2, 3
CONFIDENCE = {PROBE: "probed", BANNER: "banner", HEADER: "header", DETECTED: "detected"}

KIND_NAMES = {"a": "application", "o": "operating system", "h": "hardware"}

ServiceKey = tuple[str, str, int]          # (address, protocol, port)


@dataclass(frozen=True, slots=True)
class Observation:
    """One source saying one product runs here."""

    product: str                  # as the source spelled it
    version: str | None
    source: str                   # "nmap", "http-server-header", "gowitness", ...
    detail: str                   # what exactly was read, for the record
    rank: int
    cpes: tuple[str, ...] = ()    # CPE URIs the source gave, as written
    kind: str = ""                # "a"/"o"/"h" when the source says


@dataclass(slots=True)
class Component:
    """One product in one place, with everything said about it."""

    key: str
    product: str
    version: str | None
    kind: str
    cpes: list[cpe_mod.Cpe] = field(default_factory=list)
    cpe_origin: str | None = None           # "nmap", "alias" or None
    observations: list[Observation] = field(default_factory=list)
    conflicting: bool = False

    @property
    def rank(self) -> int:
        return min(o.rank for o in self.observations)

    @property
    def confidence(self) -> str:
        return CONFIDENCE[self.rank]

    @property
    def versioned(self) -> bool:
        return bool(self.version)

    @property
    def sources(self) -> list[str]:
        return list(dict.fromkeys(o.source for o in self.observations))

    @property
    def versions(self) -> list[tuple[str, str]]:
        """Every distinct version with the first source that gave it."""
        seen: dict[str, str] = {}
        for o in sorted(self.observations, key=lambda o: o.rank):
            if o.version:
                seen.setdefault(o.version, o.source)
        return list(seen.items())

    @property
    def cpe22(self) -> list[str]:
        return [c.uri for c in self.cpes]

    @property
    def cpe23(self) -> list[str]:
        """The 2.3 form, with the version filled in where the CPE had none."""
        return [(c.with_version(self.version) if self.version and not c.version
                 else c).fs for c in self.cpes]

    def label(self) -> str:
        return f"{self.product} {self.version}" if self.version else self.product


@dataclass(slots=True, repr=False)
class Inventory:
    by_service: dict[ServiceKey, list[Component]] = field(default_factory=dict)
    by_host: dict[str, list[Component]] = field(default_factory=dict)
    unplaced: int = 0             # captures whose URL belongs to no service
    sources: list[str] = field(default_factory=list)   # the scans it was built from

    def __repr__(self) -> str:
        return (f"Inventory({len(self.by_service)} service(s), "
                f"{len(self.by_host)} host(s))")

    def of_service(self, host: Host, svc: Service) -> list[Component]:
        return self.by_service.get((host.address, svc.protocol, svc.port), [])

    def of_host(self, host: Host) -> list[Component]:
        return self.by_host.get(host.address, [])

    def service_versioned(self, host: Host, svc: Service) -> bool:
        return any(c.versioned for c in self.of_service(host, svc))


# --- shared parsing ----------------------------------------------------------

_COMMENT = re.compile(r"\([^)]*\)")
_TOKEN = re.compile(r"^([A-Za-z][\w.+\-]*?)(?:/(v?\d[\w.+\-~]*)?)?$")


def parse_product_tokens(value: str) -> list[tuple[str, str | None]]:
    """RFC 7231 product tokens: `Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f` ->
    `[("Apache", "2.4.41"), ("OpenSSL", "1.1.1f")]`. Comments are dropped; a
    token that is not `name[/version]` is skipped rather than guessed at."""
    out: list[tuple[str, str | None]] = []
    for token in _COMMENT.sub(" ", value).split():
        m = _TOKEN.match(token.strip(",;"))
        if m:
            version = m.group(2)
            out.append((m.group(1), version.lstrip("v") if version else None))
    return out


_NAME_VERSION = re.compile(r"^(.+?)[ /]v?(\d[\w.+\-]*)\b")


def parse_generator(value: str) -> tuple[str, str | None] | None:
    """`WordPress 6.2.2` or `Drupal 9 (https://www.drupal.org)` -> name, version."""
    value = _COMMENT.sub(" ", value).strip()
    if not value:
        return None
    m = _NAME_VERSION.match(value)
    if m:
        return m.group(1).strip(), m.group(2)
    return value, None


def split_technology(value: str) -> tuple[str, str | None]:
    """gowitness's `Nginx:1.16.1` -> `("Nginx", "1.16.1")`; a colon that is not
    followed by a version stays part of the name."""
    name, sep, version = value.rpartition(":")
    if sep and name and version[:1].isdigit():
        return name.strip(), version.strip()
    return value.strip(), None


# --- recognisers: nmap -------------------------------------------------------


def _cpes(values: Iterable[str]) -> list[cpe_mod.Cpe]:
    return [c for c in (cpe_mod.parse(v) for v in values) if c is not None]


def _cpe_name(c: cpe_mod.Cpe) -> str:
    entry = cpe_mod.lookup(c.uri)
    return entry.display if entry else f"{c.vendor} {c.product}".replace("_", " ")


def from_nmap_service(host: Host, svc: Service) -> tuple[list[Observation], list[Observation]]:
    """nmap's identification: (service observations, host observations).

    Only a real probe names a product - a `method="table"` service was named
    from the port number, and that is not an identification. OS and hardware
    CPEs reported with a service (`cpe:/o:linux:linux_kernel` beside OpenSSH)
    describe the host, so they go there.
    """
    if svc.method != "probed":
        return [], []
    on_service = list(_nmap_identification(svc.product, svc.version, svc.extrainfo,
                                            svc.conf, tuple(svc.cpes), tuple(svc.sources)))
    if not svc.cpes:
        return on_service, []
    where = ", ".join(svc.sources)
    on_host = [Observation(_cpe_name(c), c.version or None, "nmap", f"with {svc.port}/"
                           f"{svc.protocol}" + (f" · {where}" if where else ""),
                           PROBE, (c.uri,), c.part)
               for c in _cpes(svc.cpes) if c.part != "a"]
    return on_service, on_host


# An engagement repeats a few identifications across hundreds of thousands of
# ports; the observation is a pure function of them, and immutable.
@lru_cache(maxsize=65536)
def _nmap_identification(product: str | None, version: str | None, extrainfo: str | None,
                         conf: str | None, cpes: tuple[str, ...],
                         sources: tuple[str, ...]) -> tuple[Observation, ...]:
    apps = [c for c in _cpes(cpes) if c.part == "a"]
    if not (product or apps):
        return ()
    # nmap sometimes leaves the distribution in the version ("10.0p2 Debian 7");
    # the version is its first token, and the rest is kept as detail.
    suffix = ""
    if version and " " in version:
        head, rest = version.split(" ", 1)
        if head[:1].isdigit() and rest[:1].isalpha():
            version, suffix = head, rest
    detail = " · ".join(b for b in (suffix, extrainfo, f"conf {conf}" if conf else "",
                                    ", ".join(sources)) if b)
    uris = tuple(c.uri for c in apps)
    # And sometimes it reports a Server header as the product
    # ("Python/3.8 websockets/8.1"): that is several products, each versioned.
    if product and "/" in product and not version and not apps:
        tokens = parse_product_tokens(product)
        if len(tokens) > 1 or (tokens and tokens[0][1]):
            return tuple(Observation(name, ver, "nmap", detail, PROBE, (), "a")
                         for name, ver in tokens)
    return (Observation(product or _cpe_name(apps[0]), version or None, "nmap", detail,
                        PROBE, uris, "a"),)


def from_os(host: Host) -> list[Observation]:
    """The best OS match, one observation per product its CPEs name. The
    version is asserted only when every CPE of that product agrees on it -
    `Linux 4.15 - 5.8` carries kernels 4 and 5, and neither is *the* version."""
    if not host.os_matches:
        return []
    best = host.os_matches[0]
    detail = best.name + (f" · accuracy {best.accuracy}" if best.accuracy else "")
    groups: dict[tuple[str, str], list[cpe_mod.Cpe]] = {}
    for c in _cpes(best.cpes):
        groups.setdefault((c.part, c.key), []).append(c)
    if not groups:
        family = host.osclass or best.name
        return [Observation(family, None, "os-detection", detail, PROBE, (), "o")]
    out = []
    for (part, _key), cs in groups.items():
        versions = {c.version for c in cs}
        version = versions.pop() if len(versions) == 1 else None
        out.append(Observation(_cpe_name(cs[0]), version or None, "os-detection", detail,
                               PROBE, tuple(c.uri for c in cs), part))
    return out


# --- recognisers: scripts ----------------------------------------------------

_HEADER_LINE = re.compile(r"^\s*(server|x-powered-by|x-aspnet-version|x-generator)\s*:\s*(.+?)\s*$",
                          re.IGNORECASE)
_SSH = re.compile(r"^\s*SSH-\d\.\d+-(\S+)(?:\s+(.*?))?\s*$")
_SSH_SOFTWARE = re.compile(r"^([A-Za-z][\w.\-]*?)[_\-](\d[\w.\-]*)$")
# Greetings of known daemons only. An unknown greeting says nothing: guessing a
# product out of free text is how "220 Welcome to Apache FTP" becomes httpd.
_GREETINGS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^220[ -].*\(vsFTPd ([\d.]+)\)", re.I), "vsftpd"),
    (re.compile(r"^220[ -].*\bProFTPD(?: (\d[\w.]*))?", re.I), "ProFTPD"),
    (re.compile(r"^220[ -].*\bPure-FTPd\b", re.I), "Pure-FTPd"),
    (re.compile(r"^220[ -].*\bFileZilla Server(?: version)?(?: (\d[\w.]*))?", re.I),
     "FileZilla Server"),
    (re.compile(r"^220[ -].*\bESMTP Postfix\b", re.I), "Postfix"),
    (re.compile(r"^220[ -].*\bExim (\d[\w.]*)", re.I), "Exim"),
    (re.compile(r"^220[ -].*\bSendmail (\d[\w.]*)", re.I), "Sendmail"),
    (re.compile(r"^(?:\+OK|\* OK).*\bDovecot\b", re.I), "Dovecot"),
)


def _lines(script: ScriptResult) -> list[str]:
    """Every line of a script's output, structured entries first."""
    texts: list[str] = []
    if isinstance(script.data, dict):
        texts += [v for v in script.data.values() if isinstance(v, str)]
    elif isinstance(script.data, list):
        texts += [v for v in script.data if isinstance(v, str)]
    if not texts and script.output:
        texts.append(script.output)
    return [line for text in texts for line in text.splitlines()]


def _from_header(name: str, value: str, source: str, rank: int,
                 detail: str) -> list[Observation]:
    name = name.lower()
    if name == "x-aspnet-version":
        return [Observation("ASP.NET", value.strip() or None, source, detail, rank)]
    if name == "x-generator":
        found = parse_generator(value)
        return [Observation(found[0], found[1], source, detail, rank)] if found else []
    return [Observation(p, v, source, detail, rank) for p, v in parse_product_tokens(value)]


def _from_line(line: str, source: str) -> list[Observation]:
    m = _HEADER_LINE.match(line)
    if m:
        return _from_header(m.group(1), m.group(2), source, BANNER,
                            f"{m.group(1).title()} line")
    m = _SSH.match(line)
    if m:
        soft = _SSH_SOFTWARE.match(m.group(1))
        product, version = (soft.group(1), soft.group(2)) if soft else (m.group(1), None)
        detail = "SSH banner" + (f" · {m.group(2)}" if m.group(2) else "")
        return [Observation(product, version, source, detail, BANNER)]
    stripped = line.strip()
    for pattern, product in _GREETINGS:
        g = pattern.match(stripped)
        if g:
            version = g.group(1) if g.groups() else None
            return [Observation(product, version, source, "greeting", BANNER)]
    return []


def from_script(script: ScriptResult) -> list[Observation]:
    """Software a service-level script names about its own service."""
    sid = script.id
    if sid == "http-server-header":
        values = script.data if isinstance(script.data, list) else [script.output or ""]
        return [Observation(p, v, sid, "Server header", BANNER)
                for value in values if isinstance(value, str)
                for p, v in parse_product_tokens(value)]
    if sid == "http-generator":
        found = parse_generator((script.output or "").strip())
        return [Observation(found[0], found[1], sid, "generator", BANNER)] if found else []
    if sid in ("fingerprint-strings", "banner"):
        out: list[Observation] = []
        for line in _lines(script):
            out += _from_line(line, sid)
        return out
    if sid == "vulners" and isinstance(script.data, dict):
        out = []
        for key in script.data:
            c = cpe_mod.parse(key)
            if c is not None:
                out.append(Observation(_cpe_name(c), c.version or None, sid, "CPE key",
                                       BANNER, (c.uri,), c.part))
        return out
    return []


def from_host_script(script: ScriptResult) -> tuple[list[Observation], list[Observation]]:
    """`smb-os-discovery`: (SMB-service observations, host observations). The
    LAN manager is the SMB server's software; `OS: Unix` says nothing."""
    if script.id != "smb-os-discovery" or not isinstance(script.data, dict):
        return [], []
    on_smb: list[Observation] = []
    on_host: list[Observation] = []
    lanman = script.data.get("lanmanager")
    if isinstance(lanman, str) and lanman.strip():
        found = parse_generator(lanman)
        if found:
            on_smb.append(Observation(found[0], found[1], script.id, "LAN manager", BANNER))
    os_name = script.data.get("os")
    if isinstance(os_name, str) and os_name.strip().lower().startswith("windows"):
        on_host.append(Observation("Windows", None, script.id, os_name.strip(), BANNER,
                                   kind="o"))
    return on_smb, on_host


# --- recognisers: captures ---------------------------------------------------

# Things a technology detector reports that are not software with a version of
# their own - a protocol, a policy header, a markup convention.
NOT_SOFTWARE = frozenset({"hsts", "http/2", "http/3", "websocket", "open graph", "rss",
                          "pwa"})


def from_capture(capture) -> list[Observation]:
    """What a gowitness capture says about the service it captured. A failed
    capture says nothing, and neither does a page title."""
    if capture.failed:
        return []
    where = capture.url
    out: list[Observation] = []
    for tech in capture.technologies:
        name, version = split_technology(tech)
        if name and cpe_mod.normal(name) not in NOT_SOFTWARE:
            out.append(Observation(name, version, "gowitness", f"technology · {where}",
                                   DETECTED))
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = capture.header(header)
        if value:
            label = "-".join(p.capitalize() for p in header.split("-"))
            out += _from_header(header, value, "gowitness", HEADER, f"{label} header · {where}")
    generator = getattr(capture, "generator", "")
    if generator:
        found = parse_generator(generator)
        if found:
            out.append(Observation(found[0], found[1], "gowitness",
                                   f"meta generator · {where}", HEADER))
    return out


# --- reconciliation ----------------------------------------------------------


def _class(ch: str) -> int:
    return 0 if ch.isdigit() else 1 if ch.isalpha() else 2


def refines(specific: str, general: str) -> bool:
    """Whether `specific` is `general` or a more precise form of it: `8.9p1` of
    `8.9`, `1.16.1` of `1.16` - but not `1.16` of `1.1`."""
    s, g = specific.casefold(), general.casefold()
    if s == g:
        return True
    if not s.startswith(g) or not g:
        return False
    nxt = s[len(g)]
    return nxt in "._-+~ " or _class(nxt) != _class(g[-1])


def reconcile(key: str, observations: list[Observation]) -> Component:
    """One component out of every observation of one product in one place."""
    ordered = sorted(observations, key=lambda o: o.rank)
    entry = cpe_mod.lookup(key) or next(
        (cpe_mod.lookup(c) for o in ordered for c in o.cpes if cpe_mod.lookup(c)), None)
    product = entry.display if entry else ordered[0].product
    kind = entry.kind if entry else next((o.kind for o in ordered if o.kind), "a")

    versions = [o.version for o in ordered if o.version]
    version: str | None = None
    conflicting = False
    for v in versions:
        if version is None or refines(v, version):
            version = v
        elif not refines(version, v):
            conflicting = True
    # A conflict leaves the most trusted source's version on show; refinement
    # only ever narrows *that* version, never replaces it with a rival's.
    if conflicting:
        best = versions[0]
        version = max((v for v in versions if refines(v, best)), key=len)

    nmap_cpes: list[cpe_mod.Cpe] = []
    for o in ordered:
        for c in _cpes(o.cpes):
            if c not in nmap_cpes:
                nmap_cpes.append(c)
    # An unversioned CPE says nothing a versioned one of the same product does
    # not (`linux_kernel` beside `linux_kernel:5`).
    versioned_keys = {c.key for c in nmap_cpes if c.version}
    nmap_cpes = [c for c in nmap_cpes if c.version or c.key not in versioned_keys]
    if nmap_cpes:
        cpes, origin = nmap_cpes, "nmap"
    elif entry is not None:
        cpes, origin = [entry.cpe(version or "")], "alias"
    else:
        cpes, origin = [], None
    return Component(key, product, version, kind, cpes, origin, ordered, conflicting)


def _key(o: Observation) -> str:
    entry = cpe_mod.lookup(o.product)
    if entry is None:
        entry = next((e for e in (cpe_mod.lookup(c) for c in o.cpes) if e), None)
    return entry.key if entry else cpe_mod.normal(o.product)


def _compatible(a: str, b: str) -> bool:
    return refines(a, b) or refines(b, a)


def split_detected(observations: list[Observation]) -> list[list[Observation]]:
    """Observations of one product on one port, as the components they are.

    One port can serve several pages - the address and each virtual host, an
    application and its admin interface - and each can load its own copy of a
    library: jQuery 2.1.3 on one, 3.4.1 on another. When every version comes
    from gowitness's captures, different versions are different components,
    not a conflict; a conflict is two sources disagreeing about *one* piece of
    software (nmap's probe against a banner). Versions that refine each other
    (`3.4` / `3.4.1`) stay together, and an unversioned detection joins the
    most trusted group rather than becoming a component of its own.
    """
    versioned = [o for o in observations if o.version]
    if len({o.version for o in versioned}) < 2 or any(o.source != "gowitness"
                                                       for o in versioned):
        return [observations]
    groups: list[list[Observation]] = []
    for o in sorted(versioned, key=lambda o: o.rank):
        home = next((g for g in groups
                     if all(_compatible(o.version, m.version) for m in g)), None)
        if home is None:
            groups.append([o])
        else:
            home.append(o)
    if len(groups) == 1:
        return [observations]
    groups[0] += [o for o in observations if not o.version]
    return groups


def _components(observations: list[Observation],
                memo: dict[tuple, list[Component]] | None = None) -> list[Component]:
    """The components of one place. With `memo`, places that saw exactly the
    same observations share one result - components are never written to after
    the build, and most ports of an engagement say the same thing."""
    if memo is not None:
        key = tuple(observations)
        found = memo.get(key)
        if found is None:
            found = memo[key] = _components(observations)
        return found
    groups: dict[str, list[Observation]] = {}
    for o in observations:
        groups.setdefault(_key(o), []).append(o)
    comps = [reconcile(k, part) for k, obs in groups.items() for part in split_detected(obs)]
    return sorted(comps, key=lambda c: (c.rank, c.product.casefold()))


# --- the whole model ---------------------------------------------------------

_SMB_PORTS = (445, 139)


def build(hosts: list[Host], captures_by_service: dict[ServiceKey, list] | None = None,
          unplaced: int = 0, report: Report | None = None) -> Inventory:
    """The inventory of every open service of `hosts`."""
    captures_by_service = captures_by_service or {}
    inv = Inventory(unplaced=unplaced)
    memo: dict[tuple, list[Component]] = {}
    for host in counted(hosts, report, HOSTS):
        host_obs: list[Observation] = from_os(host)
        service_obs: dict[ServiceKey, list[Observation]] = {}
        open_services = host.open_services
        for svc in open_services:
            key = (host.address, svc.protocol, svc.port)
            obs, on_host = from_nmap_service(host, svc)
            host_obs += on_host
            for script in svc.scripts:
                obs += from_script(script)
            for capture in captures_by_service.get(key, ()):
                obs += from_capture(capture)
            service_obs[key] = obs
        smb = next((s for p in _SMB_PORTS for s in open_services
                    if s.port == p and s.protocol == "tcp"), None)
        for script in host.scripts:
            on_smb, on_host = from_host_script(script)
            host_obs += on_host
            if smb is not None:
                service_obs[(host.address, "tcp", smb.port)] += on_smb
            else:
                host_obs += on_smb
        for key, obs in service_obs.items():
            if obs:
                inv.by_service[key] = _components(obs, memo)
        if host_obs:
            inv.by_host[host.address] = _components(host_obs, memo)
    return inv


@dataclass(slots=True, repr=False)
class Entry:
    """One product at one version across the model - a row of the Inventory
    tab - with every place it runs: `(host, service or None, component)`.

    The aggregates are computed once by `summarise`, not per access: a row
    reads each of them several times, and a common product runs in hundreds
    of thousands of places.
    """

    key: str
    product: str
    version: str | None
    kind: str
    places: list[tuple[Host, Service | None, Component]] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    service_count: int = 0
    rank: int = DETECTED
    conflicting: bool = False
    sources: list[str] = field(default_factory=list)
    cpes: list[cpe_mod.Cpe] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"Entry({self.label()}, {len(self.places)} place(s))"

    def label(self) -> str:
        return f"{self.product} {self.version}" if self.version else self.product

    def summarise(self) -> None:
        hosts: dict[int, Host] = {}
        sources: dict[str, None] = {}
        cpes: dict[cpe_mod.Cpe, None] = {}
        seen: set[int] = set()
        services = 0
        rank, conflicting = DETECTED, False
        for host, svc, c in self.places:
            hosts.setdefault(id(host), host)
            if svc is not None:
                services += 1
            if id(c) in seen:
                continue
            seen.add(id(c))
            rank = min(rank, c.rank)
            conflicting = conflicting or c.conflicting
            for o in c.observations:
                sources.setdefault(o.source, None)
            for cp in c.cpes:
                cpes.setdefault(cp, None)
        self.hosts, self.service_count = list(hosts.values()), services
        self.rank, self.conflicting = rank, conflicting
        self.sources, self.cpes = list(sources), list(cpes)

    @property
    def confidence(self) -> str:
        return CONFIDENCE[self.rank]

    @property
    def cpe22(self) -> list[str]:
        return [c.uri for c in self.cpes]

    @property
    def cpe23(self) -> list[str]:
        v = self.version
        return list(dict.fromkeys((c.with_version(v) if v and not c.version else c).fs
                                  for c in self.cpes))


def entries(inv: Inventory, hosts: list[Host]) -> list[Entry]:
    """Every component grouped by `(product key, version)`, in model order."""
    by_address = {h.address: h for h in hosts}
    services = {(h.address, s.protocol, s.port): s for h in hosts for s in h.services}
    out: dict[tuple[str, str], Entry] = {}

    def add(host: Host, svc: Service | None, c: Component) -> None:
        entry = out.get((c.key, c.version or ""))
        if entry is None:
            entry = out[(c.key, c.version or "")] = Entry(c.key, c.product, c.version,
                                                          c.kind)
        entry.places.append((host, svc, c))

    for skey, comps in inv.by_service.items():
        host, svc = by_address.get(skey[0]), services.get(skey)
        if host is None or svc is None:
            continue
        for c in comps:
            add(host, svc, c)
    for address, comps in inv.by_host.items():
        host = by_address.get(address)
        if host is None:
            continue
        for c in comps:
            add(host, None, c)
    for entry in out.values():
        entry.summarise()
    return list(out.values())
