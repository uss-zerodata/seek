"""The inventory, looked up: findings and support status per component.

Matching is by version: a CVE is a finding when one of its vulnerable CPE
criteria names the component's product (under *any* vendor name the product is
known by - NVD's nginx is both `igor_sysoev` and `f5`) and its range includes
the component's version. A range that cannot be decided makes the CVE
*undecided*, which is never shown as affected and never as safe. A component
with no version gets no findings at all - only the number of CVEs its product
has in any version.

Two layers, because components are shared: the inventory gives every port that
said the same thing one `Component` object, so the database's answer is kept per
component, while what a scan's own script reported (`vulners`, the NSE `vuln`
library) is kept per service and merged in when a service's findings are read.

Each distinct (product names, version) pair is evaluated once, however many
services run it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date

from seek.nmap import cpe as cpe_mod
from seek.nmap import vulns as vulns_mod
from seek.nmap.inventory import Component, Entry, Inventory, ServiceKey, refines
from seek.nmap.models import Host
from seek.vulndb import eol, versions
from seek.vulndb.store import Store

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1}
SEVERITIES = ("critical", "high", "medium", "low")


def severity_of(score: float | None) -> str:
    """CVSS v3 qualitative bands, for a score that came without a label."""
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else ""


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    severity: str = ""
    score: float | None = None
    vector: str = ""
    summary: str = ""
    url: str = ""
    sources: tuple[str, ...] = ()
    undecided: bool = False
    # nmap ran a check for this and reported it (NSE `vuln` scripts) - not a
    # version comparison, by nmap or by us. `state` is what it said.
    tested: bool = False
    state: str = ""
    # For a version family (`3.8`): how many of its known releases there are,
    # and how many of them the CVE's ranges cover. 0/0 when not a family.
    known: int = 0
    covered: int = 0

    @property
    def rank(self) -> tuple[int, float]:
        return (SEVERITY_RANK.get(self.severity.upper(), 0), self.score or 0.0)

    @property
    def likelihood(self) -> float | None:
        return self.covered / self.known if self.known else None

    def with_source(self, source: str) -> Finding:
        if source in self.sources:
            return self
        return replace(self, sources=(*self.sources, source))


def ordered(findings) -> list[Finding]:
    """What nmap tested first, then most severe, then highest score, then id."""
    return sorted(findings, key=lambda f: (not f.tested, -f.rank[0], -f.rank[1], f.id))


def by_likelihood(findings) -> list[Finding]:
    """Candidates: the share of the family's releases affected first, then
    severity - "affects 20 of 21 known 3.8.x" before "affects 1 of 21"."""
    return sorted(findings, key=lambda f: (-(f.likelihood or 0.0), -f.rank[0], -f.rank[1],
                                           f.id))


def host_key(address: str) -> ServiceKey:
    """Where a host script's findings are filed: the host, no port."""
    return (address, "", 0)


@dataclass(slots=True)
class Assessment:
    """What the lookup says about one component (on one service, if merged)."""

    findings: list[Finding] = field(default_factory=list)      # affected, ordered
    undecided: list[Finding] = field(default_factory=list)
    support: eol.Support = field(default_factory=lambda: eol.Support("unknown"))
    product_cves: int = 0          # for an unversioned component: CVEs in any version
    looked_up: bool = False        # the product has CPE names or an OSV package
    not_matched: str = ""          # why CVEs were deliberately not looked up

    @property
    def worst(self) -> Finding | None:
        return self.findings[0] if self.findings else None

    @property
    def max_severity(self) -> str:
        return self.findings[0].severity if self.findings else ""

    @property
    def max_score(self) -> float | None:
        scores = [f.score for f in self.findings if f.score is not None]
        return max(scores) if scores else None


@dataclass(slots=True, repr=False)
class Lookup:
    by_component: dict[int, Assessment] = field(default_factory=dict)
    # Scan-reported findings: per service, per product key (None: the script
    # named no product - the NSE `vuln` library's findings).
    scanned: dict[ServiceKey, dict[str | None, list[Finding]]] = field(default_factory=dict)
    db_missing: bool = True
    db_updated: float | None = None
    today: date = field(default_factory=date.today)

    def __repr__(self) -> str:
        return f"Lookup({len(self.by_component)} component(s), missing={self.db_missing})"

    def of(self, component: Component, where: ServiceKey | None = None) -> Assessment:
        """A component's assessment, with a service's own scan findings merged in."""
        base = self.by_component.get(id(component)) or Assessment()
        extra = self.scanned.get(where, {}).get(component.key, []) if where else []
        if not extra:
            return base
        return _merged(base, extra)

    def service_only(self, where: ServiceKey) -> list[Finding]:
        """What a scan reported for a service without naming a product."""
        return ordered(self.scanned.get(where, {}).get(None, []))

    def host_only(self, address: str) -> list[Finding]:
        """What a host script reported - `smb-vuln-ms17-010` runs per host."""
        return ordered(self.scanned.get(host_key(address), {}).get(None, []))

    def of_entry(self, entry: Entry) -> Assessment:
        """One product version across the model: the database's answer (the
        same for every place) with every place's scan findings merged in."""
        seen: dict[int, Component] = {}
        for _h, _s, c in entry.places:
            seen.setdefault(id(c), c)
        comps = list(seen.values())
        base = self.by_component.get(id(comps[0])) if comps else None
        result = base or Assessment()
        extra: list[Finding] = []
        for host, svc, c in entry.places:
            if svc is None:
                continue
            found = self.scanned.get((host.address, svc.protocol, svc.port))
            if found:
                extra += found.get(c.key, [])
        return _merged(result, extra) if extra else result


def _merged(base: Assessment, extra: list[Finding]) -> Assessment:
    by_id = {f.id: f for f in base.findings}
    undecided = {f.id: f for f in base.undecided}
    for f in extra:
        if f.id in by_id:
            merged = by_id[f.id].with_source(f.sources[0])
            if f.tested:
                merged = replace(merged, tested=True, state=f.state)
            by_id[f.id] = merged
        else:
            # A script said so: that outranks an undecided range.
            undecided.pop(f.id, None)
            by_id[f.id] = f
    return Assessment(ordered(by_id.values()), by_likelihood(undecided.values()),
                      base.support, base.product_cves, base.looked_up, base.not_matched)


# --- evaluation ------------------------------------------------------------------


def _criterion_version(version: str, update: str) -> str:
    return version + update if update not in ("", "*", "-") else version


class _Evaluator:
    """Everything the database is asked, asked once per build."""

    def __init__(self, store: Store, today: date) -> None:
        self.store = store
        self.today = today
        self._criteria: dict[str, list] = {}
        self._ranges: dict[str, list] = {}
        self._pairs: dict[tuple, Assessment] = {}
        self._cycles: dict[str, list] = {}
        self._releases: dict[str, list[str]] = {}
        self._slugs: dict[str, str] = {}

    def family(self, key: str, version: str) -> list[str]:
        """The known releases a version stands for: itself and every release
        that refines it (`3.8` -> 3.8.0 … 3.8.20), from the CPE dictionary."""
        found = self.all_releases(key)
        # Pre-releases are left out: a server runs 3.8.x, not 3.8.0b3, and a
        # beta the range happens to miss would turn "every release" into 37/38.
        return [r for r in found if refines(r, version) and not versions.is_prerelease(r)]

    def criteria(self, key: str) -> list:
        found = self._criteria.get(key)
        if found is None:
            vendor, _, product = key.partition(":")
            found = self._criteria[key] = self.store.criteria(vendor, product)
        return found

    def support(self, product_key: str, keys: tuple[str, ...],
                version: str | None) -> eol.Support:
        """A product version's support status, from the best source there is:
        endoflife.date (by override, else by the CPEs it declares), else the
        product's support policy against NVD's known releases."""
        slug = eol.SLUGS.get(product_key) or next(
            (found for found in (self.slug(k) for k in keys) if found), "")
        if slug:
            return eol.support(product_key, version, self.cycles(slug), self.today)
        releases = [r for k in keys for r in self.all_releases(k)]
        policy = eol.by_policy(product_key, version, releases)
        if policy is not None:
            return policy
        return eol.support(product_key, version, [], self.today, tracked=False)

    def slug(self, key: str) -> str:
        found = self._slugs.get(key)
        if found is None:
            found = self._slugs[key] = self.store.eol_slug(key)
        return found

    def all_releases(self, key: str) -> list[str]:
        found = self._releases.get(key)
        if found is None:
            vendor, _, product = key.partition(":")
            found = self._releases[key] = sorted(set(self.store.releases(vendor, product)))
        return found

    def cycles(self, slug: str) -> list:
        found = self._cycles.get(slug)
        if found is None:
            found = self._cycles[slug] = self.store.cycles(slug)
        return found

    def assess(self, component: Component) -> Assessment:
        if component.kind != "a":
            # An operating system or a device, from nmap's fingerprint: a guess
            # at a family ("Linux 4.15 - 5.8"), and a kernel has well over ten
            # thousand CVEs. Matched, it buries every real finding under
            # thousands that say nothing about this host - so it gets its
            # support status and no CVE list.
            keys = tuple(dict.fromkeys([*(c.key for c in component.cpes),
                                        *cpe_mod.cpe_keys(component.key)]))
            support = self.support(component.key, keys, component.version)
            return Assessment(support=support, not_matched=(
                "operating systems and devices are identified by fingerprint, a guess "
                "at a version family - their CVEs are not listed"))
        keys = tuple(dict.fromkeys([*(c.key for c in component.cpes),
                                    *cpe_mod.cpe_keys(component.key)]))
        package = eol.OSV_PACKAGES.get(component.key, "")
        pair = (keys, package, component.key, component.version or "")
        found = self._pairs.get(pair)
        if found is None:
            found = self._pairs[pair] = self._assess(keys, package, component.key,
                                                     component.version)
        return found

    def _assess(self, keys: tuple[str, ...], package: str, product_key: str,
                version: str | None) -> Assessment:
        support = self.support(product_key, keys, version)
        looked_up = bool(keys or package)
        if not version:
            ids = {c.cve_id for k in keys for c in self.criteria(k)}
            return Assessment(support=support, product_cves=len(ids), looked_up=looked_up)
        affected: dict[str, set[str]] = {}
        undecided: set[str] = set()
        # A version that names a family (`3.8`, from a header) is expanded into
        # the releases NVD knows for it, and each criterion is asked about each
        # one: covering all of them is a finding, none is no finding, some is a
        # candidate with a measured share.
        covered: dict[str, set[str]] = {}
        family_size: dict[str, int] = {}
        for key in keys:
            family: list[str] | None = None
            for c in self.criteria(key):
                exact = _criterion_version(c.version, c.update) \
                    if c.version not in ("*", "") else ""
                hit = _covers(version, exact, c)
                if hit:
                    affected.setdefault(c.cve_id, set()).add("nvd")
                    continue
                if hit is not None:
                    continue
                if family is None:
                    family = self.family(key, version)
                if not family:
                    undecided.add(c.cve_id)
                    continue
                family_size[c.cve_id] = max(family_size.get(c.cve_id, 0), len(family))
                bucket = covered.setdefault(c.cve_id, set())
                bucket.update(r for r in family if _covers(r, exact, c))
        candidates: dict[str, tuple[int, int]] = {}
        for cve, n in family_size.items():
            if cve in affected:
                continue
            hits = len(covered.get(cve, ()))
            if hits == n:
                affected.setdefault(cve, set()).add("nvd")      # every release is in
            elif hits:
                candidates[cve] = (n, hits)
            # none covered: no finding, whatever the bound looked like
        undecided -= set(affected) | set(candidates)
        osv_hits: dict[str, str] = {}          # finding id -> advisory id
        osv_undecided: set[str] = set()
        if package:
            for r in self.store.osv_ranges(package):
                if r.exact:
                    hit = versions.in_range(version, exact=r.exact)
                else:
                    hit = versions.in_range(version, start_incl=r.introduced,
                                            end_excl=r.fixed, end_incl=r.last_affected)
                if hit:
                    osv_hits[r.osv_id] = r.osv_id
                elif hit is None:
                    osv_undecided.add(r.osv_id)
        advisories = self.store.osv(sorted(set(osv_hits) | osv_undecided))
        findings: dict[str, Finding] = {}
        for oid in osv_hits:
            record = advisories.get(oid)
            cve = next((a for a in (record.aliases if record else ()) if a.startswith("CVE-")),
                       "")
            fid = cve or oid
            affected.setdefault(fid, set()).add("osv")
            if record is not None and fid not in findings:
                findings[fid] = Finding(fid, record.severity, record.score, "",
                                        record.summary, record.url)
        undecided -= set(affected)
        records = self.store.cves(sorted(set(affected) | undecided | set(candidates)))
        out: list[Finding] = []
        for fid, srcs in affected.items():
            rec = records.get(fid)
            if rec is not None:
                f = Finding(fid, rec.severity or severity_of(rec.score), rec.score, rec.vector,
                            rec.summary, rec.url)
            else:
                f = findings.get(fid) or Finding(fid)
            out.append(Finding(f.id, f.severity, f.score, f.vector, f.summary, f.url,
                               tuple(s for s in ("nvd", "osv") if s in srcs)))
        maybe = []
        for fid, (n, hits) in candidates.items():
            rec = records.get(fid)
            maybe.append(Finding(fid, rec.severity if rec else "", rec.score if rec else None,
                                 rec.vector if rec else "", rec.summary if rec else "",
                                 rec.url if rec else "", ("nvd",), True, known=n,
                                 covered=hits))
        for fid in sorted(undecided | (osv_undecided - set(osv_hits))):
            rec = records.get(fid)
            adv = advisories.get(fid)
            maybe.append(Finding(fid, rec.severity if rec else (adv.severity if adv else ""),
                                 rec.score if rec else None, rec.vector if rec else "",
                                 rec.summary if rec else (adv.summary if adv else ""),
                                 rec.url if rec else (adv.url if adv else ""),
                                 ("osv",) if adv and not rec else ("nvd",), True))
        return Assessment(ordered(out), by_likelihood(maybe), support, 0, looked_up)


def _covers(version: str, exact: str, c) -> bool | None:
    if exact:
        return versions.in_range(version, exact=exact)
    return versions.in_range(version, start_incl=c.start_incl, start_excl=c.start_excl,
                             end_incl=c.end_incl, end_excl=c.end_excl)


# (id, score, source, tested, state)
_ScanItem = tuple[str, float | None, str, bool, str]


def _from_scripts(scripts) -> dict[str | None, dict[str, _ScanItem]]:
    """Per product key (None: unnamed), every finding the scripts reported.

    `vulners` is a version lookup nmap did - it names the product by CPE and is
    *not* a test. Every other vulnerability script ran a check against the
    target, and what it reported is kept as tested, with its state."""
    per: dict[str | None, dict[str, _ScanItem]] = {}
    for script in scripts:
        if script.id == "vulners" and isinstance(script.data, dict):
            for cpe_text, entries in script.data.items():
                parsed = cpe_mod.parse(cpe_text)
                entry = cpe_mod.lookup(cpe_text) if parsed else None
                key = entry.key if entry else (cpe_mod.normal(parsed.product.replace(
                    "_", " ")) if parsed else None)
                for v in vulns_mod.from_script(type(script)(script.id, script.output,
                                                            {cpe_text: entries})):
                    per.setdefault(key, {})[v.id] = (v.id, _float(v.severity), "vulners",
                                                     False, "")
        else:
            for v in vulns_mod.from_script(script):
                per.setdefault(None, {})[v.id] = (v.id, _float(v.severity), script.id, True,
                                                  v.state or "reported")
    return per


def _scan_findings(host: Host, store: Store) -> dict[ServiceKey, dict[str | None, list]]:
    """What the scans' own scripts reported - per service, and per host for the
    host scripts (`smb-vuln-*` run once per host, not per port)."""
    out: dict[ServiceKey, dict[str | None, list]] = {}
    for svc in host.open_services:
        per = _from_scripts(svc.scripts)
        if per:
            out[(host.address, svc.protocol, svc.port)] = {
                k: list(items.values()) for k, items in per.items()}
    per = _from_scripts(host.scripts)
    if per:
        out[host_key(host.address)] = {None: [i for items in per.values()
                                              for i in items.values()]}
    return out


def _float(value) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def build(inventory: Inventory, hosts: list[Host], store: Store,
          today: date | None = None) -> Lookup:
    """Every component of the inventory, looked up once per distinct version."""
    today = today or date.today()
    lookup = Lookup(db_missing=store.missing, db_updated=store.updated_at(), today=today)
    evaluator = _Evaluator(store, today)
    for comps in (*inventory.by_service.values(), *inventory.by_host.values()):
        for c in comps:
            if id(c) not in lookup.by_component:
                lookup.by_component[id(c)] = evaluator.assess(c)
    # The scans' own findings, with the database's words where it has them.
    raw: dict[ServiceKey, dict[str | None, list]] = {}
    for host in hosts:
        raw.update(_scan_findings(host, store))
    ids = sorted({item[0] for per in raw.values() for items in per.values() for item in items})
    records = store.cves([i for i in ids if i.startswith("CVE-")])
    for where, per in raw.items():
        lookup.scanned[where] = {}
        for key, items in per.items():
            found = []
            for fid, score, source, tested, state in items:
                rec = records.get(fid)
                found.append(Finding(
                    fid, rec.severity if rec else severity_of(score),
                    rec.score if rec else score, rec.vector if rec else "",
                    rec.summary if rec else "",
                    rec.url if rec else (f"https://nvd.nist.gov/vuln/detail/{fid}"
                                         if fid.startswith("CVE-") else ""),
                    (source,), tested=tested, state=state))
            lookup.scanned[where][key] = found
    return lookup


# --- the Findings overview ------------------------------------------------------------


@dataclass(slots=True, repr=False)
class Affected:
    """One finding on one product version: a row of the Findings tab, with the
    places it actually applies to. A database finding applies wherever the
    version runs; a finding only a scan reported, only where that scan said so."""

    finding: Finding
    entry: Entry | None                     # None: a script named no product
    places: list[tuple[Host, object, Component | None]] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"Affected({self.finding.id}, {len(self.places)} place(s))"

    @property
    def product(self) -> str:
        return self.entry.product if self.entry is not None else ""

    @property
    def version(self) -> str | None:
        return self.entry.version if self.entry is not None else None

    @property
    def hosts(self) -> list[Host]:
        return list({id(h): h for h, _s, _c in self.places}.values())

    @property
    def service_count(self) -> int:
        return sum(1 for _h, s, _c in self.places if s is not None)


def affected(lookup: Lookup, entries: list[Entry], hosts: list[Host]) -> list[Affected]:
    out: list[Affected] = []
    for entry in entries:
        seen: dict[int, Component] = {}
        for _h, _s, c in entry.places:
            seen.setdefault(id(c), c)
        base = lookup.by_component.get(id(next(iter(seen.values())))) if seen else None
        general = {f.id for f in base.findings} if base else set()
        whole = lookup.of_entry(entry)
        # The most likely candidates are listed beside the findings: the reader
        # asked for the obvious things to verify, and a release family that is
        # 20/21 covered is exactly that. Ranges that could not be measured are not.
        candidates = [f for f in whole.undecided if f.known]
        for f in candidates:
            out.append(Affected(f, entry, list(entry.places)))
        for f in whole.findings:
            rows: list[tuple[Host, object, Component | None]] = []
            for host, svc, c in entry.places:
                if f.id in general:
                    rows.append((host, svc, c))
                elif svc is not None:
                    found = lookup.scanned.get((host.address, svc.protocol, svc.port), {})
                    if any(x.id == f.id for x in found.get(c.key, [])):
                        rows.append((host, svc, c))
            if rows:
                out.append(Affected(f, entry, rows))
    # What a script reported without naming a product: grouped by id.
    services = {(h.address, s.protocol, s.port): (h, s) for h in hosts for s in h.services}
    services.update({host_key(h.address): (h, None) for h in hosts})
    loose: dict[str, Affected] = {}
    for where, per in lookup.scanned.items():
        for f in per.get(None, []):
            host, svc = services.get(where, (None, None))
            if host is None:
                continue
            a = loose.setdefault(f.id, Affected(f, None))
            a.places.append((host, svc, None))
    return out + list(loose.values())
