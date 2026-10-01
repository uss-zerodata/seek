"""Support status: which release line a version belongs to, and whether that
line has ended, the version is behind its latest release, or it is current.

Where the answer comes from, in order:

- **endoflife.date**, matched by the CPEs it declares for its products (its
  catalogue carries them - `store.eol_slug`), or by `SLUGS`, which only
  overrides that for products it declares no CPE for;
- a **support policy** (`POLICIES`): upstream maintains only its latest
  release, so anything older than the newest release NVD knows is behind -
  for products endoflife.date does not track, such as OpenSSH;
- otherwise **unknown**, with the reason.

A version that names a family rather than a release (`5`, from an OS
fingerprint) is judged across the lines in it: all ended is end of life, none
ended is supported, some is *mixed* and names the ones still supported. A
version older than every line tracked, when even the oldest has ended, is end
of life too - endoflife.date lists Linux back to 4.9, and 3.x is long gone.

`OSV_PACKAGES` maps the client-side libraries to their npm package names.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from seek.nmap.inventory import refines
from seek.vulndb import versions
from seek.vulndb.store import Cycle

SLUGS: dict[str, str] = {
    "nginx": "nginx",
    "apache-httpd": "apache-http-server",
    "apache-tomcat": "tomcat",
    "haproxy": "haproxy",
    "varnish": "vinyl-cache",   # Varnish Cache was renamed Vinyl Cache
    "caddy": "caddy",
    "envoy": "envoy",
    "squid": "squid",
    "exim": "exim",
    "postfix": "postfix",
    "dovecot": "dovecot",
    "memcached": "memcached",
    "traefik": "traefik",
    "php": "php",
    "python": "python",
    "nodejs": "nodejs",
    "django": "django",
    "rails": "rails",
    "openssl": "openssl",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "typo3": "typo3",
    "grafana": "grafana",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "proxmox-ve": "proxmox-ve",
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "vuejs": "vue",
    "react": "react",
    "angularjs": "angularjs",
    "samba": "samba",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "mssql": "mssqlserver",
    "linux": "linux",
    "windows": "windows",
}

OSV_PACKAGES: dict[str, str] = {
    "jquery": "jquery",
    "lodash": "lodash",
    "bootstrap": "bootstrap",
    "vuejs": "vue",
    "react": "react",
    "angularjs": "angular",
    "express": "express",
}

# Products whose upstream supports only the latest release, so that "older
# than the newest known release" means unsupported. Only projects that say so
# themselves are listed.
POLICIES: dict[str, str] = {
    "openssh": "OpenSSH supports only its latest release",
    "exim": "Exim supports only its latest release",
}

ENDING_SOON = timedelta(days=90)

STATES = ("eol", "behind", "mixed", "current", "unknown")
# How each state reads at a glance - the colour a front end gives it.
TONE = {"current": "ok", "behind": "warn", "mixed": "warn", "eol": "bad", "unknown": "dim"}


@dataclass(frozen=True, slots=True)
class Support:
    status: str                 # one of STATES
    cycle: str = ""
    eol_date: str = ""          # ISO date the line ended or ends; "" if none given
    latest: str = ""            # the line's (or, by policy, the product's) newest release
    ending_soon: bool = False
    reason: str = ""            # why unknown, in words
    released: str = ""          # when the release line started
    latest_date: str = ""       # when its newest release came out
    basis: str = ""             # where the answer comes from, in words
    detail: str = ""            # the family's lines, for `mixed`

    @property
    def tone(self) -> str:
        return TONE.get(self.status, "dim")

    def label(self) -> str:
        """The table cell: short, and every known state says something."""
        if self.status == "eol":
            return f"EOL {self.eol_date}" if self.eol_date else "EOL"
        if self.status == "behind":
            return f"behind · {self.latest}"
        if self.status == "mixed":
            return f"mixed · {self.detail}"
        if self.status == "current":
            when = f" ({self.latest_date})" if self.latest_date else ""
            return f"current{when}"
        return "unknown"


def _as_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def choose_cycle(version: str, cycles: list[Cycle]) -> Cycle | None:
    """The most specific line the version belongs to: `7.4` for `7.4.33`,
    `20` for `20.11.1`, and `1.24` rather than `1` when both exist."""
    fitting = [c for c in cycles if refines(version, c.cycle)]
    return max(fitting, key=lambda c: len(c.cycle), default=None)


def _ended(c: Cycle, today: date) -> tuple[bool, date | None]:
    ended = _as_date(c.eol)
    return (c.eol == "true" or (ended is not None and ended <= today)), ended


def _line(version: str, c: Cycle, today: date, basis: str) -> Support:
    """The answer for a version inside one release line."""
    over, ended = _ended(c, today)
    common = {"cycle": c.cycle, "released": c.released, "latest": c.latest,
              "latest_date": c.latest_date, "basis": basis}
    if over:
        return Support("eol", eol_date=ended.isoformat() if ended else "", **common)
    soon = ended is not None and ended - today <= ENDING_SOON
    date_text = ended.isoformat() if ended else ""
    if not c.latest:
        return Support("unknown", eol_date=date_text, ending_soon=soon,
                       reason="the line names no latest release", **common)
    order = versions.compare(version, c.latest)
    if order is None:
        return Support("unknown", eol_date=date_text, ending_soon=soon,
                       reason=f"{version} cannot be compared with {c.latest}", **common)
    return Support("behind" if order < 0 else "current", eol_date=date_text,
                   ending_soon=soon, **common)


def _family(version: str, cycles: list[Cycle], today: date, basis: str) -> Support | None:
    """A version that names a family (`5`): judged across the lines in it, or -
    older than every line tracked - by the oldest line's end."""
    members = [c for c in cycles if refines(c.cycle, version) and c.cycle != version]
    if members:
        ended = [c for c in members if _ended(c, today)[0]]
        live = [c for c in members if c not in ended]
        newest = max(members, key=lambda c: versions.segments(c.cycle) or ())
        if not live:
            last = max((_ended(c, today)[1] for c in ended if _ended(c, today)[1]),
                       default=None)
            return Support("eol", cycle=f"{version}.x", eol_date=last.isoformat()
                           if last else "", latest=newest.latest, basis=basis)
        names = ", ".join(sorted((c.cycle for c in live),
                                 key=lambda v: versions.segments(v) or ()))
        if not ended:
            return Support("current", cycle=f"{version}.x", latest=newest.latest,
                           latest_date=newest.latest_date, basis=basis,
                           detail=f"every {version}.x line is supported")
        return Support("mixed", cycle=f"{version}.x", latest=newest.latest, basis=basis,
                       detail=f"{names} supported, {len(ended)} line(s) ended")
    # Older than everything tracked: the oldest line's end bounds it.
    known = [c for c in cycles if versions.segments(c.cycle) is not None]
    if not known:
        return None
    oldest = min(known, key=lambda c: versions.segments(c.cycle))
    order = versions.compare(version, oldest.cycle)
    over, ended = _ended(oldest, today)
    if order is not None and order < 0 and over:
        return Support("eol", cycle=version, eol_date="", latest=oldest.latest,
                       basis=f"{basis}: older than every tracked line - the oldest, "
                             f"{oldest.cycle}, ended "
                             f"{ended.isoformat() if ended else 'long ago'}")
    return None


def support(key: str, version: str | None, cycles: list[Cycle], today: date,
            tracked: bool = True) -> Support:
    """From endoflife.date's release lines for the product."""
    basis = "endoflife.date"
    if not tracked:
        return Support("unknown", reason="not tracked by endoflife.date")
    if not version:
        return Support("unknown", reason="version unknown")
    if not cycles:
        return Support("unknown", reason="no release data - update the database")
    cycle = choose_cycle(version, cycles)
    if cycle is not None:
        return _line(version, cycle, today, basis)
    found = _family(version, cycles, today, basis)
    if found is not None:
        return found
    return Support("unknown", reason=f"no release line matches {version}")


def by_policy(key: str, version: str | None, releases: list[str]) -> Support | None:
    """For a product whose upstream supports only its latest release: behind
    when a newer release is known, current when none is. `None` when no policy
    applies or nothing is known to compare with."""
    policy = POLICIES.get(key)
    if policy is None:
        return None
    if not version:
        return Support("unknown", reason="version unknown", basis=policy)
    finals = [r for r in releases if not versions.is_prerelease(r)
              and versions.segments(r) is not None]
    if not finals:
        return Support("unknown", reason="no releases known - update the database",
                       basis=policy)
    newest = finals[0]
    for r in finals[1:]:
        if versions.compare(r, newest) == 1:
            newest = r
    order = versions.compare(version, newest)
    if order is None:
        return Support("unknown", reason=f"{version} cannot be compared with {newest}",
                       basis=policy)
    basis = f"{policy}; newest release known to NVD: {newest}"
    return Support("behind" if order < 0 else "current", latest=newest, basis=basis)
