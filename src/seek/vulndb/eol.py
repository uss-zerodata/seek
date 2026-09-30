"""Support status: which release cycle a version belongs to, and whether that
cycle is past its end of life or the version behind its latest release.

`SLUGS` maps the inventory's product keys (`nmap.cpe` table keys) to
endoflife.date product slugs - every one checked against endoflife.date's
`all.json` on 2026-10-01; `OSV_PACKAGES` maps the client-side libraries to
their npm package names. Both are reviewed tables like `cpe.ALIASES`, and both
are fixed: the update fetches *every* slug here, not the ones an inventory
needs, so the set of requests says nothing about the engagement. The update also
checks the slugs against endoflife.date's own product list and reports any it
does not know, so a renamed product is visible rather than silently untracked.
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

ENDING_SOON = timedelta(days=90)


@dataclass(frozen=True, slots=True)
class Support:
    status: str                 # "eol" | "behind" | "current" | "unknown"
    cycle: str = ""
    eol_date: str = ""          # ISO date, or "" (no date given / not ended)
    latest: str = ""
    ending_soon: bool = False
    reason: str = ""            # why unknown, in words

    def label(self) -> str:
        if self.status == "eol":
            return f"EOL {self.eol_date}" if self.eol_date else "EOL"
        if self.status == "behind":
            return f"behind · {self.latest}"
        if self.status == "current":
            return "current"
        return "unknown"


def _as_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def choose_cycle(version: str, cycles: list[Cycle]) -> Cycle | None:
    """The most specific cycle the version belongs to: `7.4` for `7.4.33`,
    `20` for `20.11.1`, and `1.24` rather than `1` when both exist."""
    fitting = [c for c in cycles if refines(version, c.cycle)]
    return max(fitting, key=lambda c: len(c.cycle), default=None)


def support(key: str, version: str | None, cycles: list[Cycle], today: date) -> Support:
    if key not in SLUGS:
        return Support("unknown", reason="not tracked by endoflife.date")
    if not version:
        return Support("unknown", reason="version unknown")
    if not cycles:
        return Support("unknown", reason="no release data - update the database")
    cycle = choose_cycle(version, cycles)
    if cycle is None:
        return Support("unknown", reason=f"no release cycle matches {version}")
    ended = _as_date(cycle.eol)
    if cycle.eol == "true" or (ended is not None and ended <= today):
        return Support("eol", cycle.cycle, ended.isoformat() if ended else "",
                       cycle.latest)
    soon = ended is not None and ended - today <= ENDING_SOON
    date_text = ended.isoformat() if ended else ""
    if not cycle.latest:
        return Support("unknown", cycle.cycle, date_text, "", soon,
                       "the cycle names no latest release")
    order = versions.compare(version, cycle.latest)
    if order is None:
        return Support("unknown", cycle.cycle, date_text, cycle.latest, soon,
                       f"{version} cannot be compared with {cycle.latest}")
    status = "behind" if order < 0 else "current"
    return Support(status, cycle.cycle, date_text, cycle.latest, soon)
