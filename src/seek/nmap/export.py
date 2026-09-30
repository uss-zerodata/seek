"""Turning a selection into something the next tool can read.

The viewer's output is usually the input to another command - a host list for a
focused `nmap -iL`, a URL list for gowitness - so what leaves here has to be
shaped by the user, not by what one view happened to be showing.

Everything in this module is pure: records in, text out. It imports no Textual
and no `ScanSet`, so the same selection that is written to a file today can be
handed to a tool runner later without going through the screen.

The unit is a **record**: a host, together with one of its services when the row
stood for a service. A host alone cannot express "443/tcp on 10.0.0.5", which is
the half of an export the old host-only recipes could not do at all.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from seek.nmap import inventory as inv_mod
from seek.nmap import names
from seek.nmap.models import Host, Service

# Services nmap names that are HTTP(S) in practice, for URL construction.
_HTTP_NAMES = frozenset({
    "http", "https", "http-alt", "https-alt", "http-proxy", "www", "http-mgmt",
})
_TLS_NAMES = frozenset({"https", "https-alt", "ssl/http"})
_SCHEME_PORTS = {"http": 80, "https": 443}


@dataclass(slots=True)
class Record:
    """One host, or one service on one host.

    `identity` is what a mark is keyed on: it survives the rebuild every filter
    keystroke causes, and it is the same key whichever view the record was
    selected from. A host and one of its services are *different* records -
    marking `10.0.0.5` and marking `443/tcp` on it are different intentions.
    """

    host: Host
    service: Service | None = None

    @property
    def identity(self) -> tuple:
        if self.service is None:
            return (self.host.address,)
        return (self.host.address, self.service.protocol, self.service.port)

    @property
    def services(self) -> list[Service]:
        """What this record covers: its own service, or the host's open ones."""
        return [self.service] if self.service is not None else self.host.open_services


def records_for(hosts: Iterable[Host]) -> list[Record]:
    """Whole hosts as records - what an export over a host list used to take."""
    return [Record(h) for h in hosts]


def _is_http(svc: Service) -> bool:
    if svc.name in _HTTP_NAMES or svc.name in _TLS_NAMES:
        return True
    return any(s.id.startswith("http-") for s in svc.scripts)


def _scheme(svc: Service) -> str:
    if svc.tunnel == "ssl" or svc.name in _TLS_NAMES:
        return "https"
    return "http"


# --- the names a host is known by -------------------------------------------


def names_for(record: Record) -> list[str]:
    """Every DNS name known for this record: resolved, then certificate-claimed.

    Read from the model rather than re-derived - `names.attach` did the work at
    load time.
    """
    found = list(record.host.hostnames)
    for svc in record.services:
        found += [name for name, _ in svc.names]
    return list(dict.fromkeys(n for n in found if n))


def service_url(host: Host, svc: Service) -> str:
    """The URL for a web service, with the port unless it is the default."""
    if not _is_http(svc):
        return ""
    scheme = _scheme(svc)
    if svc.port == _SCHEME_PORTS[scheme]:
        return f"{scheme}://{host.address}"
    return f"{scheme}://{host.address}:{svc.port}"


# --- the field catalogue ----------------------------------------------------
# Order here *is* column order, so two exports of the same fields line up. Every
# accessor returns a string - empty when the fact is absent - which is what lets
# the three writers share one row builder and never disagree about `None`.

def _svc(record: Record, get: Callable[[Service], object]) -> str:
    if record.service is None:
        return ""
    value = get(record.service)
    return "" if value in (None, "") else str(value)


FIELDS: list[tuple[str, Callable[[Record], str]]] = [
    ("address", lambda r: r.host.address),
    ("hostname", lambda r: r.host.hostname or ""),
    ("names", lambda r: ",".join(names_for(r))),
    ("os", lambda r: r.host.os or ""),
    ("state", lambda r: r.host.state or ""),
    ("up", lambda r: "yes" if r.host.up else "no"),
    ("sources", lambda r: ",".join(r.host.sources)),
    ("port", lambda r: _svc(r, lambda s: s.port)),
    ("protocol", lambda r: _svc(r, lambda s: s.protocol)),
    ("port_label", lambda r: _svc(r, lambda s: f"{s.port}/{s.protocol}")),
    ("service", lambda r: _svc(r, lambda s: s.name)),
    ("product", lambda r: _svc(r, lambda s: s.product)),
    ("version", lambda r: _svc(r, lambda s: s.version)),
    ("extrainfo", lambda r: _svc(r, lambda s: s.extrainfo)),
    ("tunnel", lambda r: _svc(r, lambda s: s.tunnel)),
    ("vulns", lambda r: str(sum(len(s.vulnerabilities) for s in r.services))),
    ("url", lambda r: "" if r.service is None else service_url(r.host, r.service)),
]
FIELD_NAMES = [name for name, _ in FIELDS]
_ACCESSORS = dict(FIELDS)


def rows(records: Iterable[Record], fields: Iterable[str]) -> list[tuple[str, ...]]:
    """One row per record, in catalogue order, with duplicates dropped.

    A duplicate row carries no information in any of the three formats: asked
    for `address` alone, five marked services on one host are one host.
    """
    picked = [f for f in FIELD_NAMES if f in set(fields)]
    built = [tuple(_ACCESSORS[f](r) for f in picked) for r in records]
    return list(dict.fromkeys(built))


def ordered_fields(fields: Iterable[str]) -> list[str]:
    return [f for f in FIELD_NAMES if f in set(fields)]


# --- writers ----------------------------------------------------------------


def _write(table: list[tuple[str, ...]], header: list[str], fmt: str) -> str:
    """One table, three shapes. Rows are already deduplicated and ordered."""
    if fmt == "text":
        return "\n".join(" ".join(row).rstrip() for row in table)
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(table)
        return buffer.getvalue().rstrip("\n")
    if fmt == "json":
        return json.dumps([dict(zip(header, row, strict=True)) for row in table],
                          indent=2)
    raise ValueError(f"unknown format: {fmt}")


def render(records: Iterable[Record], fields: Iterable[str], fmt: str) -> str:
    """The field-picked export: the chosen fields, in catalogue order."""
    picked = ordered_fields(fields)
    return _write(rows(records, picked), picked, fmt)


def render_items(items: list[str], column: str, fmt: str) -> str:
    """A named recipe's one-per-line output, in the chosen format."""
    return _write([(item,) for item in items], [column], fmt)


FORMATS: dict[str, tuple[str, str]] = {
    "text": ("Plain text", ".txt"),
    "csv": ("CSV (with a header row)", ".csv"),
    "json": ("JSON (one object per record)", ".json"),
}


# --- the named recipes ------------------------------------------------------
# Each takes records rather than hosts, so a marked service exports as itself,
# and each returns its items rather than one blob, so the format choice can
# apply to it. A recipe that names hosts names each host once, however many of
# its services were selected.


def _unique(values: Iterable[str]) -> list[str]:
    return [v for v in dict.fromkeys(values) if v]


def export_hosts(records: Iterable[Record]) -> list[str]:
    return _unique(r.host.address for r in records if r.host.open_services)


def export_up_hosts(records: Iterable[Record]) -> list[str]:
    """The hosts `u` keeps: an open port, or a real host-discovery answer."""
    return _unique(r.host.address for r in records if r.host.up)


def export_all_hosts(records: Iterable[Record]) -> list[str]:
    return _unique(r.host.address for r in records)


def export_ports(records: Iterable[Record]) -> list[str]:
    """Distinct ports, comma separated - the form `-p` takes.

    One line whatever happens, which is why its entry below offers no column
    name: there is nothing for a header to name and nothing to key an object by.
    """
    ports = sorted({s.port for r in records for s in r.services})
    return [",".join(str(p) for p in ports)] if ports else []


def export_host_ports(records: Iterable[Record]) -> list[str]:
    return _unique(f"{r.host.address}:{s.port}"
                   for r in records for s in r.services)


def export_urls(records: Iterable[Record]) -> list[str]:
    """HTTP(S) URLs for every host *and* every name it is known by.

    The address is what the scan found; the names are what a web server answers
    to, and virtual hosting means the two often serve different things. A list
    meant for a screenshotting tool wants both, which is exactly the two lists
    the reference workflow builds separately and then combines.
    """
    urls: list[str] = []
    for record in records:
        known = names_for(record)
        for svc in record.services:
            base = service_url(record.host, svc)
            if not base:                    # not an HTTP service
                continue
            urls.append(base)
            urls += [url_for(name, svc) for name in known]
    return _unique(urls)


def url_for(host_name: str, svc: Service) -> str:
    """The same URL, for a name the host answers to rather than its address."""
    scheme = _scheme(svc)
    if svc.port == _SCHEME_PORTS[scheme]:
        return f"{scheme}://{host_name}"
    return f"{scheme}://{host_name}:{svc.port}"


def service_urls(svc: Service, host: Host | None) -> list[str]:
    """Every address the service answers on - the one scanned and every name.

    Virtual hosting means these can serve different things, so a list that shows
    only the address hides half of what was found.
    """
    if host is None:
        return [u for u in [url_for(n, svc) for n, _ in svc.names] if u]
    base = service_url(host, svc)
    if not base:
        return []
    known = [n for n, _ in names.host_names(host)]
    return list(dict.fromkeys([base, *(url_for(n, svc) for n in known)]))


# (label, recipe, the column its items are - or None when the shape is fixed and
# a format choice would be a lie about what was written).
EXPORTS: dict[str, tuple[str, Callable[[Iterable[Record]], list[str]], str | None]] = {
    "hosts": ("Hosts with open ports", export_hosts, "address"),
    "up-hosts": ("Up hosts", export_up_hosts, "address"),
    "all-hosts": ("All hosts", export_all_hosts, "address"),
    "ports": ("Open ports (comma separated)", export_ports, None),
    "host-ports": ("host:port pairs", export_host_ports, "host_port"),
    "urls": ("HTTP/HTTPS URLs", export_urls, "url"),
    # Built by `produce` from the inventory, not by a recipe over records: the
    # recipe slot is never called for it.
    "inventory": ("Software inventory (products, versions, CPEs)", lambda _r: [],
                  "inventory"),
}


# --- the software inventory ---------------------------------------------------
# A document rather than a list: it is the contract the vulnerability lookup
# reads, so it names itself and its version. Adding a field keeps the version;
# renaming a field or changing what one means increases it.

INVENTORY_SCHEMA = "seek.inventory"
# 2: each entry gained `support` and `findings`, the document `vulndb_date`.
INVENTORY_VERSION = 2
INVENTORY_FIELDS = ["address", "names", "port", "protocol", "service", "product", "version",
                    "kind", "cpe22", "cpe23", "cpe_origin", "confidence", "conflicting",
                    "observations", "support", "findings"]
# The CSV flattens `support` to its state and `findings` to a count, and adds
# the two columns a spreadsheet sorts and filters by.
INVENTORY_CSV_FIELDS = [*INVENTORY_FIELDS, "max_severity", "finding_ids"]


def _support(a) -> dict:
    s = a.support
    return {"status": s.status, "cycle": s.cycle or None, "eol_date": s.eol_date or None,
            "latest": s.latest or None, "ending_soon": s.ending_soon,
            "reason": s.reason or None}


def _finding(f) -> dict:
    return {"id": f.id, "sources": list(f.sources), "severity": f.severity or None,
            "score": f.score, "vector": f.vector or None, "url": f.url or None,
            "summary": f.summary or None, "undecided": f.undecided}


def _entry(host: Host, svc: Service | None, c: inv_mod.Component, lookup=None) -> dict:
    if lookup is not None and not lookup.db_missing:
        where = (host.address, svc.protocol, svc.port) if svc is not None else None
        a = lookup.of(c, where)
        support = _support(a)
        findings = [_finding(f) for f in [*a.findings, *a.undecided]]
    else:
        support, findings = None, []
    return {
        "address": host.address,
        "names": names.names_of(host),
        "port": svc.port if svc is not None else None,
        "protocol": svc.protocol if svc is not None else None,
        "service": (svc.name or None) if svc is not None else None,
        "product": c.product,
        "version": c.version,
        "kind": inv_mod.KIND_NAMES.get(c.kind, c.kind),
        "cpe22": c.cpe22,
        "cpe23": c.cpe23,
        "cpe_origin": c.cpe_origin,
        "confidence": c.confidence,
        "conflicting": c.conflicting,
        "observations": [{"source": o.source, "product": o.product, "version": o.version,
                          "detail": o.detail} for o in c.observations],
        "support": support,
        "findings": findings,
    }


def inventory_entries(records: Iterable[Record], inventory: inv_mod.Inventory,
                      lookup=None) -> list[dict]:
    """One entry per component per service, and per host for the components
    that describe the host. A host record covers its open services and its
    own components; a service record covers that service only."""
    out: dict[tuple, dict] = {}
    for record in records:
        host = record.host
        if record.service is None:
            for c in inventory.of_host(host):
                out.setdefault((host.address, None, c.key, c.version),
                               _entry(host, None, c, lookup))
        for svc in record.services:
            for c in inventory.of_service(host, svc):
                out.setdefault((host.address, (svc.protocol, svc.port), c.key, c.version),
                               _entry(host, svc, c, lookup))
    return list(out.values())


def inventory_document(records: Iterable[Record], inventory: inv_mod.Inventory,
                       lookup=None) -> dict:
    """The versioned document. `lookup` (a `vulndb.match.Lookup`) adds each
    entry's support status and findings; without a database both are empty and
    `vulndb_date` is null, which is how a reader tells "none found" from "not
    looked up"."""
    updated = None
    if lookup is not None and not lookup.db_missing and lookup.db_updated:
        updated = datetime.fromtimestamp(lookup.db_updated, UTC).isoformat(timespec="seconds")
    return {
        "schema": INVENTORY_SCHEMA,
        "version": INVENTORY_VERSION,
        "generated_from": list(inventory.sources),
        "unplaced_captures": inventory.unplaced,
        "vulndb_date": updated,
        "entries": inventory_entries(records, inventory, lookup),
    }


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _flat(entry: dict, field: str) -> str:
    if field == "max_severity":
        found = [f["severity"] for f in entry["findings"] if f["severity"]
                 and not f["undecided"]]
        return max(found, key=lambda s: _SEVERITY_ORDER.get(s, 0), default="")
    if field == "finding_ids":
        return " ".join(f["id"] for f in entry["findings"] if not f["undecided"])
    value = entry[field]
    if field == "support":
        return value["status"] if value else ""
    if field == "findings":
        return str(sum(1 for f in value if not f["undecided"])) if entry["support"] else ""
    if field == "observations":
        return "; ".join(f"{o['source']}={o['version'] or ''}" for o in value)
    if isinstance(value, list):
        return " ".join(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return "" if value is None else str(value)


def render_inventory(records: Iterable[Record], inventory: inv_mod.Inventory,
                     fmt: str, lookup=None) -> str:
    """The inventory as a versioned JSON document, a CSV table, or text lines."""
    document = inventory_document(records, inventory, lookup)
    if fmt == "json":
        return json.dumps(document, indent=2)
    table = [tuple(_flat(e, f) for f in INVENTORY_CSV_FIELDS) for e in document["entries"]]
    if fmt == "text":
        picked = [INVENTORY_CSV_FIELDS.index(f) for f in
                  ("address", "port", "protocol", "product", "version", "cpe23", "support",
                   "finding_ids")]
        return "\n".join(" ".join(row[i] for i in picked if row[i]) for row in table)
    return _write(table, INVENTORY_CSV_FIELDS, fmt)


def produce(records: Iterable[Record], which: str, fmt: str = "text",
            fields: Iterable[str] = (),
            inventory: inv_mod.Inventory | None = None, lookup=None) -> tuple[str, str]:
    """An export as text, and the format actually used - for every front end.

    `which` is a key of `EXPORTS`, or `custom` with `fields`. The port list is
    one comma-separated line whatever format is asked for, so that recipe
    reports `text` back rather than pretending to honour the choice.
    """
    records = list(records)
    if which == "custom":
        return render(records, fields, fmt), fmt
    if which == "inventory":
        if inventory is None:
            raise ValueError("the inventory export needs the inventory")
        return render_inventory(records, inventory, fmt, lookup), fmt
    _label, recipe, column = EXPORTS[which]
    items = recipe(records)
    if column is None:
        fmt = "text"
    return render_items(items, column or "ports", fmt), fmt
