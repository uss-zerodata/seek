"""The shapes the API returns and the pages render.

One set for both: a page is a template over the same object the API sends as
JSON, so the two cannot describe a host differently. Built from the model by
the `out_*` functions here and nowhere else.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

from seek.nmap import names as name_mod
from seek.nmap import vulns
from seek.nmap.models import Host, Service, Vulnerability
from seek.nmap.views import ServiceGroup
from seek.web.source import Placed, WebModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int


class CaptureSummary(BaseModel):
    id: str
    url: str
    final_url: str = ""
    redirected: bool = False
    status: int | None = None
    title: str = ""
    failed: bool = False
    failure: str = ""
    database: str = ""
    address: str | None = None
    protocol: str | None = None
    port: int | None = None
    image: str | None = None            # the media route, when there is a picture


class CaptureOut(CaptureSummary):
    reason: str = ""
    http_protocol: str = ""
    probed_at: str = ""
    content_length: int | None = None
    technologies: list[str] = []
    headers: list[tuple[str, str]] = []
    cookies: list[tuple[str, str]] = []
    console: list[tuple[str, str]] = []
    network: list[tuple[str, str]] = []
    tls: str = ""
    sans: list[str] = []


class VulnOut(BaseModel):
    id: str
    title: str | None = None
    state: str | None = None
    severity: str | None = None
    ids: list[str] = []
    refs: list[str] = []


class PortOut(BaseModel):
    protocol: str
    port: int
    state: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    vulnerabilities: list[VulnOut] = []
    captures: list[CaptureSummary] = []


class HostSummary(BaseModel):
    address: str
    names: list[str] = []
    os: str | None = None
    up: bool = False
    state: str | None = None
    open_ports: list[str] = []
    captures: int = 0


class HostOut(HostSummary):
    reason: str | None = None
    sources: list[str] = []
    ports: list[PortOut] = []
    vulnerabilities: list[VulnOut] = []


class ServiceSummary(BaseModel):
    protocol: str
    port: int
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    hosts: int = 0
    vulnerabilities: int = 0


class ServiceHost(BaseModel):
    address: str
    names: list[str] = []
    version: str | None = None
    extrainfo: str | None = None
    captures: list[CaptureSummary] = []


class ServiceOut(ServiceSummary):
    members: list[ServiceHost] = []


class ErrorOut(BaseModel):
    detail: str


# --- from the model -------------------------------------------------------------


def _names(host: Host) -> list[str]:
    return [name for name, _ in name_mod.host_names(host)]


def out_capture(placed: Placed, full: bool = False) -> CaptureSummary:
    c = placed.capture
    common = dict(
        id=placed.id, url=c.url, final_url=c.final_url, redirected=c.redirected,
        status=c.status, title=c.title, failed=c.failed, failure=c.failure,
        database=str(c.database or ""),
        address=placed.host.address if placed.host else None,
        protocol=placed.service.protocol if placed.service else None,
        port=placed.service.port if placed.service else None,
        image=f"/media/shot/{placed.id}" if c.shot is not None and not c.failed else None,
    )
    if not full:
        return CaptureSummary(**common)
    return CaptureOut(
        **common, reason=c.reason, http_protocol=c.protocol, probed_at=c.probed_at,
        content_length=c.content_length, technologies=c.technologies,
        headers=c.headers, cookies=c.cookies, console=c.console, network=c.network,
        tls=c.tls, sans=c.sans)


def out_vuln(v: Vulnerability) -> VulnOut:
    return VulnOut(id=v.id, title=v.title, state=v.state, severity=v.severity,
                   ids=v.ids, refs=v.refs)


def out_port(model: WebModel, host: Host, svc: Service) -> PortOut:
    return PortOut(
        protocol=svc.protocol, port=svc.port, state=svc.state, service=svc.name,
        product=svc.product, version=svc.version, extrainfo=svc.extrainfo,
        vulnerabilities=[out_vuln(v) for v in svc.vulnerabilities],
        captures=[out_capture(p) for p in model.captures_of(host, svc)])


def out_host_summary(model: WebModel, host: Host) -> HostSummary:
    return HostSummary(
        address=host.address, names=_names(host), os=host.os, up=host.up,
        state=host.state,
        open_ports=[f"{s.port}/{s.protocol}" for s in host.open_services],
        captures=len(model.captures_of_host(host)))


def out_host(model: WebModel, host: Host) -> HostOut:
    summary = out_host_summary(model, host)
    return HostOut(
        **summary.model_dump(), reason=host.reason, sources=host.sources,
        ports=[out_port(model, host, s) for s in host.services],
        vulnerabilities=[out_vuln(v) for v in vulns.host_vulnerabilities(host)])


def out_service_summary(group: ServiceGroup) -> ServiceSummary:
    return ServiceSummary(
        protocol=group.protocol, port=group.port, name=group.name,
        product=group.product, version=group.version, extrainfo=group.extrainfo,
        hosts=group.host_count, vulnerabilities=group.vulnerability_count)


def out_service(model: WebModel, group: ServiceGroup) -> ServiceOut:
    return ServiceOut(
        **out_service_summary(group).model_dump(),
        members=[ServiceHost(address=h.address, names=_names(h), version=s.version,
                             extrainfo=s.extrainfo,
                             captures=[out_capture(p) for p in model.captures_of(h, s)])
                 for h, s in group.members])
