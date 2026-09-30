"""What the web interface reads, and the indexes every route needs.

The interface is a second consumer of the viewer's model, not a second loader:
`ModelSource` is the whole of what it asks of the viewer, and nothing in
`seek.web` imports Textual or the app. A future standalone server - or a test -
implements the same one method.

`WebModel` is built from an immutable `ScanSet` and a copy of the capture list,
so a request can walk it on the server's thread while the viewer carries on.
It is cached by `CachedSource` on the identity of the `ScanSet` and the
capture generation: rebuilt when the viewer publishes a new model or reads a
new database, never per request.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from seek.gowitness.results import Capture, Captures, canonical_url
from seek.nmap import bulk
from seek.nmap.export import service_urls
from seek.nmap.models import Host, ScanSet, Service
from seek.tui.nmap import views as vdefs

# (address, protocol, port) - how a service on one host is addressed.
ServiceKey = tuple[str, str, int]


class ModelSource(Protocol):
    def snapshot(self) -> WebModel: ...


def capture_id(capture: Capture) -> str:
    """A capture's id in the interface: stable while the model is, not a path.

    gowitness's own `row_id` is per database, so two databases both have a 1;
    and a path in a URL is exactly what the screenshot route must never take.
    """
    raw = f"{capture.database or ''}\0{capture.url}\0{capture.probed_at}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


@dataclass(slots=True)
class Placed:
    """A capture, and the host and service it shows - when one does."""

    id: str
    capture: Capture
    host: Host | None = None
    service: Service | None = None


@dataclass
class WebModel:
    scans: ScanSet
    captures: list[Placed] = field(default_factory=list)
    hosts: dict[str, Host] = field(default_factory=dict)
    by_id: dict[str, Placed] = field(default_factory=dict)
    by_service: dict[ServiceKey, list[Placed]] = field(default_factory=dict)
    # One view object per list, so the TUI's row cache (keyed on the ScanSet)
    # is paid once per model here too.
    views: dict[str, vdefs.View] = field(default_factory=dict)

    @classmethod
    def build(cls, scans: ScanSet, captures: list[Capture]) -> WebModel:
        model = cls(scans=scans, hosts={h.address: h for h in scans.hosts})
        # Which service each URL belongs to, by the same matching the TUI's
        # record uses - the address and every name the host is known by.
        owner: dict[str, tuple[Host, Service]] = {}
        for host in scans.hosts:
            for svc in host.services:
                for url in service_urls(svc, host):
                    owner.setdefault(canonical_url(url), (host, svc))
        for capture in captures:
            host, svc = owner.get(canonical_url(capture.url), (None, None))
            placed = Placed(capture_id(capture), capture, host, svc)
            model.captures.append(placed)
            model.by_id[placed.id] = placed
            if host is not None and svc is not None:
                key = (host.address, svc.protocol, svc.port)
                model.by_service.setdefault(key, []).append(placed)
        model.views = {"hosts": vdefs.hosts_view(), "services": vdefs.services_view()}
        return model

    def captures_of(self, host: Host, svc: Service) -> list[Placed]:
        return self.by_service.get((host.address, svc.protocol, svc.port), [])

    def captures_of_host(self, host: Host) -> list[Placed]:
        return [p for svc in host.services for p in self.captures_of(host, svc)]

    def rows(self, name: str) -> list[vdefs.Row]:
        return self.views[name].rows(self.scans)


class CachedSource:
    """A `ModelSource` over a live viewer: two getters, one cached snapshot.

    `scans` is read as a reference - the viewer replaces its `ScanSet`, it never
    mutates a published one - and `captures` is copied under its own lock.
    """

    def __init__(self, scans: Callable[[], ScanSet], captures: Callable[[], Captures]) -> None:
        self._scans = scans
        self._captures = captures
        self._lock = threading.Lock()
        self._key: tuple[int, int] | None = None
        self._model: WebModel | None = None

    def snapshot(self) -> WebModel:
        scans, shots = self._scans(), self._captures()
        key = (id(scans), shots.generation)
        with self._lock:
            if self._model is None or self._key != key or self._model.scans is not scans:
                # Seconds at engagement scale, on the server's thread but
                # holding the interpreter the viewer also needs - so it hands
                # it back often, as the viewer's own background phases do.
                with bulk.responsive():
                    self._model = WebModel.build(scans, shots.all())
                self._key = key
            return self._model
