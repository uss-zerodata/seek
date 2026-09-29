"""Running the interface: loopback only, one server per session, on its loop.

The server is a task on the event loop that owns the session - the viewer's,
or `seek nmap serve`'s - because the runners are asyncio and must stay on one
loop: an endpoint that starts a scan is an `async def` calling the session
directly, with no thread hand-off and no lock around the marks. Rendering is
kept off the loop: every endpoint that reads the model is a plain `def`, which
FastAPI runs in its threadpool.

uvicorn installs SIGINT handlers when it serves on the main thread, which is
where Textual runs - `_Server` switches that off; `serve` handles SIGINT
itself. FastAPI and uvicorn are imported on the first `start()` only, in a
thread, so `seek` and `seek nmap` never pay for them and the viewer does not
freeze while they load. uvicorn logs to stderr by default, which would draw
over the terminal the viewer owns; its loggers are silenced before it starts.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import logging
import socket
import time
from urllib.parse import quote, urlencode

from seek.web.source import ModelSource, WebModel

_STARTUP_TIMEOUT = 5.0


class WebError(RuntimeError):
    """The interface could not be started; the message says why and what to do."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _probe(host: str, port: int) -> None:
    """Fail now, with a message, rather than from inside a dying thread."""
    if port == 0:
        return
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                raise WebError(f"port {port} is in use - set web_port in the "
                               f"config to use another") from None
            raise WebError(f"cannot listen on {host}:{port}: "
                           f"{exc.strerror or exc}") from None


def _quiet() -> None:
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi"):
        log = logging.getLogger(name)
        log.handlers = [logging.NullHandler()]
        log.propagate = False


def _load_stack():
    """Import the server stack - a few hundred milliseconds, done once."""
    import uvicorn

    from seek.web.app import create_app

    class _Server(uvicorn.Server):
        @contextlib.contextmanager
        def capture_signals(self):              # the host program owns SIGINT
            yield

    return uvicorn, create_app, _Server


class WebServer:
    def __init__(self, source: ModelSource, host: str = "127.0.0.1", port: int = 7272,
                 session=None) -> None:
        self.source = source
        self.session = session
        self.host = host
        self.port = port
        self._server = None
        self._task: asyncio.Task | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    async def start(self) -> None:
        """Serve on the running loop; return once it is listening."""
        if self.running:
            return
        if not is_loopback(self.host):
            raise WebError(f"the web interface binds to loopback only, not "
                           f"{self.host} - set web_host to 127.0.0.1")
        _probe(self.host, self.port)
        uvicorn, create_app, server_cls = await asyncio.to_thread(_load_stack)
        _quiet()
        config = uvicorn.Config(create_app(self.source, self.session, self.origin),
                                host=self.host, port=self.port, log_config=None,
                                log_level="critical", access_log=False, lifespan="off")
        server = server_cls(config)
        task = asyncio.get_running_loop().create_task(server.serve())
        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while not server.started:
            if task.done() or time.monotonic() > deadline:
                server.should_exit = True
                raise WebError(f"the web interface did not start on {self.url}")
            await asyncio.sleep(0.02)
        if self.port == 0:
            # Tests ask for any free port; report the one the kernel gave.
            with contextlib.suppress(Exception):
                self.port = server.servers[0].sockets[0].getsockname()[1]
        self._server, self._task = server, task

    def origin(self) -> str:
        """What a request from the interface's own pages carries as `Origin`."""
        return self.url

    def stop(self) -> None:
        """Ask the server to stop; it finishes on the loop by itself."""
        if self._server is not None:
            self._server.should_exit = True

    async def aclose(self, timeout: float = 3.0) -> None:
        task = self._task
        self.stop()
        self._server = self._task = None
        if task is not None:
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(task, timeout)

    def url_for(self, row, gallery: bool = False) -> str:
        """The page for what a viewer row stands for; the gallery otherwise.

        `gallery` asks for the screenshots of the row instead - every capture
        of it side by side, which is what `i` offers when there are several.
        """
        if gallery:
            return self.url + gallery_path_for(row)
        return self.url + path_for(row, self.source.snapshot())


def path_for(row, model: WebModel) -> str:
    """Host → its page, service group → that service, one capture → its page.

    A row of one host's port list is a service *on that host*, so it opens the
    host's page at that port - or the capture, when exactly one was taken of it.
    """
    from seek.nmap.models import Host, Service
    from seek.nmap.views import ServiceGroup

    if row is None:
        return "/"
    target = row.target
    if isinstance(target, Host):
        return f"/hosts/{quote(target.address)}"
    if isinstance(target, ServiceGroup):
        query = urlencode({"name": target.name or "", "product": target.product or "",
                           "version": target.version or ""})
        return f"/services/{target.protocol}/{target.port}?{query}"
    shots = [p for record in row.records if record.service is not None
             for p in model.captures_of(record.host, record.service)]
    if len({p.id for p in shots}) == 1:
        return f"/captures/{shots[0].id}"
    if isinstance(target, Service) and row.host is not None:
        return (f"/hosts/{quote(row.host.address)}"
                f"#port-{target.protocol}-{target.port}")
    return "/"


def gallery_path_for(row) -> str:
    """The gallery narrowed to what a row stands for.

    One service on one host, one port across hosts, or one host - whichever the
    row's records have in common. Structured parameters rather than a filter
    string, so the narrowing is exact and the filter box stays the user's.
    """
    if row is None:
        return "/"
    services = [r for r in row.records if r.service is not None]
    addresses = {r.host.address for r in row.records}
    ports = {(r.service.protocol, r.service.port) for r in services}
    query: dict[str, object] = {}
    if len(addresses) == 1:
        query["address"] = next(iter(addresses))
    if services and len(ports) == 1:
        protocol, port = next(iter(ports))
        query.update(protocol=protocol, port=port)
    return "/?" + urlencode(query) if query else "/"
