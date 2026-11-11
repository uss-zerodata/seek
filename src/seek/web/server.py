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
from collections.abc import Iterator
from urllib.parse import urlencode

from seek.web.source import ModelSource, WebModel

_STARTUP_TIMEOUT = 5.0
# How far past a busy configured port to look for a free one.
_PORT_ATTEMPTS = 100


class WebError(RuntimeError):
    """The interface could not be started; the message says why and what to do."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _bindable(host: str, port: int) -> bool:
    """Whether `port` is free; any failure other than "in use" is raised."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return False
            raise WebError(f"cannot listen on {host}:{port}: "
                           f"{exc.strerror or exc}") from None
    return True


def _probe(host: str, port: int) -> int:
    """The first free port from `port` upward - fail now, with a message,
    rather than from inside a dying thread."""
    if port == 0:
        return 0
    last = min(port + _PORT_ATTEMPTS - 1, 65535)
    for candidate in range(port, last + 1):
        if _bindable(host, candidate):
            return candidate
    raise WebError(f"ports {port}-{last} are all in use - set web_port in the "
                   f"config to use another")


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
        def capture_signals(self) -> Iterator[None]:              # the host program owns SIGINT
            yield

    return uvicorn, create_app, _Server


class WebServer:
    def __init__(self, source: ModelSource, host: str = "127.0.0.1", port: int = 7272,
                 session=None, on_stop=None, mode: str = "viewer") -> None:
        """`on_stop` is what the browser's Stop does - stop this interface in
        the viewer, end the process for `seek nmap serve` - and `mode` says
        which, so the page can say so before it is confirmed."""
        self.source = source
        self.session = session
        self.host = host
        self.port = port
        self.on_stop = on_stop
        self.mode = mode
        self._app = None
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
        self.port = _probe(self.host, self.port)
        uvicorn, create_app, server_cls = await asyncio.to_thread(_load_stack)
        _quiet()
        app = create_app(self.source, self.session)
        app.state.on_stop, app.state.mode = self.on_stop, self.mode
        # Two seconds for responses in flight. The event streams never end on
        # their own - `stop()` ends them - and with no limit uvicorn's graceful
        # shutdown would wait for them for ever.
        config = uvicorn.Config(app, host=self.host, port=self.port, log_config=None,
                                log_level="critical", access_log=False, lifespan="off",
                                timeout_graceful_shutdown=2)
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
        self._server, self._task, self._app = server, task, app

    def stop(self) -> None:
        """Ask the server to stop; it finishes on the loop by itself. Open pages
        are told first (`closing`), so they say "stopped", not "lost"."""
        if self._app is not None:
            self._app.state.closing.set()
        if self._server is not None:
            self._server.should_exit = True

    async def aclose(self, timeout: float = 3.0) -> None:
        """Stop and wait until the port is closed. `running` stays true until
        then: clearing the task first made a stopped-but-still-listening
        server read as gone to whoever asked in between."""
        task = self._task
        self.stop()
        if task is not None:
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(task, timeout)
        self._server = self._task = None

    def url_for(self, row, gallery: bool = False) -> str:
        """The page for what a viewer row stands for; the gallery otherwise.

        `gallery` asks for the screenshots of the row instead - every capture
        of it side by side, which is what `i` offers when there are several.
        """
        if gallery:
            return self.url + gallery_path_for(row)
        return self.url + path_for(row, self.source.snapshot())


def path_for(row, model: WebModel) -> str:
    """Host → its port list, service group → that service, a port with exactly
    one capture → the capture, a port otherwise → the port's record; the gallery
    for anything else. The same places every page links to (`web.links`)."""
    from seek.nmap.models import Host, Service
    from seek.nmap.views import ServiceGroup
    from seek.web import links

    if row is None:
        return "/"
    target = row.target
    if isinstance(target, Host):
        return links.host(target.address)
    if isinstance(target, ServiceGroup):
        return links.service(target)
    shots = [p for record in row.records if record.service is not None
             for p in model.captures_of(record.host, record.service)]
    if len({p.id for p in shots}) == 1:
        return links.capture(shots[0].id)
    if isinstance(target, Service) and row.host is not None:
        return links.port(row.host.address, target.protocol, target.port)
    return "/"


def gallery_path_for(row) -> str:
    """The gallery narrowed to what a row stands for.

    One service on one host, one port across hosts, or one host - whichever the
    row's records have in common. Structured parameters rather than a filter
    string, so the narrowing is exact and the filter box stays the user's.
    """
    if row is None:
        return "/gallery"
    services = [r for r in row.records if r.service is not None]
    addresses = {r.host.address for r in row.records}
    ports = {(r.service.protocol, r.service.port) for r in services}
    query: dict[str, object] = {}
    if len(addresses) == 1:
        query["address"] = next(iter(addresses))
    if services and len(ports) == 1:
        protocol, port = next(iter(ports))
        query.update(protocol=protocol, port=port)
    return "/gallery?" + urlencode(query) if query else "/gallery"
