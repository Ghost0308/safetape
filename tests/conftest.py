from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture(autouse=True)
def _no_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI runners set CI=true, which would put every test in lockdown."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SAFETAPE_LOCKDOWN", raising=False)


@dataclass
class Route:
    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    echo: bool = False
    """Answer with the request body wrapped in {"echo": ...} instead of ``body``."""


@dataclass
class Server:
    url: str
    routes: dict[str, Route]
    hits: list[str] = field(default_factory=list)
    request_headers: list[dict[str, str]] = field(default_factory=list)


@pytest.fixture
def server() -> Iterator[Server]:
    """A local HTTP server that answers each path with a canned response."""
    routes: dict[str, Route] = {}
    state = Server("", routes)

    class Handler(BaseHTTPRequestHandler):
        def _answer(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            received = self.rfile.read(length) if length else b""
            path = self.path.split("?", 1)[0]
            state.hits.append(path)
            state.request_headers.append(dict(self.headers.items()))
            route = routes.get(path, Route(b"not found", 404))
            body = b'{"echo": ' + received + b"}" if route.echo else route.body
            self.send_response(route.status)
            for name, value in route.headers.items():
                self.send_header(name, value)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _answer

        def log_message(self, format: str, *args: object) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    state.url = f"http://127.0.0.1:{httpd.server_port}"
    try:
        yield state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()
