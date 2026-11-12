#!/usr/bin/env python3
"""
Deliberately-vulnerable test target (localhost only).

This is a self-contained, dependency-free HTTP server that intentionally
exposes a controlled set of real vulnerabilities so the scanner's detection
modules can be exercised end-to-end in CI — proving they fire on true
positives and stay quiet on a clean baseline.

It binds to 127.0.0.1 only and must never be exposed to a network.

Vulnerabilities exposed:
  * Reflected XSS            GET /search?q=        (raw reflection into HTML)
  * Error-based SQL injection GET /item?id=        (leaks a MySQL error on quote)
  * Open redirect            GET /go?url=          (302 to attacker-controlled URL)
  * Missing security headers  every response       (no CSP/XFO/HSTS/nosniff)
  * Exposed VCS metadata      GET /.git/HEAD
  * Exposed secrets file      GET /.env
Clean/negative controls (must NOT produce findings):
  * Safe reflection          GET /safe?name=       (HTML-encoded, no XSS)
  * Parameter with no sink    GET /ping
"""
from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near '''' at line 1"
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "vulnapp/1.0"

    # No security headers on purpose (Server header only).
    def _send(self, code=200, body="", ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8", "replace") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query, keep_blank_values=True)

        if path == "/":
            self._send(body=(
                "<html><body><h1>vulnapp</h1>"
                "<a href='/search?q=test'>search</a> "
                "<a href='/item?id=1'>item</a> "
                "<a href='/go?url=/'>go</a></body></html>"))

        elif path == "/search":
            # Reflected XSS — value is echoed raw into the HTML body.
            val = q.get("q", [""])[0]
            self._send(body=f"<html><body>Results for: {val}</body></html>")

        elif path == "/safe":
            # Negative control — reflection is HTML-encoded, so NOT vulnerable.
            val = q.get("name", [""])[0]
            self._send(body=f"<html><body>Hello, {html.escape(val)}</body></html>")

        elif path == "/item":
            # Error-based SQLi — a single quote produces a DB error page.
            idv = q.get("id", ["1"])[0]
            if "'" in idv or '"' in idv:
                self._send(code=500, body=f"<html><body>{_MYSQL_ERROR}</body></html>")
            else:
                self._send(body=f"<html><body>Item #{html.escape(idv)}: Widget</body></html>")

        elif path == "/go":
            # Open redirect — Location is taken straight from user input.
            dest = q.get("url", ["/"])[0]
            self._send(code=302, body="", extra={"Location": dest})

        elif path == "/ping":
            self._send(body="<html><body>pong</body></html>")

        elif path == "/.git/HEAD":
            self._send(body="ref: refs/heads/main\n", ctype="text/plain")

        elif path == "/.env":
            self._send(body="DB_PASSWORD=super_secret_123\nAWS_SECRET_ACCESS_KEY=AKIA_test\n",
                       ctype="text/plain")

        else:
            self._send(code=404, body="<html><body>404</body></html>")

    do_HEAD = do_GET

    def log_message(self, *_a):  # silence
        return


class VulnServer:
    """Context manager that runs the vulnerable app on an ephemeral local port."""

    def __init__(self, host="127.0.0.1", port=0):
        self._srv = ThreadingHTTPServer((host, port), _Handler)
        self.host, self.port = self._srv.server_address
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()


if __name__ == "__main__":
    with VulnServer(port=8000) as s:
        print(f"vulnapp running at {s.base_url}  (Ctrl-C to stop)")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nstopped")
