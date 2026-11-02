#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check native redirect policy using loopback inside an isolated network namespace."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import gzip
import os
from pathlib import Path
import socket
import select
import subprocess
import sys
import tempfile
import time
import traceback

binary = str(Path(sys.argv[1]).resolve())
assert {name for _, name in socket.if_nameindex()} == {"lo"}
for family in ("-4", "-6"):
    assert not subprocess.check_output(["ip", family, "route", "show", "default"]).strip()


class FixtureServer(HTTPServer):
    def handle_error(self, *_):
        self.errors.append(traceback.format_exc())


class Handler(BaseHTTPRequestHandler):
    def failure_response(self):
        path = self.path
        if path == '/malformed':
            self.wfile.write(b'not an HTTP response\r\n\r\n')
        elif path == '/incomplete':
            self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n')
        elif path in ('/timeout', '/body-timeout', '/cancel'):
            if path == '/body-timeout':
                self.send_response(200)
                self.send_header('Content-Length', '10')
                self.end_headers()
                self.wfile.write(b'r')
                self.wfile.flush()
            if path == '/cancel':
                os.write(self.server.ready_fd, b'r')
            self.connection.settimeout(5)
            assert self.connection.recv(1) == b'', 'client must close on timeout/cancellation'
        elif path == '/headers-limit':
            try:
                self.wfile.write(b'HTTP/1.1 200 OK\r\n' + (b'X-Large: ' + b'x' * 4096 + b'\r\n') * 17 + b'\r\n')
            except (BrokenPipeError, ConnectionResetError):
                pass  # The client deliberately stops reading at its header cap.
        elif path.startswith('/redirect/'):
            self.send_response(int(path.rsplit('/', 1)[1]))
            self.send_header('Location', '/destination')
            self.send_header('Content-Length', '0')
            self.end_headers()
        elif path in ('/loop', '/sensitive', '/scheme'):
            if path == '/sensitive':
                assert self.headers['Authorization'] == 'Bearer synthetic-only'
            self.send_response(302)
            self.send_header('Location', {'/loop': '/loop', '/sensitive': '/destination',
                                          '/scheme': 'file:///briar-must-not-open'}[path])
            self.send_header('Content-Length', '0')
            self.end_headers()
        elif path in ('/short', '/body-limit', '/gzip', '/gzip-ok', '/informational') or path.startswith('/status/'):
            body = b'r'
            if path == '/body-limit':
                body = b'x' * (8 * 1024 * 1024 + 1)
            elif path == '/gzip':
                body = b'not a gzip stream'
            elif path == '/gzip-ok':
                body = gzip.compress(b'decoded\x00body')
            elif path == '/informational':
                self.wfile.write(b'HTTP/1.1 100 Continue\r\nX-Old: discard\r\n\r\n')
            status = int(path.rsplit('/', 1)[1]) if path.startswith('/status/') else 200
            self.send_response(status)
            self.send_header('Content-Length', str(100 if path == '/short' else len(body)))
            if path in ('/gzip', '/gzip-ok'):
                self.send_header('Content-Encoding', 'gzip')
            if path == '/informational':
                self.send_header('X-Repeat', 'one')
                self.send_header('X-Repeat', 'two')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                assert path in ('/body-limit', '/gzip')
        else:
            return False
        return True

    def do_GET(self):
        self.server.paths.append(self.path)
        assert self.headers["Content-Length"] is None
        assert self.headers["User-Agent"] == "TruffleHog native-http-fixture"
        if self.failure_response():
            return
        if self.path == "/abandoned":
            # Detached native work must finish before runtime/curl destruction.
            ready, _, _ = select.select([self.server.cancel_fd], [], [], 5)
            assert ready and os.read(self.server.cancel_fd, 1) == b"c"
            time.sleep(0.1)
        if self.path in ("/destination", "/abandoned"):
            body, status = b"destination-body", 200
        else:
            assert self.path in ("/redirect", "/short-redirect")
            body, status = b"redirect-body", 302
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/destination")
        self.send_header("Content-Length", "9999" if self.path == "/short-redirect" else str(len(body)))
        self.end_headers()
        self.wfile.write(b"r" if self.path == "/short-redirect" else body)

    def do_POST(self):
        self.server.paths.append(self.path)
        assert self.headers["User-Agent"] == "TruffleHog native-http-fixture"
        assert self.path in ("/post", "/post-empty", "/post-typed", "/redirect")
        expected = b"" if self.path == "/post-empty" else b"synthetic\x00body"
        assert self.headers["Content-Length"] == str(len(expected))
        assert self.rfile.read(int(self.headers["Content-Length"])) == expected
        assert self.headers["Content-Type"] == ("application/json" if self.path == "/post-typed" else None)
        body = b"redirect-body" if self.path == "/redirect" else b"posted-body"
        self.send_response(302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "/destination")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


for profile, path, expected_paths in (
    ("LOCAL", "/redirect", ["/redirect"]),
    ("LOCAL-short", "/short-redirect", ["/short-redirect"]),
    ("SANE", "/redirect", ["/redirect", "/destination"]),
    ("SANE-owned", "/destination", ["/destination"]),
    ("SANE-owned-redirect", "/redirect", ["/redirect"]),
    ("runtime-success", "/destination", ["/destination"]),
    ("runtime-gitter", "/destination", ["/destination"]),
    ("runtime-redirect", "/redirect", ["/redirect"]),
    ("runtime-unknown", "/destination", []),
    ("runtime-cancel-drain", "/abandoned", ["/abandoned"]),
    ("PUBLIC", "/redirect", []),
    ("SANE-POST", "/post", ["/post"]),
    ("LOCAL-POST", "/post", ["/post"]),
    ("SANE-POST-empty", "/post-empty", ["/post-empty"]),
    ("SANE-POST-type", "/post-typed", ["/post-typed"]),
    ("SANE-POST-redirect", "/redirect", ["/redirect"]),
    ("SANE-length-GET", "/destination", ["/destination"]),
    ("SANE-length-POST", "/post", ["/post"]),
    *(("SANE", f"/redirect/{status}", [f"/redirect/{status}", "/destination"])
      for status in (301, 303, 307, 308)),
    ("failure-method", "/destination", []),
    ("failure-get-body", "/destination", []),
    ("failure-short", "/short", ["/short"]),
    ("failure-owned-short", "/short", ["/short"]),
    ("failure-malformed", "/malformed", ["/malformed"]),
    ("failure-incomplete", "/incomplete", ["/incomplete"]),
    ("failure-headers", "/headers-limit", ["/headers-limit"]),
    ("failure-body-limit", "/body-limit", ["/body-limit"]),
    ("failure-loop", "/loop", ["/loop"] * 10),
    ("failure-sensitive", "/sensitive", ["/sensitive"]),
    ("failure-scheme", "/scheme", ["/scheme"]),
    ("failure-timeout", "/timeout", ["/timeout"]),
    ("failure-body-timeout", "/body-timeout", ["/body-timeout"]),
    ("failure-cancel", "/cancel", ["/cancel"]),
    ("failure-gzip", "/gzip", ["/gzip"]),
    ("failure-gzip-ok", "/gzip-ok", ["/gzip-ok"]),
    ("failure-informational", "/informational", ["/informational"]),
    *((f"failure-status-{status}", f"/status/{status}", [f"/status/{status}"])
      for status in (401, 403, 429, 500)),
):
    cancel_read, cancel_write = os.pipe()
    ready_read, ready_write = os.pipe()
    os.set_blocking(ready_read, False)
    with (os.fdopen(cancel_read, "rb") as cancellation_read,
          os.fdopen(cancel_write, "wb") as cancellation_write,
          os.fdopen(ready_read, 'rb') as request_ready,
          os.fdopen(ready_write, 'wb') as request_notify,
          FixtureServer(("127.0.0.1", 0), Handler) as server,
          tempfile.TemporaryDirectory(prefix="briar-http-home-") as home):
        server.paths = []
        server.errors = []
        server.cancel_fd = cancellation_read.fileno()
        server.ready_fd = request_notify.fileno()
        url = f"http://127.0.0.1:{server.server_port}{path}"
        env = {"HOME": home, "PATH": os.environ["PATH"], "LANG": "C.UTF-8", "BRIAR_TEST_ISOLATED_NET": "1"}
        env.update({name: "" for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")})
        env.update(no_proxy="*", NO_PROXY="*", BRIAR_TEST_CANCEL_FD=str(cancellation_write.fileno()),
                   BRIAR_TEST_READY_FD=str(request_ready.fileno()))
        with ThreadPoolExecutor(max_workers=1) as pool:
            serving = pool.submit(server.serve_forever, poll_interval=0.01)
            try:
                result = subprocess.run([binary, profile, url], env=env, capture_output=True, text=True,
                                        pass_fds=(cancellation_write.fileno(), request_ready.fileno()), timeout=15)
            finally:
                server.shutdown()
            serving.result(timeout=5)
        print(result.stdout, end="", flush=True)
        assert result.returncode == 0, result.stderr
        assert server.paths == expected_paths, (profile, server.paths)
        assert not server.errors, server.errors

# Bind without listening so no other process can take the refused port.
with socket.socket() as refused, tempfile.TemporaryDirectory(prefix='briar-http-home-') as home:
    refused.bind(('127.0.0.1', 0))
    env = {'HOME': home, 'PATH': os.environ['PATH'], 'LANG': 'C.UTF-8',
           'BRIAR_TEST_ISOLATED_NET': '1', 'no_proxy': '*', 'NO_PROXY': '*'}
    result = subprocess.run([binary, 'failure-refused', f'http://127.0.0.1:{refused.getsockname()[1]}/'],
                            env=env, capture_output=True, text=True, timeout=10)
    print(result.stdout, end='', flush=True)
    assert result.returncode == 0, result.stderr
print('PASS: native HTTP profiles, routing, response/read failures, bounds, redirects, cancellation, deadlines and release; loopback-only namespace')
