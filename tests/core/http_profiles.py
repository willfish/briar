#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check native redirect policy using loopback inside an isolated network namespace."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
assert {name for _, name in socket.if_nameindex()} == {"lo"}
for family in ("-4", "-6"):
    assert not subprocess.check_output(["ip", family, "route", "show", "default"]).strip()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.append(self.path)
        assert self.headers["Content-Length"] is None
        assert self.headers["User-Agent"] == "TruffleHog native-http-fixture"
        if self.path == "/destination":
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
    ("PUBLIC", "/redirect", []),
    ("SANE-POST", "/post", ["/post"]),
    ("LOCAL-POST", "/post", ["/post"]),
    ("SANE-POST-empty", "/post-empty", ["/post-empty"]),
    ("SANE-POST-type", "/post-typed", ["/post-typed"]),
    ("SANE-POST-redirect", "/redirect", ["/redirect"]),
    ("SANE-length-GET", "/destination", ["/destination"]),
    ("SANE-length-POST", "/post", ["/post"]),
):
    with HTTPServer(("127.0.0.1", 0), Handler) as server, tempfile.TemporaryDirectory(prefix="briar-http-home-") as home:
        server.paths = []
        url = f"http://127.0.0.1:{server.server_port}{path}"
        env = {"HOME": home, "PATH": os.environ["PATH"], "LANG": "C.UTF-8", "BRIAR_TEST_ISOLATED_NET": "1"}
        env.update({name: "" for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")})
        env.update(no_proxy="*", NO_PROXY="*")
        with ThreadPoolExecutor(max_workers=1) as pool:
            serving = pool.submit(server.serve_forever, poll_interval=0.01)
            try:
                result = subprocess.run([binary, profile, url], env=env, capture_output=True, text=True, timeout=15)
            finally:
                server.shutdown()
            serving.result(timeout=5)
        print(result.stdout, end="", flush=True)
        assert result.returncode == 0, result.stderr
        assert server.paths == expected_paths, (profile, server.paths)
print("PASS: LOCAL/SANE redirects, owned singleflight curl path, binary/empty bodies and body-derived framing; PUBLIC, keyed native redirects and unported POST redirects fail closed; loopback-only namespace")
