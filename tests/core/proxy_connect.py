#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run only in a fresh user+network namespace with loopback enabled."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
assert {name for _, name in socket.if_nameindex()} == {"lo"}, "external interfaces must be absent"
for family in ("-4", "-6"):
    routes = subprocess.check_output(["ip", family, "route", "show", "default"])
    assert not routes.strip(), "external default routes must be absent"


def receive_exact(connection, length):
    data = b""
    while len(data) < length:
        part = connection.recv(length - len(data))
        assert part, "client closed before TLS ClientHello"
        data += part
    return data


def proxy_once(listener, host):
    # This is not a tunnel: it never resolves the host or opens an outbound socket.
    connection, address = listener.accept()
    with connection:
        assert address[0] == "127.0.0.1"
        connection.settimeout(5)
        request = b""
        while b"\r\n\r\n" not in request:
            part = connection.recv(4096)
            assert part, "client closed before CONNECT"
            request += part
            assert len(request) <= 16384
        assert request.startswith(f"CONNECT {host}:443 HTTP/1.1\r\n".encode())
        connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        record = receive_exact(connection, 5)
        assert record[:2] == b"\x16\x03", "TLS ClientHello expected after CONNECT"
        receive_exact(connection, int.from_bytes(record[3:5], "big"))
        # Fatal TLS handshake_failure alert, with no origin HTTP response.
        connection.sendall(b"\x15\x03\x03\x00\x02\x02\x28")


for detector_type, host in ((239, "api.abyssale.com"), (384, "exchange-rates.abstractapi.com")):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        proxy = f"http://127.0.0.1:{listener.getsockname()[1]}"
        env = {name: value for name, value in os.environ.items() if name.lower() not in (
            "https_proxy", "http_proxy", "all_proxy", "no_proxy",
        )}
        env.update(https_proxy=proxy, HTTPS_PROXY=proxy, no_proxy="", NO_PROXY="", BRIAR_TEST_ISOLATED_NET="1")
        with ThreadPoolExecutor(max_workers=1) as pool:
            server = pool.submit(proxy_once, listener, host)
            process = subprocess.run([binary, str(detector_type)], env=env, capture_output=True, text=True, timeout=10)
            server.result(timeout=5)
        print(process.stdout, end="", flush=True)
        assert process.returncode == 0, process.stderr
print("PASS: CONNECT 200 cannot verify either status-only detector after TLS failure; loopback-only namespace, no forwarding")
