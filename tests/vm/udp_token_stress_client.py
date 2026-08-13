#!/usr/bin/env python3
import socket


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
for cycle in range(2):
    for port in range(18100, 18228):
        payload = f"cycle-{cycle}-port-{port}".encode()
        target = ("127.0.0.1", port)
        sock.sendto(payload, target)
        response, source = sock.recvfrom(65535)
        expected = f"udp-stress:{port}:".encode() + payload
        if response != expected:
            raise RuntimeError(f"unexpected response from {target}: {response!r}")
        if source[:2] != target:
            raise RuntimeError(f"source identity changed: {target!r} -> {source!r}")

print("udp-token-stress-ok")
