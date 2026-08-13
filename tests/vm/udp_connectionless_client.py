#!/usr/bin/env python3
import socket


family = socket.AF_INET
targets = (
    (("127.0.0.1", 18082), b"udp-v4:first", b"first"),
    (("127.0.0.1", 18084), b"udp-v4-alt:second", b"second"),
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
for target, expected, payload in targets:
    sock.sendto(payload, target)
    response, source = sock.recvfrom(65535)
    if response != expected:
        raise RuntimeError(f"unexpected response: {response!r}")
    if source[:2] != target:
        raise RuntimeError(f"source identity changed: {target!r} -> {source!r}")

print("udp-connectionless-ok")
