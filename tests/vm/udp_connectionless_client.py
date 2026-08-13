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

sock.close()
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
sock.settimeout(5)
target = ("::1", 18083)
sock.sendto(b"ipv6-single-peer", target)
response, source = sock.recvfrom(65535)
if response != b"udp-v6:ipv6-single-peer":
    raise RuntimeError(f"unexpected IPv6 response: {response!r}")
if source[:2] != target:
    raise RuntimeError(f"IPv6 source identity changed: {target!r} -> {source!r}")

try:
    sock.sendto(b"must-fail", ("::1", 18085))
except PermissionError:
    pass
else:
    raise RuntimeError("ambiguous IPv6 multi-target send unexpectedly succeeded")

print("udp-connectionless-ok")
