#!/usr/bin/env python3
import socket


source = ("127.0.0.1", 39001)
cases = [
    (("127.0.0.1", 18082), b"first", b"udp-v4:first"),
    (("127.0.0.1", 18084), b"second", b"udp-v4-alt:second"),
]

for target, payload, expected in cases:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(5)
    sock.bind(source)
    sock.connect(target)
    sock.send(payload)
    response = sock.recv(65535)
    if response != expected:
        raise RuntimeError(f"unexpected response for {target}: {response!r}")
    sock.close()

print("udp-port-reuse-ok")
