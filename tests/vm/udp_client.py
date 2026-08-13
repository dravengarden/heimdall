#!/usr/bin/env python3
import socket
import sys


host, port, expected = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
family = socket.AF_INET6 if ":" in host else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.connect((host, port))
original_peer = sock.getpeername()
sock.send(b"probe")
response = sock.recv(65535)
if response != expected:
    raise RuntimeError(f"unexpected response: {response!r}")
if sock.getpeername() != original_peer:
    raise RuntimeError(f"peer identity changed: {original_peer!r} -> {sock.getpeername()!r}")
print(response.decode())
