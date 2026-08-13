#!/usr/bin/env python3
import socket


def reusable_socket():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.settimeout(5)
    return sock


first = reusable_socket()
first.bind(("::1", 39003))
second = reusable_socket()
try:
    second.bind(("::1", 39003))
except PermissionError:
    pass
else:
    raise RuntimeError("ambiguous IPv6 shared-port bind unexpectedly succeeded")
finally:
    second.close()

first.sendto(b"first-owner", ("::1", 18083))
response, source = first.recvfrom(65535)
if response != b"udp-v6:first-owner" or source[:2] != ("::1", 18083):
    raise RuntimeError(f"first owner exchange mismatch: {response!r} from {source!r}")
first.close()

replacement = reusable_socket()
replacement.bind(("::1", 39003))
replacement.sendto(b"replacement", ("::1", 18085))
response, source = replacement.recvfrom(65535)
if response != b"udp-v6-alt:replacement" or source[:2] != ("::1", 18085):
    raise RuntimeError(f"replacement exchange mismatch: {response!r} from {source!r}")

print("udp-ipv6-bind-guard-ok")
