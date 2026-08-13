#!/usr/bin/env python3
import socket
import threading


def serve(family, address, prefix):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind(address)
    while True:
        payload, peer = sock.recvfrom(65535)
        sock.sendto(prefix + payload, peer)


threads = [
    threading.Thread(
        target=serve,
        args=(socket.AF_INET, ("127.0.0.1", 18082), b"udp-v4:"),
    ),
    threading.Thread(
        target=serve,
        args=(socket.AF_INET6, ("::1", 18083), b"udp-v6:"),
    ),
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
