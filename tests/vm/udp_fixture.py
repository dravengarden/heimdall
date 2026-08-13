#!/usr/bin/env python3
import socket
import selectors
import threading


def serve(family, address, prefix):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind(address)
    while True:
        payload, peer = sock.recvfrom(65535)
        if payload == b"multi":
            sock.sendto(prefix + b"multi-1", peer)
            sock.sendto(prefix + b"multi-2", peer)
        else:
            sock.sendto(prefix + payload, peer)


def serve_range(first_port, count):
    selector = selectors.DefaultSelector()
    for port in range(first_port, first_port + count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        selector.register(sock, selectors.EVENT_READ, port)
    while True:
        for key, _ in selector.select():
            payload, peer = key.fileobj.recvfrom(65535)
            key.fileobj.sendto(
                f"udp-stress:{key.data}:".encode() + payload,
                peer,
            )


threads = [
    threading.Thread(
        target=serve,
        args=(socket.AF_INET, ("127.0.0.1", 18082), b"udp-v4:"),
    ),
    threading.Thread(
        target=serve,
        args=(socket.AF_INET6, ("::1", 18083), b"udp-v6:"),
    ),
    threading.Thread(
        target=serve,
        args=(socket.AF_INET6, ("::1", 18085), b"udp-v6-alt:"),
    ),
    threading.Thread(
        target=serve,
        args=(socket.AF_INET, ("127.0.0.1", 18084), b"udp-v4-alt:"),
    ),
    threading.Thread(target=serve_range, args=(18100, 128)),
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
