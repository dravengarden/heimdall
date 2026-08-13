#!/usr/bin/env python3
import socket
import threading


def exchange(sock, target, payload, expected, barrier, errors):
    try:
        sock.connect(target)
        barrier.wait()
        sock.send(payload)
        response = sock.recv(65535)
        if response != expected:
            errors.append(f"{target}: {response!r}")
        if sock.getpeername() != target:
            errors.append(f"peer identity changed: {target!r} -> {sock.getpeername()!r}")
    except Exception as error:
        errors.append(repr(error))
    finally:
        sock.close()


local = "127.0.0.1"
sockets = []
count = 32
for _ in range(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind((local, 39002))
    sock.settimeout(5)
    sockets.append(sock)

barrier = threading.Barrier(2)
errors = []
cases = [
    (
        ("127.0.0.1", 18100 + index),
        f"payload-{index}".encode(),
        f"udp-stress:{18100 + index}:payload-{index}".encode(),
    )
    for index in range(count)
]
threads = [
    threading.Thread(
        target=exchange,
        args=(sockets[index], target, payload, expected, barrier, errors),
    )
    for index, (target, payload, expected) in enumerate(cases)
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
if errors:
    raise RuntimeError(errors)

print("udp-shared-port-ok")
