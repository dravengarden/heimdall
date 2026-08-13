#!/usr/bin/env python3
import socket
import threading


def request(sock, address, expected, barrier, errors):
    try:
        barrier.wait()
        sock.connect(address)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n")
        response = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        if expected not in response:
            errors.append(f"missing {expected!r} in {bytes(response)!r}")
    except Exception as error:
        errors.append(repr(error))
    finally:
        sock.close()


for iteration in range(100):
    ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipv4.bind(("127.0.0.1", 0))
    source_port = ipv4.getsockname()[1]
    ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    ipv6.bind(("::1", source_port))
    barrier = threading.Barrier(2)
    errors = []
    threads = [
        threading.Thread(
            target=request,
            args=(ipv4, ("127.0.0.1", 18080), b"fixture-v4", barrier, errors),
        ),
        threading.Thread(
            target=request,
            args=(ipv6, ("::1", 18081), b"fixture-v6", barrier, errors),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise RuntimeError(f"iteration {iteration}: {errors}")

print("dual-stack correlation ok")
