#!/usr/bin/env python3
import errno
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


def bind_shared_source_port():
    # The IPv4 ephemeral allocator cannot see an IPv6 TIME_WAIT entry from an
    # earlier iteration. Retry until the selected number is free in both
    # families so allocator state cannot make this correlation test flaky.
    for _ in range(256):
        ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ipv4.bind(("127.0.0.1", 0))
        source_port = ipv4.getsockname()[1]
        ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            ipv6.bind(("::1", source_port))
        except OSError as error:
            ipv4.close()
            ipv6.close()
            if error.errno == errno.EADDRINUSE:
                continue
            raise
        return ipv4, ipv6
    raise RuntimeError("could not allocate one source port across both families")


for iteration in range(100):
    ipv4, ipv6 = bind_shared_source_port()
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
