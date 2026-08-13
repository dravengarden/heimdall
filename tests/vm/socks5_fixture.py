#!/usr/bin/env python3
import json
import select
import socket
import socketserver
import struct


LOG_PATH = "/run/heimdall-test/socks.log"


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        version, methods = struct.unpack("!BB", read_exact(self.request, 2))
        if version != 5:
            return
        read_exact(self.request, methods)
        self.request.sendall(b"\x05\x00")

        version, command, reserved, atyp = struct.unpack(
            "!BBBB", read_exact(self.request, 4)
        )
        if (version, command, reserved) != (5, 1, 0):
            return
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, read_exact(self.request, 4))
        elif atyp == 3:
            host = read_exact(self.request, read_exact(self.request, 1)[0]).decode("ascii")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(self.request, 16))
        else:
            return
        port = struct.unpack("!H", read_exact(self.request, 2))[0]
        with open(LOG_PATH, "a", encoding="utf-8") as log:
            log.write(json.dumps({"atyp": atyp, "host": host, "port": port}) + "\n")

        connect_host = "127.0.0.1" if host == "fixture.test" else host
        try:
            upstream = socket.create_connection((connect_host, port), timeout=5)
        except OSError:
            self.request.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        with upstream:
            self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            sockets = [self.request, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], 10)
                if not readable:
                    return
                for source in readable:
                    payload = source.recv(65536)
                    if not payload:
                        return
                    target = upstream if source is self.request else self.request
                    target.sendall(payload)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("127.0.0.1", 1080), Handler).serve_forever()
