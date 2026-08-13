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
        if version != 5 or reserved != 0:
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
        if command == 3:
            self.udp_associate()
            return
        if command != 1:
            return
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

    def udp_associate(self):
        udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        udp.bind(("::1", 0))
        relay_port = udp.getsockname()[1]
        self.request.sendall(
            b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1")
            + struct.pack("!H", relay_port)
        )
        client = None
        with udp:
            while True:
                readable, _, _ = select.select([self.request, udp], [], [], 10)
                if self.request in readable:
                    if not self.request.recv(1):
                        return
                if udp not in readable:
                    continue
                packet, sender = udp.recvfrom(65535)
                if client is None or sender == client:
                    client = sender
                    target, header, payload = parse_udp_frame(packet)
                    family = socket.AF_INET6 if ":" in target[0] else socket.AF_INET
                    with socket.socket(family, socket.SOCK_DGRAM) as upstream:
                        upstream.settimeout(5)
                        upstream.sendto(payload, target)
                        response, _ = upstream.recvfrom(65535)
                    udp.sendto(b"\x00\x00\x00" + header + response, client)


def parse_udp_frame(packet):
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise ValueError("invalid SOCKS5 UDP frame")
    atyp = packet[3]
    offset = 4
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, packet[offset : offset + 4])
        offset += 4
    elif atyp == 3:
        length = packet[offset]
        offset += 1
        host = packet[offset : offset + length].decode("ascii")
        offset += length
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, packet[offset : offset + 16])
        offset += 16
    else:
        raise ValueError("unknown SOCKS5 UDP ATYP")
    port = struct.unpack("!H", packet[offset : offset + 2])[0]
    offset += 2
    with open(LOG_PATH, "a", encoding="utf-8") as log:
        log.write(json.dumps({"udp": True, "atyp": atyp, "host": host, "port": port}) + "\n")
    connect_host = "127.0.0.1" if host == "fixture.test" else host
    return (connect_host, port), packet[3:offset], packet[offset:]


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("127.0.0.1", 1080), Handler).serve_forever()
