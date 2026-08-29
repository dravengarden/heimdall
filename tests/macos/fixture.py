#!/usr/bin/env python3
import argparse
import http.server
import json
import select
import signal
import socket
import socketserver
import struct
import threading
from pathlib import Path


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


class HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"heimdall-macos-explicit-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        version, method_count = struct.unpack("!BB", read_exact(self.request, 2))
        if version != 5:
            return
        methods = read_exact(self.request, method_count)
        if 0 not in methods:
            self.request.sendall(b"\x05\xff")
            return
        self.request.sendall(b"\x05\x00")

        version, command, reserved, atyp = struct.unpack(
            "!BBBB", read_exact(self.request, 4)
        )
        if version != 5 or command != 1 or reserved != 0:
            return
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, read_exact(self.request, 4))
        elif atyp == 3:
            host = read_exact(self.request, read_exact(self.request, 1)[0]).decode(
                "ascii"
            )
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(self.request, 16))
        else:
            return
        port = struct.unpack("!H", read_exact(self.request, 2))[0]
        with self.server.log_lock:
            with self.server.log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps({"host": host, "port": port}) + "\n")

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


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    args.ready.parent.mkdir(parents=True, exist_ok=True)

    http = ThreadingServer(("127.0.0.1", 0), HttpHandler)
    socks = ThreadingServer(("127.0.0.1", 0), SocksHandler)
    socks.log_path = args.log
    socks.log_lock = threading.Lock()
    threads = [
        threading.Thread(target=http.serve_forever, daemon=True),
        threading.Thread(target=socks.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()

    args.ready.write_text(
        json.dumps(
            {
                "http_port": http.server_address[1],
                "socks_port": socks.server_address[1],
            }
        ),
        encoding="utf-8",
    )

    stopped = threading.Event()

    def stop(_signum, _frame):
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    stopped.wait()
    socks.shutdown()
    http.shutdown()


if __name__ == "__main__":
    main()
