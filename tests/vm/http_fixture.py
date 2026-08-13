#!/usr/bin/env python3
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.body.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def serve(server_type, address, body):
    server = server_type(address, Handler)
    server.body = body
    server.serve_forever()


if __name__ == "__main__":
    threads = [
        threading.Thread(
            target=serve,
            args=(ThreadingHTTPServer, ("127.0.0.1", 18080), "fixture-v4"),
        ),
        threading.Thread(
            target=serve,
            args=(V6Server, ("::1", 18081), "fixture-v6"),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
