#!/usr/bin/env python3
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHUNK = b"0123456789abcdef" * 4096
MAX_STREAM_BYTES = 32 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/bytes/"):
            try:
                body_size = int(self.path.removeprefix("/bytes/"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= body_size <= MAX_STREAM_BYTES:
                self.send_error(413)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(body_size))
            self.end_headers()
            remaining = body_size
            while remaining:
                payload = CHUNK[:remaining]
                self.wfile.write(payload)
                remaining -= len(payload)
            return

        body = self.server.body.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class TLSServer(ThreadingHTTPServer):
    def shutdown_request(self, request):
        try:
            raw_socket = request.unwrap()
        except (OSError, ssl.SSLError):
            self.close_request(request)
            return
        try:
            raw_socket.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        raw_socket.close()


def serve(server_type, address, body, tls_context=None):
    server = server_type(address, Handler)
    server.body = body
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) == 3:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(sys.argv[1], sys.argv[2])
        serve(TLSServer, ("127.0.0.1", 18444), "fixture-tls", context)
        raise SystemExit

    threads = [
        threading.Thread(
            target=serve,
            args=(ThreadingHTTPServer, ("127.0.0.1", 18080), "fixture-v4"),
        ),
        threading.Thread(
            target=serve,
            args=(ThreadingHTTPServer, ("192.0.2.1", 18080), "fixture-v4"),
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
