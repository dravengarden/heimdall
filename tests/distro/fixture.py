#!/usr/bin/env python3
"""Loopback fixtures and machine-readable assertions for distro acceptance."""

from __future__ import annotations

import json
import pathlib
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
TCP_PORT = 18080
UDP_PORT = 18082
TLS_PORT = 18444
TCP_BODY = b"ubuntu-tcp-ok"
UDP_BODY = b"ubuntu-udp:probe"
TLS_BODY = b"ubuntu-tls-ok"
STREAM_CHUNK = b"0123456789abcdef" * 4096
MAX_STREAM_BYTES = 32 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
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
                payload = STREAM_CHUNK[:remaining]
                self.wfile.write(payload)
                remaining -= len(payload)
            return

        body = self.server.body
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class TLSServer(ThreadingHTTPServer):
    def shutdown_request(self, request: socket.socket) -> None:
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


def serve_udp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, UDP_PORT))
        while True:
            payload, peer = sock.recvfrom(65535)
            sock.sendto(b"ubuntu-udp:" + payload, peer)


def serve_http() -> None:
    server = ThreadingHTTPServer((HOST, TCP_PORT), Handler)
    server.body = TCP_BODY
    server.serve_forever()


def serve_tls(cert_path: str, key_path: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server = TLSServer((HOST, TLS_PORT), Handler)
    server.body = TLS_BODY
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def serve(cert_path: str, key_path: str) -> None:
    udp = threading.Thread(target=serve_udp, daemon=True)
    http = threading.Thread(target=serve_http, daemon=True)
    tls = threading.Thread(target=serve_tls, args=(cert_path, key_path), daemon=True)
    udp.start()
    http.start()
    tls.start()
    http.join()


def read_http_body(sock: socket.socket) -> bytes:
    response = bytearray()
    while chunk := sock.recv(65535):
        response.extend(chunk)
    headers, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator or not headers.startswith(b"HTTP/1.0 200"):
        raise RuntimeError(f"unexpected HTTP response: {bytes(response[:200])!r}")
    return body


def tcp_client(host: str = HOST, body_size: int | None = None) -> None:
    path = "/" if body_size is None else f"/bytes/{body_size}"
    with socket.create_connection((host, TCP_PORT), timeout=30) as sock:
        sock.sendall(
            f"GET {path} HTTP/1.1\r\n"
            "Host: fixture.test\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        body = read_http_body(sock)
    if body_size is not None:
        if len(body) != body_size:
            raise RuntimeError(
                f"unexpected TCP response length: {len(body)} != {body_size}"
            )
        print(len(body))
        return
    if body != TCP_BODY:
        raise RuntimeError(f"unexpected TCP response: {body!r}")
    print(body.decode())


def udp_client(host: str = HOST) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((host, UDP_PORT))
        original_peer = sock.getpeername()
        sock.sendall(b"probe")
        response = sock.recv(65535)
        if sock.getpeername() != original_peer:
            raise RuntimeError("UDP peer identity changed")
    if response != UDP_BODY:
        raise RuntimeError(f"unexpected UDP response: {response!r}")
    print(response.decode())


def tls_client(ca_path: str, body_size: int | None = None) -> None:
    path = "/" if body_size is None else f"/bytes/{body_size}"
    context = ssl.create_default_context(cafile=ca_path)
    with socket.create_connection(("fixture.test", TLS_PORT), timeout=30) as raw:
        sock = context.wrap_socket(raw, server_hostname="fixture.test")
        try:
            sock.sendall(
                f"GET {path} HTTP/1.1\r\n"
                "Host: fixture.test:18444\r\n"
                "Authorization: bearer fixture-value\r\n"
                "Connection: close\r\n\r\n".encode()
            )
            body = read_http_body(sock)
            # Why: SSLSocket.close() may close the transport without a TLS
            # close_notify. Relay acceptance needs a clean TLS lifecycle so a
            # genuine protocol error cannot be mistaken for successful flow
            # completion.
            plain = sock.unwrap()
            plain.close()
        finally:
            sock.close()
    if body_size is not None:
        if len(body) != body_size:
            raise RuntimeError(
                f"unexpected TLS response length: {len(body)} != {body_size}"
            )
        print(len(body))
        return
    if body != TLS_BODY:
        raise RuntimeError(f"unexpected TLS response: {body!r}")
    print(body.decode())


def read_document() -> dict[str, object]:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise RuntimeError("expected one JSON object")
    return value


def verify_config() -> None:
    value = read_document()
    if value.get("contract") != "heimdall.config.validate/v2" or not value.get("valid"):
        raise RuntimeError(f"configuration is not valid: {value!r}")


def verify_agent(mode: str) -> None:
    value = read_document()
    execution = value.get("execution")
    config = value.get("config")
    if not isinstance(execution, dict) or not isinstance(config, dict):
        raise RuntimeError("agent document is missing execution or config")
    capture = config.get("capture")
    decrypt = config.get("decrypt")
    if not isinstance(capture, dict) or not isinstance(decrypt, dict):
        raise RuntimeError("agent document is missing capture or decrypt")
    expected = (
        value.get("contract") == "heimdall.agent/v8"
        and value.get("ready") is True
        and execution.get("backend") == "linux-ebpf-foreground"
        and execution.get("owner") == "heimdall-run"
        and execution.get("daemon_required") is False
        and execution.get("web_ui_required") is False
        and capture.get("mode") == ("off" if mode == "off" else "on")
        and decrypt.get("mode") == mode
    )
    if not expected:
        raise RuntimeError(f"unexpected agent contract: {value!r}")


def latest_run() -> None:
    value = read_document()
    runs = value.get("runs")
    if value.get("contract") != "heimdall.logs.list/v1" or not isinstance(runs, list) or not runs:
        raise RuntimeError(f"no Heimdall run found: {value!r}")
    print(runs[0]["run_id"])


def latest_running_run() -> None:
    value = read_document()
    runs = value.get("runs")
    if not isinstance(runs, list):
        raise RuntimeError("logs list has no runs array")
    for run in runs:
        if run.get("state") == "running":
            print(run["run_id"])
            return
    raise RuntimeError("no running Heimdall run found")


def running_runs() -> None:
    value = read_document()
    runs = value.get("runs")
    if not isinstance(runs, list):
        raise RuntimeError("logs list has no runs array")
    for run in runs:
        if run.get("state") == "running":
            print(run["run_id"])


def list_runs() -> None:
    value = read_document()
    runs = value.get("runs")
    if not isinstance(runs, list):
        raise RuntimeError("logs list has no runs array")
    for run in runs:
        print(run["run_id"])


def verify_events(network: str, port: int) -> None:
    events = [json.loads(line) for line in sys.stdin if line.strip()]

    def matches(kind: str) -> bool:
        for event in events:
            data = event.get("data", {})
            destination = data.get("destination", {})
            action = data.get("action", {})
            if (
                event.get("kind") == kind
                and data.get("network") == network
                and destination.get("ip") == HOST
                and destination.get("port") == port
                and action.get("type") == "direct"
            ):
                return True
        return False

    if not matches("policy.decision") or not matches("flow.open"):
        raise RuntimeError(f"missing direct {network} interception evidence: {events!r}")
    if not any(
        event.get("kind") == "flow.close"
        and event.get("data", {}).get("network") == network
        and event.get("data", {}).get("status") == "complete"
        for event in events
    ):
        raise RuntimeError(f"missing completed {network} flow: {events!r}")
    if not events or events[-1].get("kind") != "run.close" or not events[-1]["data"]["complete"]:
        raise RuntimeError("run did not close completely")


def run_dir() -> None:
    value = read_document()
    path = value.get("run_dir")
    if not isinstance(path, str) or not path:
        raise RuntimeError(f"logs path has no run directory: {value!r}")
    print(path)


def verify_log(expected_state: str) -> None:
    value = read_document()
    if not (
        value.get("contract") == "heimdall.logs.verify/v1"
        and value.get("valid") is True
        and (
            value.get("state") == expected_state
            if expected_state != "closed-or-failed"
            else value.get("state") in {"closed", "failed"}
        )
    ):
        raise RuntimeError(f"invalid run evidence: {value!r}")


def read_events() -> list[dict[str, object]]:
    return [json.loads(line) for line in sys.stdin if line.strip()]


def verify_close(exit_code: int, signal: int) -> None:
    events = read_events()
    if not events:
        raise RuntimeError("run has no events")
    final = events[-1]
    data = final.get("data", {})
    if not (
        final.get("kind") == "run.close"
        and data.get("exit_code") == exit_code
        and data.get("signal") == signal
        and data.get("complete") is True
    ):
        raise RuntimeError(f"unexpected signal close evidence: {final!r}")


def verify_recovery_preview() -> None:
    value = read_document()
    if not (
        value.get("contract") == "heimdall.logs.recover/v1"
        and value.get("applicable") is True
        and value.get("applied") is False
        and value.get("code") == "recovery_available"
        and value.get("projected_state") == "failed"
    ):
        raise RuntimeError(f"unexpected recovery preview: {value!r}")


def verify_recovery_apply() -> None:
    value = read_document()
    if not (
        value.get("contract") == "heimdall.logs.recover/v1"
        and value.get("applied") is True
        and value.get("state_after") == "failed"
    ):
        raise RuntimeError(f"unexpected recovery result: {value!r}")


def verify_ca() -> None:
    value = read_document()
    fingerprint = value.get("ca_cert_sha256")
    if not (
        value.get("contract") == "heimdall.tls-ca/v2"
        and isinstance(fingerprint, str)
        and len(fingerprint) == 64
        and all(character in "0123456789abcdef" for character in fingerprint)
    ):
        raise RuntimeError(f"unexpected relay CA result: {value!r}")


def load_run_events(path: pathlib.Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for segment in sorted(path.glob("events-*.jsonl")):
        with segment.open(encoding="utf-8") as source:
            events.extend(json.loads(line) for line in source if line.strip())
    return events


def verify_tls(mode: str, path: pathlib.Path) -> None:
    boundary = f"tls_plaintext.{mode}"
    events = load_run_events(path)
    data_events = [
        event
        for event in events
        if event.get("kind") == "flow.data"
        and event.get("data", {}).get("boundary") == boundary
    ]
    if not data_events:
        raise RuntimeError(f"run has no {boundary} payload evidence")

    plaintext = bytearray()
    for event in data_events:
        blob = event.get("data", {}).get("blob")
        if isinstance(blob, dict) and isinstance(blob.get("path"), str):
            plaintext.extend((path / blob["path"]).read_bytes())
    if b"GET / HTTP" not in plaintext:
        raise RuntimeError(f"{boundary} blobs do not contain the HTTP request")

    if mode == "runtime":
        observed = any(
            event.get("kind") == "tls.runtime"
            and event.get("data", {}).get("library") == "openssl"
            and event.get("data", {}).get("boundary") == boundary
            and event.get("data", {}).get("observed_bytes", 0) > 0
            for event in events
        )
    elif mode == "relay":
        observed = (
            any(event.get("kind") == "tls.client_hello" for event in events)
            and any(
                event.get("kind") == "tls.handshake"
                and event.get("data", {}).get("mode") == "relay"
                and event.get("data", {}).get("peer_identity", {}).get("verified") is True
                for event in events
            )
            and any(event.get("kind") == "http.request" for event in events)
            and any(event.get("kind") == "http.response" for event in events)
        )
    else:
        raise RuntimeError(f"unknown TLS mode: {mode}")
    if not observed:
        kinds = [event.get("kind") for event in events]
        raise RuntimeError(
            f"run has no complete {mode} TLS observation evidence; kinds={kinds!r}"
        )


def verify_benchmark() -> None:
    value = read_document()
    environment = value.get("environment")
    aggregates = value.get("aggregates")
    throughput = value.get("throughput")
    integrity = value.get("event_integrity")
    if not all(
        isinstance(item, expected)
        for item, expected in (
            (environment, dict),
            (aggregates, list),
            (throughput, list),
            (integrity, dict),
        )
    ):
        raise RuntimeError(f"benchmark document is incomplete: {value!r}")

    iterations = environment.get("iterations")
    expected_runs = 71 + (5 * iterations) if isinstance(iterations, int) else -1
    expected_integrity = {
        "runs": expected_runs,
        "incomplete_runs": 0,
        "missing_records": 0,
        "out_of_order_records": 0,
        "active_flows_after_close": 0,
        "failed_flows": 0,
        "error_events": 0,
    }
    aggregate_scenarios = {item.get("scenario") for item in aggregates}
    concurrent_levels = {
        item.get("concurrency")
        for item in aggregates
        if item.get("scenario") == "concurrent_cold_start"
    }
    throughput_scenarios = {item.get("scenario") for item in throughput}
    expected_throughput = {
        "direct_tcp_no_capture",
        "proxy_tcp_no_capture",
        "proxy_udp_no_capture",
        "proxy_tcp_capture",
        "relay_tls_capture",
    }
    valid = (
        value.get("contract") == "heimdall.benchmark/v1"
        and value.get("scope") == "disposable-ubuntu-vm"
        and environment.get("architecture") == "x86_64"
        and environment.get("memory_bytes", 0) >= 7 * 1024 * 1024 * 1024
        and environment.get("rss_source") == "procfs-heimdall-processes"
        and isinstance(environment.get("distribution"), str)
        and "Ubuntu 24.04" in environment["distribution"]
        and isinstance(iterations, int)
        and 1 <= iterations <= 20
        and aggregate_scenarios
        == {
            "cold_start",
            "concurrent_cold_start",
            "direct_tcp",
            "proxy_tcp",
            "proxy_udp",
            "relay_tls",
        }
        and concurrent_levels == {1, 10, 50}
        and throughput_scenarios == expected_throughput
        and all(item.get("wall_ns", {}).get("min", 0) > 0 for item in aggregates)
        and all(
            item.get("max_rss_kib", {}).get("max_process", 0) > 0
            for item in aggregates
        )
        and all(item.get("transferred_bytes", 0) > 0 for item in throughput)
        and all(item.get("bytes_per_second", 0) > 0 for item in throughput)
        and integrity == expected_integrity
    )
    if not valid:
        raise RuntimeError(f"unexpected Ubuntu benchmark contract: {value!r}")


def main() -> None:
    command = sys.argv[1]
    if command == "serve":
        serve(sys.argv[2], sys.argv[3])
    elif command == "tcp":
        tcp_client()
    elif command == "http":
        tcp_client(sys.argv[2])
    elif command == "http-bytes":
        tcp_client(sys.argv[2], int(sys.argv[3]))
    elif command == "udp":
        udp_client()
    elif command == "udp-host":
        udp_client(sys.argv[2])
    elif command == "tls":
        tls_client(sys.argv[2])
    elif command == "tls-bytes":
        tls_client(sys.argv[2], int(sys.argv[3]))
    elif command == "verify-config":
        verify_config()
    elif command == "verify-agent":
        verify_agent(sys.argv[2] if len(sys.argv) > 2 else "off")
    elif command == "latest-run":
        latest_run()
    elif command == "latest-running-run":
        latest_running_run()
    elif command == "running-runs":
        running_runs()
    elif command == "list-runs":
        list_runs()
    elif command == "run-dir":
        run_dir()
    elif command == "verify-events":
        verify_events(sys.argv[2], int(sys.argv[3]))
    elif command == "verify-log":
        verify_log(sys.argv[2] if len(sys.argv) > 2 else "closed")
    elif command == "verify-close":
        verify_close(int(sys.argv[2]), int(sys.argv[3]))
    elif command == "verify-recovery-preview":
        verify_recovery_preview()
    elif command == "verify-recovery-apply":
        verify_recovery_apply()
    elif command == "verify-ca":
        verify_ca()
    elif command == "verify-tls":
        verify_tls(sys.argv[2], pathlib.Path(sys.argv[3]))
    elif command == "verify-benchmark":
        verify_benchmark()
    else:
        raise SystemExit(f"unknown command: {command}")


if __name__ == "__main__":
    main()
