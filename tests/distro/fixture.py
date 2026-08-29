#!/usr/bin/env python3
"""Loopback fixtures and machine-readable assertions for distro acceptance."""

from __future__ import annotations

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
TCP_PORT = 18080
UDP_PORT = 18082
TCP_BODY = b"ubuntu-tcp-ok"
UDP_BODY = b"ubuntu-udp:probe"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(TCP_BODY)))
        self.end_headers()
        self.wfile.write(TCP_BODY)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def serve_udp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, UDP_PORT))
        while True:
            payload, peer = sock.recvfrom(65535)
            sock.sendto(b"ubuntu-udp:" + payload, peer)


def serve() -> None:
    udp = threading.Thread(target=serve_udp, daemon=True)
    udp.start()
    ThreadingHTTPServer((HOST, TCP_PORT), Handler).serve_forever()


def tcp_client() -> None:
    with socket.create_connection((HOST, TCP_PORT), timeout=5) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n")
        response = bytearray()
        while chunk := sock.recv(65535):
            response.extend(chunk)
    body = bytes(response).partition(b"\r\n\r\n")[2]
    if body != TCP_BODY:
        raise RuntimeError(f"unexpected TCP response: {body!r}")
    print(body.decode())


def udp_client() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((HOST, UDP_PORT))
        original_peer = sock.getpeername()
        sock.sendall(b"probe")
        response = sock.recv(65535)
        if sock.getpeername() != original_peer:
            raise RuntimeError("UDP peer identity changed")
    if response != UDP_BODY:
        raise RuntimeError(f"unexpected UDP response: {response!r}")
    print(response.decode())


def read_document() -> dict[str, object]:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise RuntimeError("expected one JSON object")
    return value


def verify_config() -> None:
    value = read_document()
    if value.get("contract") != "heimdall.config.validate/v2" or not value.get("valid"):
        raise RuntimeError(f"configuration is not valid: {value!r}")


def verify_agent() -> None:
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
        and capture.get("mode") == "off"
        and decrypt.get("mode") == "off"
    )
    if not expected:
        raise RuntimeError(f"unexpected agent contract: {value!r}")


def latest_run() -> None:
    value = read_document()
    runs = value.get("runs")
    if value.get("contract") != "heimdall.logs.list/v1" or not isinstance(runs, list) or not runs:
        raise RuntimeError(f"no Heimdall run found: {value!r}")
    print(runs[0]["run_id"])


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


def verify_log() -> None:
    value = read_document()
    if not (
        value.get("contract") == "heimdall.logs.verify/v1"
        and value.get("valid") is True
        and value.get("state") == "closed"
    ):
        raise RuntimeError(f"invalid run evidence: {value!r}")


def main() -> None:
    command = sys.argv[1]
    if command == "serve":
        serve()
    elif command == "tcp":
        tcp_client()
    elif command == "udp":
        udp_client()
    elif command == "verify-config":
        verify_config()
    elif command == "verify-agent":
        verify_agent()
    elif command == "latest-run":
        latest_run()
    elif command == "list-runs":
        list_runs()
    elif command == "verify-events":
        verify_events(sys.argv[2], int(sys.argv[3]))
    elif command == "verify-log":
        verify_log()
    else:
        raise SystemExit(f"unknown command: {command}")


if __name__ == "__main__":
    main()
