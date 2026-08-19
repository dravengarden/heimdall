#!/usr/bin/env python3
"""Transfer a bounded payload through one connected UDP flow."""

import argparse
import socket


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--chunk-bytes", type=int, default=8192)
    args = parser.parse_args()
    if not 1 <= args.bytes <= 32 * 1024 * 1024:
        parser.error("--bytes must be between 1 and 33554432")
    if not 8 <= args.chunk_bytes <= 60_000:
        parser.error("--chunk-bytes must be between 8 and 60000")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.connect((args.host, args.port))
    sent = 0
    received = 0
    sequence = 0
    while sent < args.bytes:
        size = min(args.chunk_bytes, args.bytes - sent)
        payload = (sequence.to_bytes(8, "big") + (b"x" * size))[:size]
        sock.send(payload)
        response = sock.recv(65_535)
        if response != b"udp-v4:" + payload:
            raise RuntimeError(f"UDP response mismatch at sequence {sequence}")
        sent += len(payload)
        received += len(response)
        sequence += 1

    print(sent + received)


if __name__ == "__main__":
    main()
