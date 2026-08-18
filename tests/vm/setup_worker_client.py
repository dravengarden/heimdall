#!/usr/bin/env python3

import array
import json
import os
import socket
import struct
import subprocess
import sys


def read_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("setup worker closed the socket early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main():
    binary = sys.argv[1]
    cgroup = "/sys/fs/cgroup/heimdall-setup-test"
    os.mkdir(cgroup)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    process = None
    try:
        process = subprocess.Popen(
            [binary, "__setup-worker"],
            stdin=child,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        child.close()
        request = json.dumps(
            {
                "contract": "heimdall.setup/v1",
                "cgroup_path": cgroup,
                "cgroup_id": os.stat(cgroup).st_ino,
                "relay_port": 12345,
                "dns_port": 5358,
                "policy_flags": 2,
            },
            separators=(",", ":"),
        ).encode()
        parent.sendall(struct.pack(">I", len(request)) + request)

        response_length = struct.unpack(">I", read_exact(parent, 4))[0]
        response = json.loads(read_exact(parent, response_length))
        if response.get("status") != "ready" or len(response.get("fds", [])) != 15:
            raise RuntimeError(f"unexpected setup response: {response}")

        marker, ancillary, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(15 * 4))
        if marker != b"F" or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("invalid or truncated setup FD message")
        received = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received.frombytes(data[: len(data) - (len(data) % received.itemsize)])
            else:
                raise RuntimeError("unexpected setup ancillary message")
        if len(received) != 15:
            raise RuntimeError(f"received {len(received)} setup FDs instead of 15")

        stderr = process.communicate(timeout=10)[1].decode()
        if process.returncode != 0:
            raise RuntimeError(f"setup worker failed: {stderr}")
        for fd in received:
            os.fstat(fd)
        for fd in received[4:]:
            with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as info:
                if "prog_id:" not in info.read():
                    raise RuntimeError("received descriptor is not a live BPF link")
        for fd in received:
            os.close(fd)
    finally:
        parent.close()
        child.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        os.rmdir(cgroup)


if __name__ == "__main__":
    main()
