#!/usr/bin/env bash
set -euo pipefail

systemctl is-active --quiet heimdall.service
systemctl is-active --quiet heimdall-test-socks.service
systemctl is-active --quiet heimdall-test-http.service
systemctl start user@1000.service

as_tester() {
  runuser -u tester -- env \
    HOME=/home/tester \
    XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    PATH=/run/current-system/sw/bin \
    "$@"
}

as_tester heimdall config validate --json \
  | jq -e '.contract == "heimdall.config.validate/v1" and .valid'
as_tester heimdall agent \
  | jq -e '.contract == "heimdall.agent/v2" and .ready'

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy fake -- \
  curl -4fsS --max-time 5 http://fixture.test:18080/)" = "fixture-v4"
grep -q '"atyp": 3, "host": "fixture.test", "port": 18080' \
  /run/heimdall-test/socks.log

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy system -- \
  curl -4fsS --max-time 5 http://127.0.0.1:18080/)" = "fixture-v4"
test "$(as_tester heimdall run --policy system -- \
  curl -gfsS --max-time 5 http://[::1]:18081/)" = "fixture-v6"
grep -q '"atyp": 1, "host": "127.0.0.1", "port": 18080' \
  /run/heimdall-test/socks.log
grep -q '"atyp": 4, "host": "::1", "port": 18081' \
  /run/heimdall-test/socks.log

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy direct -- \
  curl -4fsS --max-time 5 http://127.0.0.1:18080/)" = "fixture-v4"
test ! -s /run/heimdall-test/socks.log

if as_tester heimdall run --policy reject -- \
  curl -4fsS --max-time 2 http://127.0.0.1:18080/; then
  echo "reject policy unexpectedly allowed TCP" >&2
  exit 1
fi

as_tester heimdall run --policy system -- python3 -c '
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(b"blocked", ("127.0.0.1", 18080))
except PermissionError:
    pass
else:
    raise SystemExit("non-DNS UDP unexpectedly allowed")
'

: > /run/heimdall-test/socks.log
as_tester heimdall run --policy system -- \
  python3 /etc/heimdall-test/dual_stack_client.py
test "$(grep -c '"atyp": 1' /run/heimdall-test/socks.log)" -eq 100
test "$(grep -c '"atyp": 4' /run/heimdall-test/socks.log)" -eq 100

: > /run/heimdall-test/socks.log
test "$(as_tester curl -4fsS --max-time 5 http://127.0.0.1:18080/)" = "fixture-v4"
test ! -s /run/heimdall-test/socks.log

if find /sys/fs/cgroup/user.slice -type d -name 'heimdall-cli-*' -print -quit \
  | grep -q .; then
  echo "heimdall CLI cgroup leaked after successful runs" >&2
  exit 1
fi

echo "heimdall VM acceptance OK"
