#!/usr/bin/env bash
set -euo pipefail

systemctl is-active --quiet heimdall.service
systemctl is-active --quiet heimdall-test-socks.service
systemctl is-active --quiet heimdall-test-http.service
systemctl is-active --quiet heimdall-test-udp.service
systemctl is-active --quiet heimdall-test-http3.service
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
  | jq -e '.contract == "heimdall.agent/v2"
    and .ready
    and .capabilities.udp.connected
    and .capabilities.udp.association_reuse
    and .capabilities.udp.multi_response
    and (.capabilities.udp.connectionless | not)
    and .capabilities.udp.connectionless_ipv4
    and (.capabilities.udp.connectionless_ipv6 | not)
    and .capabilities.udp.connectionless_ipv6_single_peer
    and .capabilities.udp.ipv4_mapped_ipv6_socket
    and (.capabilities.udp.concurrent_shared_source_port | not)
    and .capabilities.udp.concurrent_shared_source_port_ipv4
    and (.capabilities.udp.concurrent_shared_source_port_ipv6 | not)
    and .capabilities.udp.quic == "ipv4+ipv6-single-path"
    and .capabilities.udp.quic_ipv4
    and .capabilities.udp.quic_ipv6
    and (.capabilities.udp.quic_address_family_migration | not)
    and .capabilities.udp.max_socks5_payload_bytes == 65245
    and (.capabilities.runtime_acceptance.tcp_fake_dns | index("go-netgo")) != null
    and (.capabilities.runtime_acceptance.udp_ipv4 | index("nodejs")) != null
    and (.capabilities.runtime_acceptance.udp_ipv6 | index("java")) != null'

CGO_ENABLED=0 go build -tags netgo -trimpath \
  -o /run/heimdall-test/runtime-go /etc/heimdall-test/runtime_client.go
if ldd /run/heimdall-test/runtime-go >/dev/null 2>&1; then
  echo "Go netgo fixture unexpectedly linked dynamic libraries" >&2
  exit 1
fi
javac -d /run/heimdall-test /etc/heimdall-test/RuntimeClient.java
rustc --edition 2024 -C opt-level=2 -D warnings \
  -o /run/heimdall-test/runtime-rust /etc/heimdall-test/runtime_client.rs

: > /run/heimdall-test/socks.log
for runtime in go-netgo java nodejs rust; do
  test "$(as_tester heimdall run --policy fake -- \
    /etc/heimdall-test/runtime-wrapper "$runtime" tcp)" = "$runtime-tcp-ok"
  test "$(as_tester heimdall run --policy udp -- \
    /etc/heimdall-test/runtime-wrapper "$runtime" udp4)" = "$runtime-udp4-ok"
  test "$(as_tester heimdall run --policy udp -- \
    /etc/heimdall-test/runtime-wrapper "$runtime" udp6)" = "$runtime-udp6-ok"
done
test "$(grep -c '"atyp": 3, "host": "fixture.test", "port": 18080' \
  /run/heimdall-test/socks.log)" -eq 4
test "$(grep -c '"udp": true, "atyp": 1, "host": "127.0.0.1", "port": 18082' \
  /run/heimdall-test/socks.log)" -eq 4
test "$(grep -c '"udp": true, "atyp": 4, "host": "::1", "port": 18083' \
  /run/heimdall-test/socks.log)" -eq 4

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
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_client.py 127.0.0.1 18082 udp-v4:probe)" = "udp-v4:probe"
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_client.py ::1 18083 udp-v6:probe)" = "udp-v6:probe"
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_client.py fixture.test 18082 udp-v4:probe)" = "udp-v4:probe"
grep -q '"udp": true, "atyp": 1, "host": "127.0.0.1", "port": 18082' \
  /run/heimdall-test/socks.log
grep -q '"udp": true, "atyp": 4, "host": "::1", "port": 18083' \
  /run/heimdall-test/socks.log
grep -q '"udp": true, "atyp": 3, "host": "fixture.test", "port": 18082' \
  /run/heimdall-test/socks.log

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_session_client.py 127.0.0.1 18082 udp-v4:)" = "udp-session-ok"
test "$(grep -c '"udp_associate": true' /run/heimdall-test/socks.log)" -eq 1
test "$(grep -c '"udp": true' /run/heimdall-test/socks.log)" -eq 3

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_port_reuse_client.py)" = "udp-port-reuse-ok"
test "$(grep -c '"udp_associate": true' /run/heimdall-test/socks.log)" -eq 2

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_connectionless_client.py)" = "udp-connectionless-ok"
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_ipv6_bind_guard_client.py)" = "udp-ipv6-bind-guard-ok"
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_shared_port_client.py)" = "udp-shared-port-ok"
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/udp_token_stress_client.py)" = "udp-token-stress-ok"

gcc -O2 -Wall -Wextra -Werror \
  /etc/heimdall-test/udp_batch_client.c -o /run/heimdall-test/udp-batch-client
test "$(as_tester heimdall run --policy udp -- \
  /run/heimdall-test/udp-batch-client)" = "udp-batch-ok"

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/http3_client.py fixture.test)" = "http3-ok"
test "$(grep -c '"udp_associate": true' /run/heimdall-test/socks.log)" -eq 1
grep -q '"udp": true, "atyp": 3, "host": "fixture.test", "port": 18443' \
  /run/heimdall-test/socks.log

: > /run/heimdall-test/socks.log
test "$(as_tester heimdall run --policy udp -- \
  python3 /etc/heimdall-test/http3_client.py ::1)" = "http3-ok"
test "$(grep -c '"udp_associate": true' /run/heimdall-test/socks.log)" -eq 1
grep -q '"udp": true, "atyp": 4, "host": "::1", "port": 18443' \
  /run/heimdall-test/socks.log

test "$(as_tester heimdall run --policy udp-direct -- \
  python3 /etc/heimdall-test/http3_client.py 127.0.0.1)" = "http3-ok"
test "$(as_tester heimdall run --policy udp-direct -- \
  python3 /etc/heimdall-test/http3_client.py ::1)" = "http3-ok"

test "$(as_tester heimdall run --policy udp-direct -- \
  python3 /etc/heimdall-test/udp_client.py 127.0.0.1 18082 udp-v4:probe)" = "udp-v4:probe"
test "$(as_tester heimdall run --policy udp-direct -- \
  python3 /etc/heimdall-test/udp_client.py ::1 18083 udp-v6:probe)" = "udp-v6:probe"
test "$(as_tester heimdall run --policy udp-direct -- \
  python3 /etc/heimdall-test/udp_session_client.py 127.0.0.1 18082 udp-v4:)" = "udp-session-ok"
test "$(as_tester heimdall run --policy udp-direct -- \
  python3 /etc/heimdall-test/udp_connectionless_client.py)" = "udp-connectionless-ok"

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
