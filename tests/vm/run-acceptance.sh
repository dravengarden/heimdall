#!/usr/bin/env bash
set -euo pipefail

systemctl is-active --quiet heimdall.service
systemctl is-active --quiet heimdall-test-socks.service
systemctl is-active --quiet heimdall-test-http.service
systemctl is-active --quiet heimdall-test-udp.service
systemctl is-active --quiet heimdall-test-http3.service
systemctl is-active --quiet heimdall-test-git.service
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
    and (.capabilities.runtime_acceptance.udp_ipv6 | index("java")) != null
    and (.capabilities.cli_acceptance.tcp_fake_dns | index("git")) != null
    and .capabilities.lifecycle.descendant_cgroup_lifetime
    and .capabilities.lifecycle.exit_code_passthrough
    and .capabilities.lifecycle.signal_exit_code == "128+signal"
    and .capabilities.lifecycle.upstream_unreachable_fail_closed
    and .capabilities.lifecycle.daemon_unreachable_prevents_exec
    and (.capabilities.lifecycle.daemon_restart_continuity | not)
    and .capabilities.lifecycle.daemon_restart_enforcement_continuity
    and .capabilities.lifecycle.daemon_restart_policy_recovery
    and .capabilities.lifecycle.daemon_restart_fake_dns_recovery
    and (.capabilities.lifecycle.daemon_restart_existing_connections | not)
    and .capabilities.lifecycle.pinned_state_schema == 1
    and .capabilities.lifecycle.transactional_program_upgrade
    and .capabilities.lifecycle.cleanup_requires_no_active_workloads'

set +e
cleanup_report="$(heimdall ebpf cleanup --json)"
cleanup_status=$?
set -e
test "$cleanup_status" -eq 1
printf '%s' "$cleanup_report" \
  | jq -e '.contract == "heimdall.ebpf.cleanup/v1" and (.cleaned | not) and .code == "daemon_active"'

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
test -z "$(as_tester heimdall run --policy fake -- \
  git ls-remote git://fixture.test:19418/repo.git)"
grep -q '"atyp": 3, "host": "fixture.test", "port": 19418' \
  /run/heimdall-test/socks.log

set +e
as_tester heimdall run --policy direct -- sh -c 'exit 42'
exit_status=$?
as_tester heimdall run --policy direct -- sh -c 'kill -TERM $$'
signal_status=$?
set -e
test "$exit_status" -eq 42
test "$signal_status" -eq 143

rm -f /tmp/heimdall-descendant.out
: > /run/heimdall-test/socks.log
as_tester heimdall run --policy fake -- sh -c \
  '(sleep 0.2; curl -4fsS --max-time 5 http://fixture.test:18080/ > /tmp/heimdall-descendant.out) &'
test "$(cat /tmp/heimdall-descendant.out)" = "fixture-v4"
grep -q '"atyp": 3, "host": "fixture.test", "port": 18080' \
  /run/heimdall-test/socks.log

if as_tester heimdall run --policy upstream-down -- \
  curl -4fsS --max-time 2 http://fixture.test:18080/; then
  echo "unreachable upstream unexpectedly allowed TCP" >&2
  exit 1
fi

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

rm -f /tmp/heimdall-restart-ready /tmp/heimdall-restart-stop-go \
  /tmp/heimdall-restart-stop-done /tmp/heimdall-restart-start-go \
  /tmp/heimdall-restart-blocked /tmp/heimdall-restart-bypass \
  /tmp/heimdall-restart.out
as_tester heimdall run --policy fake -- sh -c \
  'getent ahostsv4 fixture.test >/dev/null; touch /tmp/heimdall-restart-ready; while test ! -e /tmp/heimdall-restart-stop-go; do sleep 0.02; done; if curl -4fsS --max-time 2 http://192.0.2.1:18080/ >/dev/null; then touch /tmp/heimdall-restart-bypass; else touch /tmp/heimdall-restart-blocked; fi; touch /tmp/heimdall-restart-stop-done; while test ! -e /tmp/heimdall-restart-start-go; do sleep 0.02; done; curl -4fsS --max-time 5 http://fixture.test:18080/ > /tmp/heimdall-restart.out' &
restart_run_pid=$!
for _ in $(seq 1 250); do
  test -e /tmp/heimdall-restart-ready && break
  sleep 0.02
done
test -e /tmp/heimdall-restart-ready
test "$(find /run/heimdall/registrations -type f -name '*.json' | wc -l)" -eq 1
test "$(find /sys/fs/bpf/heimdall/links -type f | wc -l)" -ge 10
systemctl stop heimdall.service
test "$(find /sys/fs/bpf/heimdall/links -type f | wc -l)" -ge 10
set +e
cleanup_report="$(heimdall ebpf cleanup --json)"
cleanup_status=$?
set -e
test "$cleanup_status" -eq 1
printf '%s' "$cleanup_report" \
  | jq -e '(.cleaned | not) and .code == "active_workloads" and (.active_cgroups | length) == 1 and (.registrations | length) == 1'
: > /run/heimdall-test/socks.log
touch /tmp/heimdall-restart-stop-go
for _ in $(seq 1 250); do
  test -e /tmp/heimdall-restart-stop-done && break
  sleep 0.02
done
test -e /tmp/heimdall-restart-stop-done
test -e /tmp/heimdall-restart-blocked
test ! -e /tmp/heimdall-restart-bypass
test ! -s /run/heimdall-test/socks.log
systemctl start heimdall.service
systemctl is-active --quiet heimdall.service
restored_registration=false
for _ in $(seq 1 100); do
  if journalctl -u heimdall.service -n 100 --no-pager \
    | grep 'restored=1' >/dev/null; then
    restored_registration=true
    break
  fi
  sleep 0.02
done
test "$restored_registration" = true
: > /run/heimdall-test/socks.log
touch /tmp/heimdall-restart-start-go
for _ in $(seq 1 500); do
  ! kill -0 "$restart_run_pid" 2>/dev/null && break
  sleep 0.02
done
if kill -0 "$restart_run_pid" 2>/dev/null; then
  journalctl -u heimdall.service -n 100 --no-pager >&2
  kill "$restart_run_pid" 2>/dev/null || true
  wait "$restart_run_pid" 2>/dev/null || true
  echo "wrapped command did not resume after daemon restart" >&2
  exit 1
fi
wait "$restart_run_pid"
test "$(cat /tmp/heimdall-restart.out)" = "fixture-v4"
grep -q '"host": "fixture.test"' /run/heimdall-test/socks.log
test "$(find /run/heimdall/registrations -type f -name '*.json' | wc -l)" -eq 0

systemctl stop heimdall.service
set +e
daemon_report="$(as_tester heimdall agent)"
agent_status=$?
set -e
test "$agent_status" -eq 1
printf '%s' "$daemon_report" | jq -e '.ready == false and .daemon.reachable == false'
rm -f /tmp/heimdall-unregistered-command
if as_tester heimdall run --policy direct -- \
  sh -c 'touch /tmp/heimdall-unregistered-command'; then
  echo "command executed without daemon registration" >&2
  exit 1
fi
test ! -e /tmp/heimdall-unregistered-command
systemctl start heimdall.service
systemctl is-active --quiet heimdall.service
as_tester heimdall agent | jq -e '.ready and .daemon.reachable'

# A future map-layout schema must fail before any pinned program replacement.
systemctl stop heimdall.service
bpftool map update pinned /sys/fs/bpf/heimdall/maps/STATE_SCHEMA \
  key 0x00 0x00 0x00 0x00 value 0xe7 0x03 0x00 0x00
set +e
schema_error="$(timeout -k 1s 10s heimdall --config /etc/heimdall/config.toml daemon 2>&1)"
schema_status=$?
set -e
test "$schema_status" -ne 0
printf '%s' "$schema_error" | grep -q 'incompatible pinned eBPF state schema 999'
bpftool map update pinned /sys/fs/bpf/heimdall/maps/STATE_SCHEMA \
  key 0x00 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00
systemctl start heimdall.service
systemctl is-active --quiet heimdall.service

# A late invalid pin forces rollback of every earlier program replacement.
systemctl stop heimdall.service
rm /sys/fs/bpf/heimdall/links/skb_egress-user
link_programs_before="$(bpftool -j link show \
  | jq -c '[.[].prog_id] | sort')"
mkdir /sys/fs/bpf/heimdall/links/skb_egress-user
set +e
rollback_error="$(timeout -k 1s 10s heimdall --config /etc/heimdall/config.toml daemon 2>&1)"
rollback_status=$?
set -e
test "$rollback_status" -ne 0
link_programs_after="$(bpftool -j link show \
  | jq -c '[.[].prog_id] | sort')"
if test "$link_programs_before" != "$link_programs_after"; then
  printf 'rollback changed link programs: before=%s after=%s\n%s\n' \
    "$link_programs_before" "$link_programs_after" "$rollback_error" >&2
  exit 1
fi
test -n "$rollback_error"
rmdir /sys/fs/bpf/heimdall/links/skb_egress-user

# Cleanup is idempotent and a clean subsequent start installs a full generation.
cleanup_report="$(heimdall ebpf cleanup --json)"
printf '%s' "$cleanup_report" \
  | jq -e '.cleaned and .code == "cleaned" and .removed_entries > 0'
test ! -e /sys/fs/bpf/heimdall
heimdall ebpf cleanup --json | jq -e '.cleaned and .removed_entries == 0'
systemctl start heimdall.service
systemctl is-active --quiet heimdall.service
test -e /sys/fs/bpf/heimdall/maps/STATE_SCHEMA
as_tester heimdall agent | jq -e '.ready and .daemon.reachable'

if find /sys/fs/cgroup/user.slice -type d -name 'heimdall-cli-*' -print -quit \
  | grep -q .; then
  echo "heimdall CLI cgroup leaked after successful runs" >&2
  exit 1
fi

echo "heimdall VM acceptance OK"
