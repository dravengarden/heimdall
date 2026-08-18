#!/usr/bin/env bash
set -euo pipefail

systemctl is-active --quiet heimdall.service
systemctl is-active --quiet heimdall-test-socks.service
systemctl is-active --quiet heimdall-test-http.service
systemctl is-active --quiet heimdall-test-udp.service
systemctl is-active --quiet heimdall-test-http3.service
systemctl is-active --quiet heimdall-test-git.service

python3 /etc/heimdall-test/setup_worker_client.py "$(command -v heimdall)"
systemctl start user@1000.service

as_tester() {
  runuser -u tester -- env \
    HOME=/home/tester \
    XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    PATH=/run/wrappers/bin:/run/current-system/sw/bin \
    "$@"
}

capture_contains() {
  local action="$1"
  local needle="$2"
  local capture_file
  for capture_file in /run/heimdall-test/captures/*.jsonl; do
    test -f "$capture_file" || continue
    if jq -e --arg action "$action" \
      'select(.event == "open" and .action == $action and .payload == "tls_plaintext")' \
      "$capture_file" >/dev/null \
      && jq -r 'select(.event == "data") | .payload_base64' "$capture_file" \
        | base64 -d 2>/dev/null \
        | grep -Fq "$needle"; then
      return 0
    fi
  done
  return 1
}

as_tester heimdall config validate --json \
  | jq -e '.contract == "heimdall.config.validate/v2" and .valid'
as_tester heimdall agent \
  | jq -e '.contract == "heimdall.agent/v6"
    and .ready
    and .execution.backend == "linux-ebpf-foreground"
    and .execution.owner == "heimdall-run"
    and .execution.privilege_setup == "sudo-then-unprivileged-session-helper"
    and (.execution.daemon_required | not)
    and (.execution.web_ui_required | not)
    and .config.capture.mode == "on"
    and .config.capture.directory == "/run/heimdall-test/captures"
    and .config.capture.max_bytes_per_flow == 128
    and .capabilities.capture.contract == "heimdall.capture/v1"
    and .capabilities.capture.format == "jsonl"
    and .capabilities.capture.tcp
    and .capabilities.capture.udp
    and .capabilities.capture.payload == "mode_dependent"
    and .capabilities.capture.tls_plaintext
    and .capabilities.logs.event_contract == "heimdall.event/v1"
    and .capabilities.logs.run_contract == "heimdall.run/v1"
    and .capabilities.logs.format == "jsonl"
    and .capabilities.logs.lifecycle_events
    and .capabilities.logs.flow_events == "tcp+udp_metadata"
    and .capabilities.logs.writer_owned_rotation
    and (.capabilities.logs.content_addressed_blobs | not)
    and .capabilities.decrypt.modes == ["off", "runtime", "relay"]
    and .capabilities.decrypt.runtime_libraries == ["openssl"]
    and .capabilities.decrypt.runtime_apis == ["SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex"]
    and .capabilities.decrypt.runtime_discovery == "loaded_images_at_run_start"
    and .capabilities.decrypt.runtime_max_bytes_per_event == 256
    and .capabilities.decrypt.runtime_requires_attached_image
    and .capabilities.decrypt.relay_library_independent
    and .daemon.health.contract == "heimdall.daemon.health/v2"
    and .daemon.health.ready
    and .daemon.health.relay_port > 0
    and .daemon.health.decrypt_mode == "off"
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
    and (.capabilities.runtime_acceptance.tls_runtime | index("curl-openssl")) != null
    and (.capabilities.runtime_acceptance.tls_relay | index("curl")) != null
    and (.capabilities.cli_acceptance.tcp_fake_dns | index("git")) != null
    and .capabilities.lifecycle.descendant_cgroup_lifetime
    and .capabilities.lifecycle.exit_code_passthrough
    and .actions.logs_schema_event == ["heimdall", "logs", "schema", "--event", "v1"]
    and .actions.logs_schema_run == ["heimdall", "logs", "schema", "--run", "v1"]
    and .actions.logs_list == ["heimdall", "logs", "list", "--json"]
    and .capabilities.lifecycle.signal_exit_code == "128+signal"
    and .capabilities.lifecycle.upstream_unreachable_fail_closed
    and .capabilities.lifecycle.foreground_modes == ["off", "runtime", "relay"]
    and (.capabilities.lifecycle.runtime_mode_requires_daemon | not)
    and .capabilities.lifecycle.foreground_owned_resources
    and .capabilities.lifecycle.resources_close_when_run_exits
    and .capabilities.lifecycle.setup_helper_session_scoped
    and .capabilities.lifecycle.setup_helper_drops_privileges
    and .capabilities.lifecycle.web_ui_optional
    and .capabilities.lifecycle.concurrent_runs_isolated'
as_tester heimdall status --json \
  | jq -e '.daemon_reachable
    and .daemon_ready
    and (.relay_listen | test("^127\\.0\\.0\\.1:[0-9]+ \\+ \\[::1\\]:[0-9]+$"))
    and .daemon_decrypt_mode == "off"
    and .daemon_config_matches'

set +e
cleanup_report="$(heimdall ebpf cleanup --json)"
cleanup_status=$?
set -e
test "$cleanup_status" -eq 1
printf '%s' "$cleanup_report" \
  | jq -e '.contract == "heimdall.ebpf.cleanup/v1" and (.cleaned | not) and .code == "daemon_active"'

# Ordinary proxying owns its complete data plane in the foreground. Stop the
# compatibility daemon and remove its pinned generation before exercising it.
systemctl stop heimdall.service
heimdall ebpf cleanup --json \
  | jq -e '.contract == "heimdall.ebpf.cleanup/v1" and .cleaned'
foreground_link_baseline="$(bpftool -j link show | jq 'length')"
chown tester /run/heimdall-test/captures
as_tester heimdall agent \
  | jq -e '.ready
    and (.daemon.reachable | not)
    and .execution.backend == "linux-ebpf-foreground"
    and (.execution.daemon_required | not)'
rm -f /tmp/heimdall-daemonless-smoke
as_tester heimdall run --policy direct -- \
  sh -c 'touch /tmp/heimdall-daemonless-smoke'
test -e /tmp/heimdall-daemonless-smoke

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
udp_run_id="$(as_tester heimdall logs list --json | jq -er '.runs[0].run_id')"
as_tester heimdall logs query --run "$udp_run_id" --kind flow.open --jsonl \
  | jq -e 'select(.kind == "flow.open" and .data.network == "udp")' >/dev/null
as_tester heimdall logs query --run "$udp_run_id" --kind flow.close --jsonl \
  | jq -e 'select(.kind == "flow.close" and .data.network == "udp" and .data.status == "complete")' >/dev/null
as_tester heimdall logs verify --run "$udp_run_id" --json \
  | jq -e '.contract == "heimdall.logs.verify/v1" and .valid' >/dev/null
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

tcp_run_id="$(as_tester heimdall logs list --json | jq -er '.runs[0].run_id')"
tcp_run_dir="$(as_tester heimdall logs path --run "$tcp_run_id" --json | jq -er '.run_dir')"
test "$(stat -c '%a' "$tcp_run_dir")" = 700
test "$(stat -c '%a' "$tcp_run_dir/run.json")" = 600
if find "$tcp_run_dir" -maxdepth 1 -name 'events-*.jsonl' -printf '%m\n' \
  | grep -qv '^600$'; then
  echo "event segment permissions are not 0600" >&2
  exit 1
fi
as_tester heimdall logs query --run "$tcp_run_id" --jsonl \
  | jq -s -e '
    (map(.seq) == [1, 2, 3, 4, 5, 6])
    and any(.[]; .kind == "flow.open" and .data.network == "tcp")
    and any(.[]; .kind == "flow.close" and .data.network == "tcp" and .data.status == "complete")
    and .[-1].kind == "run.close"
  ' >/dev/null
as_tester heimdall logs verify --run "$tcp_run_id" --json \
  | jq -e '.valid and .state == "closed" and .events == 6' >/dev/null
as_tester heimdall logs schema --event v1 \
  | jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema" and (.oneOf | length) == 17' >/dev/null
as_tester heimdall logs schema --run v1 \
  | jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema"' >/dev/null

as_tester heimdall run --policy direct -- sleep 1 &
rotation_process=$!
rotation_run_id=""
for _ in $(seq 1 100); do
  rotation_run_id="$(as_tester heimdall logs list --json \
    | jq -r '.runs[] | select(.state == "running" and .policy == "direct") | .run_id' \
    | head -n1)"
  test -n "$rotation_run_id" && break
  sleep 0.02
done
test -n "$rotation_run_id"
as_tester heimdall logs rotate --run "$rotation_run_id" --json \
  | jq -e '.contract == "heimdall.logs.control/v1" and .ok' >/dev/null
wait "$rotation_process"
as_tester heimdall logs verify --run "$rotation_run_id" --json \
  | jq -e '.valid and .state == "closed" and .segments == 2' >/dev/null

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

# Two foreground invocations own disjoint listener ports, maps, links, and DNS
# state while sharing no daemon registration or pinned eBPF generation.
as_tester heimdall run --policy direct -- sleep 1 &
parallel_run_one=$!
as_tester heimdall run --policy direct -- sleep 1 &
parallel_run_two=$!
parallel_ready=false
for _ in $(seq 1 100); do
  if test "$(as_tester heimdall logs list --json \
    | jq '[.runs[] | select(.state == "running" and .policy == "direct")] | length')" -ge 2; then
    parallel_ready=true
    break
  fi
  sleep 0.02
done
test "$parallel_ready" = true
test "$(bpftool -j link show | jq 'length')" \
  -ge "$((foreground_link_baseline + 22))"
wait "$parallel_run_one"
wait "$parallel_run_two"
links_released=false
for _ in $(seq 1 100); do
  if test "$(bpftool -j link show | jq 'length')" -eq "$foreground_link_baseline"; then
    links_released=true
    break
  fi
  sleep 0.02
done
if test "$links_released" != true; then
  printf 'foreground BPF links did not return to baseline: baseline=%s actual=%s\n' \
    "$foreground_link_baseline" "$(bpftool -j link show | jq 'length')" >&2
fi
test "$links_released" = true

# Persistent-map upgrade coverage remains scoped to the compatibility daemon.
systemctl start heimdall.service
systemctl is-active --quiet heimdall.service
as_tester heimdall agent \
  | jq -e '.ready and .daemon.reachable and (.execution.daemon_required | not)'

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

test "$(stat -c '%a' /run/heimdall-test/captures)" = 700
if find /run/heimdall-test/captures -type f ! -perm 600 -print -quit | grep -q .; then
  echo "capture file permissions are not 0600" >&2
  exit 1
fi

tcp_capture=false
udp_capture=false
truncated_capture=false
for capture_file in /run/heimdall-test/captures/*.jsonl; do
  test -f "$capture_file"
  jq -e -s '
    length >= 1
    and all(.[]; .contract == "heimdall.capture/v1")
    and (to_entries | all(.value.sequence == .key))
    and .[0].event == "open"
  ' "$capture_file" >/dev/null
  if jq -e -s '
    .[0].network == "tcp"
    and any(.[]; .event == "data" and .direction == "client_to_remote")
    and any(.[]; .event == "data" and .direction == "remote_to_client")
    and any(.[]; .event == "close" and .status == "complete")
  ' "$capture_file" >/dev/null; then
    tcp_capture=true
  fi
  if jq -e -s '
    .[0].network == "udp"
    and any(.[]; .event == "data" and .direction == "client_to_remote")
    and any(.[]; .event == "data" and .direction == "remote_to_client")
    and any(.[]; .event == "close" and .status == "complete")
  ' "$capture_file" >/dev/null; then
    udp_capture=true
  fi
  if jq -e -s 'any(.[]; .event == "close" and .truncated)' "$capture_file" >/dev/null; then
    truncated_capture=true
  fi
done
test "$tcp_capture" = true
test "$udp_capture" = true
test "$truncated_capture" = true

# Exercise both TLS modes through the real foreground cgroup/eBPF relay. The
# long-lived OpenSSL fixture provides a representative image before each run,
# matching the startup discovery boundary reported by `heimdall agent`.
systemctl stop heimdall.service
heimdall ebpf cleanup --json | jq -e '.cleaned'
test "$(bpftool -j link show | jq 'length')" -eq "$foreground_link_baseline"
curl -V | grep -q OpenSSL
rm -f /run/heimdall-test/captures/*.jsonl
as_tester heimdall --config /etc/heimdall-test/runtime.toml agent \
  | jq -e '.ready
    and (.daemon.reachable | not)
    and .execution.backend == "linux-ebpf-foreground"
    and .execution.owner == "heimdall-run"
    and (.execution.daemon_required | not)
    and .config.decrypt.mode == "runtime"'
as_tester heimdall --config /etc/heimdall-test/runtime.toml run --policy fake -- \
  sh -c 'sleep 0.5; exec curl --cacert /etc/heimdall-test/upstream-ca.pem -fsS --max-time 5 https://fixture.test:18444/' \
    >/dev/null &
runtime_process=$!
runtime_helper=""
for _ in $(seq 1 100); do
  for candidate in $(pgrep -u tester -x heimdall); do
    if tr '\0' ' ' < "/proc/$candidate/cmdline" | grep -q ' __setup-worker '; then
      runtime_helper="$candidate"
      break 2
    fi
  done
  sleep 0.02
done
test -n "$runtime_helper"
test "$(awk '/^Uid:/{print $2 ":" $3 ":" $4}' "/proc/$runtime_helper/status")" = "1000:1000:1000"
test -z "$(pgrep -u root -x heimdall || true)"
wait "$runtime_process"
for _ in $(seq 1 100); do
  capture_contains runtime 'GET / HTTP' && break
  sleep 0.02
done
capture_contains runtime 'GET / HTTP'
test "$(bpftool -j link show | jq 'length')" -eq "$foreground_link_baseline"

rm -f /run/heimdall-test/captures/*.jsonl
install -d -o tester -g users -m 0700 /run/heimdall-test/relay
as_tester heimdall tls init-ca --dir /run/heimdall-test/relay --json \
  | jq -e '.contract == "heimdall.tls-ca/v2" and .config.mode == "relay"'
as_tester heimdall --config /etc/heimdall-test/relay.toml agent \
  | jq -e '.ready
    and (.daemon.reachable | not)
    and .execution.backend == "linux-ebpf-foreground"
    and (.execution.daemon_required | not)
    and .config.decrypt.mode == "relay"
    and .config.decrypt.ca_material_ready'
as_tester heimdall --config /etc/heimdall-test/relay.toml run --policy fake -- \
  curl --cacert /run/heimdall-test/relay/ca.pem -fsS --max-time 5 \
    https://fixture.test:18444/ >/dev/null
capture_contains route:default 'GET / HTTP'
systemctl start heimdall.service
systemctl is-active --quiet heimdall.service
as_tester heimdall agent \
  | jq -e '.ready and .daemon.health.decrypt_mode == "off"'

if find /sys/fs/cgroup/user.slice -type d -name 'heimdall-cli-*' -print -quit \
  | grep -q .; then
  echo "heimdall CLI cgroup leaked after successful runs" >&2
  exit 1
fi

echo "heimdall VM acceptance OK"
