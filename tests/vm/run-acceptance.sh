#!/usr/bin/env bash
set -euo pipefail

systemctl is-active --quiet heimdall-test-socks.service
systemctl is-active --quiet heimdall-test-http.service
systemctl is-active --quiet heimdall-test-udp.service
systemctl is-active --quiet heimdall-test-http3.service
systemctl is-active --quiet heimdall-test-git.service

python3 /etc/heimdall-test/setup_worker_client.py "$(command -v heimdall)"
systemctl start user@1000.service
systemctl start user@1001.service

as_tester() {
  runuser -u tester -- env \
    HOME=/home/tester \
    XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    PATH=/run/wrappers/bin:/run/current-system/sw/bin \
    HEIMDALL_CAPTURE_SECRET=redaction-secret \
    "$@"
}

as_unauthorized() {
  runuser -u unauthorized -- env \
    HOME=/home/unauthorized \
    XDG_RUNTIME_DIR=/run/user/1001 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus \
    PATH=/run/wrappers/bin:/run/current-system/sw/bin \
    "$@"
}

set +e
authorization_failure="$(as_unauthorized heimdall run --policy direct -- true 2>&1)"
authorization_status=$?
set -e
test "$authorization_status" -ne 0
printf '%s' "$authorization_failure" \
  | grep -F 'non-interactive setup authorization must allow exactly' >/dev/null

capture_contains() {
  local boundary="$1"
  local needle="$2"
  local event_file run_dir blob
  while IFS= read -r event_file; do
    run_dir="$(dirname "$event_file")"
    while IFS= read -r blob; do
      if grep -Fq "$needle" "$run_dir/$blob"; then
        return 0
      fi
    done < <(jq -r --arg boundary "$boundary" \
      'select(.kind == "flow.data" and .data.boundary == $boundary) | .data.blob.path' \
      "$event_file")
  done < <(find /home/tester/.local/state/heimdall/runs -name 'events-*.jsonl' -type f)
  return 1
}

as_tester heimdall config validate --json \
  | jq -e '.contract == "heimdall.config.validate/v2" and .valid'
as_tester heimdall config schema --version v1 \
  | jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema"
    and .title == "heimdall.config/v1"
    and .properties.version.const == 1
    and .additionalProperties == false' >/dev/null
as_tester heimdall config example --format toml > /tmp/heimdall-example.toml
as_tester heimdall --config /tmp/heimdall-example.toml config validate
as_tester heimdall agent \
  | jq -e '.contract == "heimdall.agent/v8"
    and .ready
    and .execution.backend == "linux-ebpf-foreground"
    and .execution.owner == "heimdall-run"
    and .execution.privilege_setup == "sudo-then-unprivileged-session-helper"
    and (.execution.daemon_required | not)
    and (.execution.web_ui_required | not)
    and .config.capture.mode == "on"
    and .config.capture.max_bytes_per_flow == 512
    and .config.capture.block_max_bytes == 32
    and .config.capture.flush_interval_ms == 20
    and .config.capture.boundaries == ["transport", "tls_plaintext.runtime", "tls_plaintext.relay"]
    and .config.capture.directions == ["client_to_remote", "remote_to_client"]
    and .config.capture.redact_env == ["HEIMDALL_CAPTURE_SECRET"]
    and .config.capture.redaction_values_ready
    and .config.capture.redaction_error == null
    and .capabilities.capture.contract == "heimdall.event/v1"
    and .capabilities.capture.format == "content-addressed-blobs"
    and .capabilities.capture.tcp
    and .capabilities.capture.udp
    and .capabilities.capture.payload == "mode_dependent"
    and .capabilities.capture.tls_plaintext
    and .capabilities.capture.boundary_allowlist
    and .capabilities.capture.direction_allowlist
    and .capabilities.capture.environment_redaction
    and .capabilities.logs.event_contract == "heimdall.event/v1"
    and .capabilities.logs.summary_contract == "heimdall.logs.summary/v1"
    and .capabilities.logs.run_contract == "heimdall.run/v1"
    and .capabilities.logs.format == "jsonl"
    and .capabilities.logs.lifecycle_events
    and .capabilities.logs.flow_events == "tcp+udp+payload"
    and .capabilities.logs.dns_events == "fake"
    and .capabilities.logs.policy_decision_events
    and .capabilities.logs.tls_events == "runtime+relay"
    and .capabilities.logs.client_hello_events
    and .capabilities.logs.derived_http_records == "http1_headers_from_tls_plaintext"
    and .capabilities.logs.offline_schema_validation
    and .capabilities.logs.writer_owned_rotation
    and .capabilities.logs.content_addressed_blobs
    and .capabilities.logs.bounded_block_coalescing
    and .capabilities.logs.incomplete_run_recovery
    and .capabilities.decrypt.modes == ["off", "runtime", "relay"]
    and .capabilities.decrypt.runtime_libraries == ["openssl"]
    and .capabilities.decrypt.runtime_apis == ["SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex"]
    and .capabilities.decrypt.runtime_evidence == "tls.runtime+flow.data"
    and .capabilities.decrypt.runtime_discovery == "loaded_images_at_run_start"
    and .capabilities.decrypt.runtime_max_bytes_per_event == 256
    and .capabilities.decrypt.runtime_requires_attached_image
    and .capabilities.decrypt.relay_library_independent
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
    and .actions.config_schema == ["heimdall", "config", "schema", "--version", "v1"]
    and .actions.config_example_toml == ["heimdall", "config", "example", "--format", "toml"]
    and .actions.logs_summary == ["heimdall", "logs", "summary", "--run", "<RUN_ID>", "--json"]
    and .actions.logs_schema_run == ["heimdall", "logs", "schema", "--run", "v1"]
    and .actions.logs_list == ["heimdall", "logs", "list", "--json"]
    and .actions.logs_recover_preview == ["heimdall", "logs", "recover", "--run", "<RUN_ID>", "--json"]
    and .capabilities.lifecycle.signal_exit_code == "128+signal"
    and .capabilities.lifecycle.foreground_signal_forwarding == ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"]
    and .capabilities.lifecycle.upstream_unreachable_fail_closed
    and .capabilities.lifecycle.foreground_modes == ["off", "runtime", "relay"]
    and .capabilities.lifecycle.foreground_owned_resources
    and .capabilities.lifecycle.resources_close_when_run_exits
    and .capabilities.lifecycle.setup_helper_session_scoped
    and .capabilities.lifecycle.setup_helper_drops_privileges
    and .capabilities.lifecycle.web_ui_optional
    and .capabilities.lifecycle.concurrent_runs_isolated'
# The public CLI has no persistent service, status endpoint, or pin lifecycle.
if heimdall help -v | grep -Eq '^  (daemon|status|ebpf)( |$)'; then
  echo "persistent compatibility command leaked into the CLI" >&2
  exit 1
fi
test ! -e /sys/fs/bpf/heimdall
foreground_link_baseline="$(bpftool -j link show | jq 'length')"
as_tester heimdall agent \
  | jq -e '.ready
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
  curl -4fsS --max-time 5 http://fixture.test:18080/redaction-secret)" = "fixture-v4"
grep -q '"atyp": 3, "host": "fixture.test", "port": 18080' \
  /run/heimdall-test/socks.log

tcp_run_id="$(as_tester heimdall logs list --json | jq -er '.runs[0].run_id')"
tcp_run_dir="$(as_tester heimdall logs path --run "$tcp_run_id" --json | jq -er '.run_dir')"
test "$(stat -c '%a' "$tcp_run_dir")" = 700
test "$(stat -c '%a' "$tcp_run_dir/run.json")" = 600
captured_payload="$(
  jq -r 'select(.kind == "flow.data" and .data.direction == "client_to_remote") | .data.blob.path' \
    "$tcp_run_dir"/events-*.jsonl \
    | while IFS= read -r blob; do cat "$tcp_run_dir/$blob"; done
)"
case "$captured_payload" in
  *'****************'*) ;;
  *)
    echo "capture did not preserve a redacted marker across blocks" >&2
    exit 1
    ;;
esac
if [[ "$captured_payload" == *redaction-secret* ]]; then
  echo "capture persisted a configured redaction value" >&2
  exit 1
fi
if find "$tcp_run_dir" -maxdepth 1 -name 'events-*.jsonl' -printf '%m\n' \
  | grep -qv '^600$'; then
  echo "event segment permissions are not 0600" >&2
  exit 1
fi
as_tester heimdall logs query --run "$tcp_run_id" --jsonl \
  | jq -s -e '
    ([.[] | select(.kind == "dns.query") | .data.exchange_id] | unique) as $dns
    | (map(.seq) == [range(1; length + 1)])
    and (($dns | length) > 0)
    and any(.[]; .kind == "dns.answer" and (.data.exchange_id as $id | $dns | index($id)))
    and any(.[]; .kind == "policy.decision"
      and .data.network == "tcp"
      and .data.destination.host == "fixture.test"
      and .data.action.type == "route")
    and any(.[]; .kind == "flow.open" and .data.network == "tcp")
    and any(.[]; .kind == "flow.data"
      and .data.blob.algorithm == "sha256"
      and .data.block.max_bytes == 32
      and .data.block.flush_interval_ms == 20
      and (.data.block.flush_reason == "size"
        or .data.block.flush_reason == "interval"
        or .data.block.flush_reason == "close"))
    and all(.[] | select(.kind == "flow.data"); .data.stored_bytes <= 32)
    and any(.[]; .kind == "flow.close" and .data.network == "tcp" and .data.status == "complete")
    and .[-1].kind == "run.close"
  ' >/dev/null
as_tester heimdall logs verify --run "$tcp_run_id" --json \
  | jq -e '.valid and .state == "closed" and .events >= 8 and .blobs >= 1' >/dev/null
as_tester heimdall logs schema --event v1 \
  | jq -e '."$schema" == "https://json-schema.org/draft/2020-12/schema" and (.oneOf | length) == 18' >/dev/null
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
set +e
active_recovery="$(as_tester heimdall logs recover --run "$rotation_run_id" --json 2>/dev/null)"
active_recovery_status=$?
set -e
test "$active_recovery_status" -eq 1
printf '%s' "$active_recovery" \
  | jq -e '.contract == "heimdall.logs.recover/v1"
    and (.applicable | not)
    and (.applied | not)
    and .code == "run_active"' >/dev/null
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

# A signal addressed to the foreground owner is forwarded to the immediate
# child. The owner stays alive long enough to finalize logs and release links.
as_tester heimdall run --policy direct -- sleep 30 &
forward_wrapper=$!
forward_owner=""
forward_run_id=""
for _ in $(seq 1 200); do
  for candidate in $(pgrep -u tester -x heimdall || true); do
    if tr '\0' ' ' < "/proc/$candidate/cmdline" \
      | grep -q ' run .*--no-reentry .*sleep 30'; then
      forward_owner="$candidate"
      break
    fi
  done
  forward_run_id="$(as_tester heimdall logs list --json \
    | jq -r 'first(.runs[] | select(.state == "running" and .policy == "direct")) | .run_id // empty')"
  test -n "$forward_owner" && test -n "$forward_run_id" && break
  sleep 0.02
done
test -n "$forward_owner"
test -n "$forward_run_id"
kill -TERM "$forward_owner"
set +e
wait "$forward_wrapper"
forward_status=$?
set -e
test "$forward_status" -eq 143
as_tester heimdall logs verify --run "$forward_run_id" --json \
  | jq -e '.valid and .state == "closed"' >/dev/null
forward_run_dir="$(as_tester heimdall logs path --run "$forward_run_id" --json | jq -er .run_dir)"
jq -e -s '.[-1].kind == "run.close"
  and .[-1].data.exit_code == 143
  and .[-1].data.signal == 15
  and .[-1].data.complete' "$forward_run_dir"/events-*.jsonl >/dev/null

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

# Killing the foreground owner must not turn a still-running workload into
# direct egress. The unprivileged session helper owns no listener; it only
# observes the private socket and kills/removes this run's cgroup on EOF.
as_tester heimdall run --policy direct -- sleep 30 &
kill_wrapper=$!
kill_owner=""
kill_helper=""
for _ in $(seq 1 200); do
  for candidate in $(pgrep -u tester -x heimdall || true); do
    candidate_cmdline="$(tr '\0' ' ' < "/proc/$candidate/cmdline")"
    if printf '%s' "$candidate_cmdline" | grep -q ' run .*--no-reentry .*sleep 30'; then
      kill_owner="$candidate"
    elif printf '%s' "$candidate_cmdline" | grep -q ' __setup-worker '; then
      kill_helper="$candidate"
    fi
  done
  test -n "$kill_owner" && test -n "$kill_helper" && break
  sleep 0.02
done
test -n "$kill_owner"
test -n "$kill_helper"
kill_cgroup="$(find /sys/fs/cgroup/user.slice -type d -name "heimdall-cli-$kill_owner-*" -print -quit)"
test -n "$kill_cgroup"
abandoned_run_id="$(as_tester heimdall logs list --json \
  | jq -er 'first(.runs[] | select(.state == "running" and .policy == "direct")) | .run_id')"
test -n "$abandoned_run_id"
kill -KILL "$kill_owner"
wait "$kill_wrapper" 2>/dev/null || true
abandoned_cleaned=false
for _ in $(seq 1 500); do
  if ! test -e "/proc/$kill_helper" \
    && ! test -e "$kill_cgroup" \
    && test "$(bpftool -j link show | jq 'length')" -eq "$foreground_link_baseline"; then
    abandoned_cleaned=true
    break
  fi
  sleep 0.02
done
test "$abandoned_cleaned" = true
as_tester heimdall logs recover --run "$abandoned_run_id" --json \
  | jq -e '.contract == "heimdall.logs.recover/v1"
    and .applicable
    and (.applied | not)
    and .code == "recovery_available"
    and .projected_state == "failed"' >/dev/null
recovery_dir="$(as_tester heimdall logs recover --run "$abandoned_run_id" --apply --json \
  | jq -er 'select(.applied and .state_after == "failed") | .recovery_dir')"
test "$(stat -c '%a' "$recovery_dir")" = 700
test "$(stat -c '%a' "$recovery_dir/manifest-before.json")" = 600
jq -e '.contract == "heimdall.logs.recovery-record/v1" and .status == "applied"' \
  "$recovery_dir/recovery.json" >/dev/null
as_tester heimdall logs verify --run "$abandoned_run_id" --json \
  | jq -e '.valid and .state == "failed"' >/dev/null

tcp_capture=false
udp_capture=false
truncated_capture=false
while IFS= read -r run_id; do
  as_tester heimdall logs verify --run "$run_id" --json | jq -e '.valid'
  run_dir="$(as_tester heimdall logs path --run "$run_id" --json | jq -er .run_dir)"
  if jq -e -s '
    ([.[] | select(.kind == "flow.open" and .data.network == "tcp") | .flow_id] | unique) as $flows
    | any(.[]; .kind == "flow.data" and (.flow_id as $id | $flows | index($id)))
  ' "$run_dir"/events-*.jsonl >/dev/null; then tcp_capture=true; fi
  if jq -e -s '
    ([.[] | select(.kind == "flow.open" and .data.network == "udp") | .flow_id] | unique) as $flows
    | any(.[]; .kind == "flow.data" and (.flow_id as $id | $flows | index($id)))
  ' "$run_dir"/events-*.jsonl >/dev/null; then udp_capture=true; fi
  if jq -e -s 'any(.[]; .kind == "flow.data" and .data.truncated)' \
    "$run_dir"/events-*.jsonl >/dev/null; then truncated_capture=true; fi
done < <(as_tester heimdall logs list --json | jq -r '.runs[].run_id')
test "$tcp_capture" = true
test "$udp_capture" = true
test "$truncated_capture" = true

# Exercise both TLS modes through the real foreground cgroup/eBPF relay. The
# long-lived OpenSSL fixture provides a representative image before each run,
# matching the startup discovery boundary reported by `heimdall agent`.
test "$(bpftool -j link show | jq 'length')" -eq "$foreground_link_baseline"
curl -V | grep -q OpenSSL
as_tester heimdall --config /etc/heimdall-test/runtime.toml agent \
  | jq -e '.ready
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
  capture_contains tls_plaintext.runtime 'GET / HTTP' && break
  sleep 0.02
done
capture_contains tls_plaintext.runtime 'GET / HTTP'
find /home/tester/.local/state/heimdall/runs -name 'events-*.jsonl' -type f -print0 \
  | xargs -0 jq -e -s 'any(.[]; .kind == "tls.runtime"
      and .data.library == "openssl"
      and .data.boundary == "tls_plaintext.runtime"
      and (.data.api_family == "SSL_read*" or .data.api_family == "SSL_write*")
      and .data.observed_bytes > 0
      and .pid > 0)' >/dev/null
test "$(bpftool -j link show | jq 'length')" -eq "$foreground_link_baseline"

install -d -o tester -g users -m 0700 /run/heimdall-test/relay
as_tester heimdall tls init-ca --dir /run/heimdall-test/relay --json \
  | jq -e '.contract == "heimdall.tls-ca/v2" and .config.mode == "relay"'
as_tester heimdall --config /etc/heimdall-test/relay.toml agent \
  | jq -e '.ready
    and .execution.backend == "linux-ebpf-foreground"
    and (.execution.daemon_required | not)
    and .config.decrypt.mode == "relay"
    and .config.decrypt.ca_material_ready'
as_tester heimdall --config /etc/heimdall-test/relay.toml run --policy fake -- \
  curl --cacert /run/heimdall-test/relay/ca.pem -H 'User-Agent:' \
    -H 'Authorization: bearer fixture-value' -fsS --max-time 5 \
    https://fixture.test:18444/ >/dev/null
capture_contains tls_plaintext.relay 'GET / HTTP'
relay_run_id="$(as_tester heimdall logs list --json | jq -er '.runs[0].run_id')"
relay_run_dir="$(as_tester heimdall logs path --run "$relay_run_id" --json | jq -er .run_dir)"
jq -e -s '
      ([.[] | select(.kind == "flow.data"
          and .data.boundary == "tls_plaintext.relay") | .seq] | unique) as $plaintext
      | any(.[]; .kind == "tls.client_hello"
        and .data.sni == "fixture.test"
        and (.data.alpn_offered | index("http/1.1"))
        and .data.parser_status == "parsed_versions_unavailable")
      and any(.[]; .kind == "tls.handshake"
        and .data.mode == "relay"
        and .data.peer_identity.verified
        and .data.version != "unknown"
        and .data.cipher != "unknown")
      and any(.[]; .kind == "http.request"
        and .data.parser == {"name":"heimdall-http1","version":"1"}
        and .data.method == "GET"
        and .data.scheme == "https"
        and .data.authority == "fixture.test:18444"
        and .data.path == "/"
        and (.data.source_seq | length) > 0
        and any(.data.headers[]; (.name | ascii_downcase) == "authorization"
          and .value == "[REDACTED]"))
      and any(.[]; .kind == "http.response"
        and .data.status == 200
        and (.data.source_seq | length) > 0)
      and all(.[] | select(.kind == "http.request" or .kind == "http.response");
          all(.data.source_seq[]; . as $seq | $plaintext | index($seq)))' \
  "$relay_run_dir"/events-*.jsonl >/dev/null
as_tester heimdall logs summary --run "$relay_run_id" --json \
  | jq -e '
      .contract == "heimdall.logs.summary/v1"
      and .state == "closed"
      and .complete
      and .sequence.contiguous
      and .sequence.missing_records == 0
      and .flows.opened >= 1
      and .flows.opened == .flows.closed
      and .flows.active == 0
      and .capture.by_boundary["tls_plaintext.relay"] >= 2
      and .tls.client_hellos >= 1
      and .tls.handshakes >= 1
      and .tls.errors == 0
      and .http.requests == 1
      and .http.responses == 1
      and .error_events.total == 0' >/dev/null

# Keep the two certificate trust boundaries distinguishable. An IP name fails
# upstream identity verification before Heimdall presents a leaf, while the
# second client reaches the verified upstream but rejects Heimdall's CA.
if as_tester heimdall --config /etc/heimdall-test/relay.toml run --policy direct -- \
  curl --cacert /etc/heimdall-test/upstream-ca.pem -fsS --max-time 5 \
    https://127.0.0.1:18444/ >/dev/null 2>&1; then
  echo "relay accepted an upstream certificate for the wrong identity" >&2
  exit 1
fi
upstream_cert_run_id="$(as_tester heimdall logs list --json | jq -er '.runs[0].run_id')"
upstream_cert_run_dir="$(as_tester heimdall logs path --run "$upstream_cert_run_id" --json | jq -er .run_dir)"
jq -e -s 'any(.[]; .kind == "tls.error"
      and .data.code == "tls_upstream_certificate_invalid"
      and .data.phase == "upstream_handshake"
      and (.data.peer_identity.verified | not))
    and any(.[]; .kind == "flow.close"
      and .data.error_code == "tls_upstream_certificate_invalid")' \
  "$upstream_cert_run_dir"/events-*.jsonl >/dev/null

if as_tester heimdall --config /etc/heimdall-test/relay.toml run --policy fake -- \
  curl -fsS --max-time 5 https://fixture.test:18444/ >/dev/null 2>&1; then
  echo "relay client unexpectedly trusted the unconfigured Heimdall CA" >&2
  exit 1
fi
downstream_cert_run_id="$(as_tester heimdall logs list --json | jq -er '.runs[0].run_id')"
downstream_cert_run_dir="$(as_tester heimdall logs path --run "$downstream_cert_run_id" --json | jq -er .run_dir)"
if ! jq -e -s 'any(.[]; .kind == "tls.error"
      and .data.code == "tls_downstream_closed_without_close_notify"
      and .data.phase == "stream"
      and .data.peer_identity.verified)
    and any(.[]; .kind == "flow.close"
      and .data.error_code == "tls_downstream_closed_without_close_notify")' \
  "$downstream_cert_run_dir"/events-*.jsonl >/dev/null; then
  jq -c 'select(.kind == "tls.error" or .kind == "flow.close")' \
    "$downstream_cert_run_dir"/events-*.jsonl >&2
  exit 1
fi
as_tester heimdall logs summary --run "$downstream_cert_run_id" --json \
  | jq -e '.tls.errors == 1
      and .error_events.by_code.tls_downstream_closed_without_close_notify == 1
      and .flows.failures_by_code.tls_downstream_closed_without_close_notify == 1
      and .flows.active == 0' >/dev/null

run_count_before_prune="$(as_tester heimdall logs list --json | jq '.runs | length')"
as_tester heimdall logs prune --keep-last 1 --max-total-bytes 1 --json \
  | jq -e '.contract == "heimdall.logs.prune/v1"
      and (.applied | not)
      and .total_bytes_before >= .total_bytes_after
      and (.limit_satisfied | not)
      and (.candidates | length) > 0
      and all(.candidates[]; .reason == "max_total_bytes")' >/dev/null
test "$(as_tester heimdall logs list --json | jq '.runs | length')" \
  -eq "$run_count_before_prune"
test ! -e /sys/fs/bpf/heimdall

if find /sys/fs/cgroup/user.slice -type d -name 'heimdall-cli-*' -print -quit \
  | grep -q .; then
  echo "heimdall CLI cgroup leaked after successful runs" >&2
  exit 1
fi

echo "heimdall VM acceptance OK"
