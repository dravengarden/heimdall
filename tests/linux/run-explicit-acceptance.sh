#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
cd "$repo_root"

[[ $(uname -s) == Linux ]] || {
  printf 'explicit native acceptance requires Linux\n' >&2
  exit 1
}

binary=${HEIMDALL_LINUX_BINARY:-$repo_root/target/release/heimdall}
[[ -x $binary ]] || {
  printf 'missing native Heimdall binary: %s\n' "$binary" >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-linux-explicit.XXXXXX")
fixture_pid=
cleanup() {
  if [[ -n $fixture_pid ]]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  find "$test_root" -depth -delete
}
trap cleanup EXIT

ready=$test_root/fixture.json
fixture_log=$test_root/socks.jsonl
python3 tests/macos/fixture.py --ready "$ready" --log "$fixture_log" &
fixture_pid=$!
for _ in $(seq 1 100); do
  [[ -s $ready ]] && break
  kill -0 "$fixture_pid" 2>/dev/null || {
    printf 'explicit fixture exited before readiness\n' >&2
    exit 1
  }
  sleep 0.05
done
[[ -s $ready ]] || {
  printf 'explicit fixture did not become ready\n' >&2
  exit 1
}

http_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_port"])' "$ready")
socks_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_port"])' "$ready")
config=$test_root/config.toml
cat >"$config" <<EOF
version = 1

[execution]
backend = "explicit"

[proxy]
default_policy = "default"

[proxy.outbounds.default]
type = "socks5"
server = "127.0.0.1"
server_port = $socks_port
network = ["tcp"]

[proxy.policies.default.dns]
mode = "system"

[proxy.policies.default.final]
tcp = { type = "route", outbound = "default" }
udp = { type = "reject", method = "refused" }

[capture]
mode = "off"

[decrypt]
mode = "off"
EOF

state_home=$test_root/state
runtime_dir=$test_root/runtime
mkdir -p "$state_home" "$runtime_dir"
agent_json=$(XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" agent)
python3 -c '
import json, sys
value = json.loads(sys.argv[1])
assert value["contract"] == "heimdall.agent/v10"
assert value["ready"] is True
assert value["execution"]["backend"] == "explicit"
assert value["execution"]["configured_backend"] == "explicit"
assert value["execution"]["scope"] == "cooperative_proxy_environment"
assert value["execution"]["privilege_setup"] == "none"
assert value["execution"]["daemon_required"] is False
assert value["capabilities"]["scope"]["strict_command_scope"] is False
assert value["capabilities"]["scope"]["client_can_bypass"] is True
assert value["capabilities"]["udp"]["connected"] is False
assert value["capabilities"]["decrypt"]["modes"] == ["off"]
assert value["actions"]["execute_prefix"][-5:] == [
    "--backend", "explicit", "--policy", "default", "--",
]
' "$agent_json"

# Why: explicit must remain a direct foreground path even when the host would
# otherwise qualify for the Linux systemd/cgroup re-entry used by eBPF.
reentry_marker=$test_root/systemd-run-called
fake_bin=$test_root/bin
mkdir -p "$fake_bin"
cat >"$fake_bin/systemd-run" <<EOF
#!/usr/bin/env bash
touch "$reentry_marker"
exit 99
EOF
chmod +x "$fake_bin/systemd-run"

stdout=$test_root/stdout
stderr=$test_root/stderr
if ! PATH="$fake_bin:$PATH" XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- \
  curl --fail --silent --show-error "http://fixture.test:$http_port/" \
  >"$stdout" 2>"$stderr"; then
  printf 'Linux explicit curl acceptance failed:\n' >&2
  sed -n '1,160p' "$stderr" >&2
  exit 1
fi
[[ ! -e $reentry_marker ]] || {
  printf 'explicit unexpectedly entered the systemd/cgroup path\n' >&2
  exit 1
}
grep -Fxq 'heimdall-fixture-ok' "$stdout"
grep -Fq 'backend=explicit scope=cooperative_environment ALL_PROXY=socks5h://127.0.0.1:' "$stderr"
python3 -c '
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert any(row["host"] == "fixture.test" and row["port"] == int(sys.argv[2]) for row in rows)
' "$fixture_log" "$http_port"

manifest=$(find "$state_home/heimdall/runs" -name run.json -type f -print -quit)
[[ -n $manifest ]] || {
  printf 'explicit did not create a run manifest\n' >&2
  exit 1
}
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$manifest")
python3 -c '
import json, pathlib, sys
manifest_path = pathlib.Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
assert manifest["backend"] == "explicit"
assert manifest["state"] == "closed"
assert manifest["result"]["exit_code"] == 0
assert manifest["result"]["complete"] is False
events = []
for segment in manifest["segments"]:
    with (manifest_path.parent / segment["file"]).open(encoding="utf-8") as stream:
        events.extend(json.loads(line) for line in stream)
assert any(event["kind"] == "policy.decision" and event["data"]["source"] == {
    "backend": "explicit", "scope": "cooperative_environment"
} for event in events)
assert any(event["kind"] == "flow.close" and event["data"]["status"] == "complete" for event in events)
' "$manifest"
verify_json=$(XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" logs verify --run "$run_id" --json)
python3 -c 'import json,sys; assert json.loads(sys.argv[1])["valid"] is True' "$verify_json"

proxy_port=$(python3 -c '
import re, sys
value = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"ALL_PROXY=socks5h://127[.]0[.]0[.]1:([0-9]+)", value)
assert match
print(match.group(1))
' "$stderr")
python3 -c '
import socket, sys
sock = socket.socket()
sock.settimeout(0.2)
assert sock.connect_ex(("127.0.0.1", int(sys.argv[1]))) != 0
' "$proxy_port"

set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- /bin/sh -c 'exit 23' >/dev/null 2>&1
exit_code=$?
set -e
[[ $exit_code -eq 23 ]] || {
  printf 'explicit did not preserve exit 23: %s\n' "$exit_code" >&2
  exit 1
}

missing_config=$test_root/missing-backend.toml
sed '/^\[execution\]$/,/^$/d' "$config" >"$missing_config"
missing_marker=$test_root/missing-backend-ran
set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$missing_config" run -- /usr/bin/touch "$missing_marker" \
  >/dev/null 2>&1
missing_exit=$?
set -e
[[ $missing_exit -ne 0 && ! -e $missing_marker ]] || {
  printf 'Linux run accepted a config without execution.backend\n' >&2
  exit 1
}

fake_dns_config=$test_root/fake-dns.toml
sed 's/mode = "system"/mode = "fake"/' "$config" >"$fake_dns_config"
unsupported_marker=$test_root/unsupported-policy-ran
set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$fake_dns_config" run -- /usr/bin/touch "$unsupported_marker" \
  >/dev/null 2>&1
unsupported_exit=$?
set -e
[[ $unsupported_exit -ne 0 && ! -e $unsupported_marker ]] || {
  printf 'Linux explicit executed a command outside its DNS boundary\n' >&2
  exit 1
}

keep_marker=$test_root/keep-cgroup-ran
set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run --keep-cgroup -- /usr/bin/touch "$keep_marker" \
  >/dev/null 2>&1
keep_exit=$?
set -e
[[ $keep_exit -ne 0 && ! -e $keep_marker ]] || {
  printf 'Linux explicit accepted the eBPF-only --keep-cgroup flag\n' >&2
  exit 1
}

printf 'Linux explicit native acceptance OK\n'
