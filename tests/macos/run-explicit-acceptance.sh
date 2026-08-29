#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
cd "$repo_root"

[[ $(uname -s) == Darwin ]] || {
  printf 'macos-explicit native acceptance requires macOS\n' >&2
  exit 1
}
[[ $(uname -m) == arm64 ]] || {
  printf 'macos-explicit native acceptance requires Apple silicon\n' >&2
  exit 1
}

binary=${HEIMDALL_MACOS_BINARY:-$repo_root/target/release/heimdall}
[[ -x $binary ]] || {
  printf 'missing native Heimdall binary: %s\n' "$binary" >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-macos-explicit.XXXXXX")
fixture_pid=
cleanup() {
  if [[ -n $fixture_pid ]]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

ready=$test_root/fixture.json
fixture_log=$test_root/socks.jsonl
python3 tests/macos/fixture.py --ready "$ready" --log "$fixture_log" &
fixture_pid=$!
for _ in $(seq 1 100); do
  [[ -s $ready ]] && break
  kill -0 "$fixture_pid" 2>/dev/null || {
    printf 'macOS fixture exited before readiness\n' >&2
    exit 1
  }
  sleep 0.05
done
[[ -s $ready ]] || {
  printf 'macOS fixture did not become ready\n' >&2
  exit 1
}

http_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_port"])' "$ready")
socks_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_port"])' "$ready")
config=$test_root/config.toml
cat >"$config" <<EOF
version = 1

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
assert value["ready"] is True
assert value["execution"]["backend"] == "macos-explicit"
assert value["capabilities"]["scope"]["strict_command_scope"] is False
assert value["capabilities"]["udp"]["connected"] is False
assert value["actions"]["execute_prefix"][-3:] == ["--policy", "default", "--"]
' "$agent_json"

stdout=$test_root/stdout
stderr=$test_root/stderr
if ! XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run --backend macos-explicit -- \
  curl --fail --silent --show-error "http://fixture.test:$http_port/" \
  >"$stdout" 2>"$stderr"; then
  printf 'macos-explicit curl acceptance failed:\n' >&2
  sed -n '1,120p' "$stderr" >&2
  exit 1
fi
grep -Fxq 'heimdall-macos-explicit-ok' "$stdout"
grep -Fq 'backend=macos-explicit scope=cooperative_environment ALL_PROXY=socks5h://127.0.0.1:' "$stderr"
python3 -c '
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert any(row["host"] == "fixture.test" and row["port"] == int(sys.argv[2]) for row in rows)
' "$fixture_log" "$http_port"

manifest=$(find "$state_home/heimdall/runs" -name run.json -type f | head -n 1)
[[ -n $manifest ]] || {
  printf 'macos-explicit did not create a run manifest\n' >&2
  exit 1
}
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$manifest")
python3 -c '
import json, pathlib, sys
manifest_path = pathlib.Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
assert manifest["backend"] == "macos-explicit"
assert manifest["state"] == "closed"
assert manifest["result"]["exit_code"] == 0
assert manifest["result"]["complete"] is False
events = []
for segment in manifest["segments"]:
    with (manifest_path.parent / segment["file"]).open(encoding="utf-8") as stream:
        events.extend(json.loads(line) for line in stream)
assert any(event["kind"] == "policy.decision" and event["data"]["source"] == {
    "backend": "macos-explicit", "scope": "cooperative_environment"
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
  "$binary" --config "$config" run --backend macos-explicit -- \
  /bin/sh -c 'exit 23' >/dev/null 2>&1
exit_code=$?
set -e
[[ $exit_code -eq 23 ]] || {
  printf 'macos-explicit did not preserve exit 23: %s\n' "$exit_code" >&2
  exit 1
}

marker=$test_root/implicit-backend-ran
set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- /usr/bin/touch "$marker" \
  >/dev/null 2>&1
implicit_exit=$?
set -e
[[ $implicit_exit -ne 0 && ! -e $marker ]] || {
  printf 'macOS run selected the reduced backend without explicit authorization\n' >&2
  exit 1
}

printf 'macos-explicit native acceptance OK\n'
