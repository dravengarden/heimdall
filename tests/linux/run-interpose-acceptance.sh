#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
cd "$repo_root"

[[ $(uname -s) == Linux ]] || {
  printf 'interpose native acceptance requires Linux\n' >&2
  exit 1
}

binary=${HEIMDALL_LINUX_BINARY:-$repo_root/target/release/heimdall}
[[ -x $binary ]] || {
  printf 'missing native Heimdall binary: %s\n' "$binary" >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-linux-interpose.XXXXXX")
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
    printf 'interpose fixture exited before readiness\n' >&2
    exit 1
  }
  sleep 0.05
done
[[ -s $ready ]] || {
  printf 'interpose fixture did not become ready\n' >&2
  exit 1
}

http_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_port"])' "$ready")
socks_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["socks_port"])' "$ready")
config=$test_root/config.toml
cat >"$config" <<EOF
version = 1

[execution]
backend = "interpose"

[proxy]
default_policy = "default"

[proxy.outbounds.default]
type = "socks5"
server = "127.0.0.1"
server_port = $socks_port
network = ["tcp"]

[proxy.policies.default.dns]
mode = "fake"

[proxy.policies.default.final]
tcp = { type = "route", outbound = "default" }
udp = { type = "reject", method = "refused" }

[capture]
mode = "off"

[decrypt]
mode = "off"
EOF

udp_source=$test_root/udp-reject.c
cat >"$udp_source" <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    struct sockaddr_in destination = {0};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9);
    destination.sin_addr.s_addr = htonl(0x7f000001u);
    int connected = socket(AF_INET, SOCK_DGRAM, 0);
    if (connected < 0) return 2;
    errno = 0;
    int connect_result = connect(
        connected, (const struct sockaddr *)&destination, sizeof(destination)
    );
    int connect_errno = errno;
    close(connected);
    if (connect_result != -1 || connect_errno != EACCES) return 3;

    int connectionless = socket(AF_INET, SOCK_DGRAM, 0);
    if (connectionless < 0) return 4;
    const char payload[] = "blocked";
    errno = 0;
    ssize_t send_result = sendto(
        connectionless,
        payload,
        sizeof(payload),
        0,
        (const struct sockaddr *)&destination,
        sizeof(destination)
    );
    int send_errno = errno;
    close(connectionless);
    return send_result == -1 && send_errno == EACCES ? 0 : 5;
}
EOF
udp_client=$test_root/udp-reject
"${CC:-cc}" -O2 -Wall -Wextra -Werror "$udp_source" -o "$udp_client"

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
assert value["execution"]["backend"] == "interpose"
assert value["execution"]["configured_backend"] == "interpose"
assert value["execution"]["scope"] == "interposed_dynamic_calls"
assert value["capabilities"]["scope"]["strict_command_scope"] is False
assert value["capabilities"]["scope"]["client_can_bypass"] is True
assert value["capabilities"]["udp"]["connected"] is False
assert value["capabilities"]["decrypt"]["modes"] == ["off"]
assert value["actions"]["execute_prefix"][-5:] == [
    "--backend", "interpose", "--policy", "default", "--",
]
' "$agent_json"
stdout=$test_root/stdout
stderr=$test_root/stderr
if ! XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- \
  curl --fail --silent --show-error "http://fixture.test:$http_port/" \
  >"$stdout" 2>"$stderr"; then
  printf 'Linux interpose curl acceptance failed:\n' >&2
  sed -n '1,160p' "$stderr" >&2
  exit 1
fi
grep -Fxq 'heimdall-fixture-ok' "$stdout"
grep -Fq 'backend=interpose scope=interposed_dynamic_calls failure_boundary=interposed_calls_only' "$stderr"
python3 -c '
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert any(row["host"] == "fixture.test" and row["port"] == int(sys.argv[2]) for row in rows)
' "$fixture_log" "$http_port"

manifest=$(find "$state_home/heimdall/runs" -name run.json -type f -print -quit)
[[ -n $manifest ]] || {
  printf 'interpose did not create a run manifest\n' >&2
  exit 1
}
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$manifest")
python3 -c '
import json, pathlib, sys
manifest_path = pathlib.Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
assert manifest["backend"] == "interpose"
assert manifest["state"] == "closed"
assert manifest["result"]["exit_code"] == 0
assert manifest["result"]["complete"] is False
events = []
for segment in manifest["segments"]:
    with (manifest_path.parent / segment["file"]).open(encoding="utf-8") as stream:
        events.extend(json.loads(line) for line in stream)
assert any(event["kind"] == "policy.decision" and event["data"]["source"] == {
    "backend": "interpose", "scope": "interposed_dynamic_calls"
} for event in events)
assert any(event["kind"] == "flow.close" and event["data"]["status"] == "complete" for event in events)
' "$manifest"
verify_json=$(XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" logs verify --run "$run_id" --json)
python3 -c 'import json,sys; assert json.loads(sys.argv[1])["valid"] is True' "$verify_json"

if find "$runtime_dir" -name '*libheimdall_interpose.so' -type f -print -quit | grep -q .; then
  printf 'interpose left its materialized library behind\n' >&2
  exit 1
fi

udp_state=$test_root/us
udp_runtime=$test_root/ur
mkdir -p "$udp_state" "$udp_runtime"
XDG_STATE_HOME="$udp_state" XDG_RUNTIME_DIR="$udp_runtime" \
  "$binary" --config "$config" run -- "$udp_client"

set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- /bin/sh -c 'exit 23' >/dev/null 2>&1
exit_code=$?
set -e
[[ $exit_code -eq 23 ]] || {
  printf 'interpose did not preserve exit 23: %s\n' "$exit_code" >&2
  exit 1
}

printf 'Linux interpose native acceptance OK\n'
