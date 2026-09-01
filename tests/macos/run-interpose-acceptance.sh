#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
cd "$repo_root"

[[ $(uname -s) == Darwin ]] || {
  printf 'interpose native acceptance requires macOS\n' >&2
  exit 1
}
[[ $(uname -m) == arm64 ]] || {
  printf 'interpose native acceptance requires Apple silicon\n' >&2
  exit 1
}

binary=${HEIMDALL_MACOS_BINARY:-$repo_root/target/release/heimdall}
[[ -x $binary ]] || {
  printf 'missing native Heimdall binary: %s\n' "$binary" >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-macos-interpose.XXXXXX")
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

client_source=$test_root/client.c
cat >"$client_source" <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--exit-23") == 0) return 23;
    if (argc == 2 && strcmp(argv[1], "--udp-reject") == 0) {
        struct sockaddr_in destination = {0};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(9);
        destination.sin_addr.s_addr = htonl(0x7f000001u);
        int connected = socket(AF_INET, SOCK_DGRAM, 0);
        if (connected < 0) return 9;
        errno = 0;
        int connect_result = connect(
            connected, (const struct sockaddr *)&destination, sizeof(destination)
        );
        int connect_errno = errno;
        close(connected);
        if (connect_result != -1 || connect_errno != EACCES) return 10;

        int connectionless = socket(AF_INET, SOCK_DGRAM, 0);
        if (connectionless < 0) return 11;
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
        return send_result == -1 && send_errno == EACCES ? 0 : 12;
    }
    if (argc != 2) return 2;
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("fixture.test", argv[1], &hints, &addresses) != 0) return 3;
    int fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    if (fd < 0) return 4;
    if (connect(fd, addresses->ai_addr, addresses->ai_addrlen) != 0) return 5;
    freeaddrinfo(addresses);
    const char request[] = "GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n";
    if (send(fd, request, sizeof(request) - 1, 0) < 0) return 6;
    char response[4096] = {0};
    ssize_t length = recv(fd, response, sizeof(response) - 1, 0);
    close(fd);
    if (length <= 0) return 7;
    fwrite(response, 1, (size_t)length, stdout);
    return strstr(response, "heimdall-fixture-ok") == NULL ? 8 : 0;
}
EOF
client=$test_root/client
xcrun clang -O2 -Wall -Wextra -Werror "$client_source" -o "$client"

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
assert value["execution"]["scope"] == "interposed_dynamic_calls"
assert value["capabilities"]["scope"]["strict_command_scope"] is False
assert value["capabilities"]["scope"]["client_can_bypass"] is True
assert value["capabilities"]["udp"]["connected"] is False
assert value["actions"]["execute_prefix"][-5:] == [
    "--backend", "interpose", "--policy", "default", "--",
]
' "$agent_json"

stdout=$test_root/stdout
stderr=$test_root/stderr
if ! XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- "$client" "$http_port" \
  >"$stdout" 2>"$stderr"; then
  printf 'macOS interpose TCP acceptance failed:\n' >&2
  sed -n '1,160p' "$stderr" >&2
  exit 1
fi
grep -Fq 'heimdall-fixture-ok' "$stdout"
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
' "$manifest"
verify_json=$(XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" logs verify --run "$run_id" --json)
python3 -c 'import json,sys; assert json.loads(sys.argv[1])["valid"] is True' "$verify_json"

if find "$runtime_dir" -name '*libheimdall_interpose.dylib' -type f -print -quit | grep -q .; then
  printf 'interpose left its materialized library behind\n' >&2
  exit 1
fi

udp_state=$test_root/us
udp_runtime=$test_root/ur
mkdir -p "$udp_state" "$udp_runtime"
XDG_STATE_HOME="$udp_state" XDG_RUNTIME_DIR="$udp_runtime" \
  "$binary" --config "$config" run -- "$client" --udp-reject

set +e
XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- "$client" --exit-23 >/dev/null 2>&1
exit_code=$?
set -e
[[ $exit_code -eq 23 ]] || {
  printf 'interpose did not preserve exit 23: %s\n' "$exit_code" >&2
  exit 1
}

set +e
protected_error=$(XDG_STATE_HOME="$state_home" XDG_RUNTIME_DIR="$runtime_dir" \
  "$binary" --config "$config" run -- /usr/bin/true 2>&1)
protected_exit=$?
set -e
[[ $protected_exit -ne 0 ]] || {
  printf 'interpose accepted a SIP-protected executable\n' >&2
  exit 1
}
grep -Fq 'SIP-protected' <<<"$protected_error"

printf 'macOS interpose native acceptance OK\n'
