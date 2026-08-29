#!/usr/bin/env bash
set -euo pipefail

fixture=/opt/heimdall-acceptance/fixture.py
uid=$(id -u)
: "${HEIMDALL_EXPECTED_VERSION:?expected release version is required}"
export HOME=${HOME:-/home/tester}
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$uid}
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
export PATH=/usr/local/bin:/usr/bin:/bin

work_dir=$(mktemp -d)
fixture_pid=
cleanup() {
  if [[ -n "$fixture_pid" ]] && kill -0 "$fixture_pid" 2>/dev/null; then
    kill "$fixture_pid"
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "Ubuntu acceptance failed: $*" >&2
  exit 1
}

[[ $(uname -m) == x86_64 ]] || fail "guest architecture is not x86_64"
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || fail "cgroup v2 is not mounted"
systemctl --user show-environment >/dev/null
[[ $(heimdall --version) == "heimdall $HEIMDALL_EXPECTED_VERSION" ]]

if sudo --non-interactive true >/dev/null 2>&1; then
  fail "tester unexpectedly has broad passwordless sudo"
fi
sudo --non-interactive --list 2>/dev/null \
  | grep -F '/usr/local/bin/heimdall __setup-worker' >/dev/null \
  || fail "exact setup-worker authorization is missing"

if systemctl list-unit-files --no-legend --no-pager \
  | grep -E '^heimdall[^[:space:]]*[[:space:]]' >/dev/null; then
  fail "an installed Heimdall service exists"
fi
[[ ! -e /sys/fs/bpf/heimdall ]] || fail "a persistent Heimdall BPF pin exists"
[[ -z $(pgrep -x heimdall || true) ]] || fail "Heimdall was running before acceptance"

heimdall config validate --json | python3 "$fixture" verify-config
heimdall agent | python3 "$fixture" verify-agent

python3 "$fixture" serve >"$work_dir/fixture.log" 2>&1 &
fixture_pid=$!
for _ in $(seq 1 100); do
  if python3 "$fixture" tcp >/dev/null 2>&1 \
    && python3 "$fixture" udp >/dev/null 2>&1; then
    break
  fi
  sleep 0.02
done
kill -0 "$fixture_pid" 2>/dev/null || {
  cat "$work_dir/fixture.log" >&2
  fail "loopback fixture did not start"
}
python3 "$fixture" tcp >/dev/null
python3 "$fixture" udp >/dev/null
ss -Hlnptu | sort >"$work_dir/listeners-before"

[[ $(heimdall run --policy direct -- python3 "$fixture" tcp) == ubuntu-tcp-ok ]]
tcp_run_id=$(heimdall logs list --json | python3 "$fixture" latest-run)
heimdall logs query --run "$tcp_run_id" --jsonl \
  | python3 "$fixture" verify-events tcp 18080
heimdall logs verify --run "$tcp_run_id" --json \
  | python3 "$fixture" verify-log

[[ $(heimdall run --policy direct -- python3 "$fixture" udp) == ubuntu-udp:probe ]]
udp_run_id=$(heimdall logs list --json | python3 "$fixture" latest-run)
[[ "$udp_run_id" != "$tcp_run_id" ]]
heimdall logs query --run "$udp_run_id" --jsonl \
  | python3 "$fixture" verify-events udp 18082
heimdall logs verify --run "$udp_run_id" --json \
  | python3 "$fixture" verify-log

set +e
heimdall run --policy direct -- sh -c 'exit 42'
exit_status=$?
set -e
[[ $exit_status -eq 42 ]] || fail "wrapped exit status was $exit_status instead of 42"

heimdall run --policy direct -- sleep 2 &
active_job=$!
active_owner=
for _ in $(seq 1 100); do
  active_owner=$(pgrep -u "$uid" -x heimdall | head -n1 || true)
  [[ -n "$active_owner" ]] && break
  sleep 0.02
done
[[ -n "$active_owner" ]] || fail "foreground owner was not observable"
[[ -z $(pgrep -u 0 -x heimdall || true) ]] \
  || fail "setup worker retained root privileges after child start"
wait "$active_job"

while IFS= read -r run_id; do
  heimdall logs verify --run "$run_id" --json | python3 "$fixture" verify-log
done < <(heimdall logs list --json | python3 "$fixture" list-runs)

for _ in $(seq 1 100); do
  [[ -z $(pgrep -x heimdall || true) ]] && break
  sleep 0.02
done
[[ -z $(pgrep -x heimdall || true) ]] || fail "foreground processes survived run exit"
if find "/sys/fs/cgroup/user.slice/user-$uid.slice" -type d \
  -name 'heimdall-cli-*' -print -quit 2>/dev/null | grep -q .; then
  fail "a command cgroup survived run exit"
fi
[[ ! -e /sys/fs/bpf/heimdall ]] || fail "a persistent Heimdall BPF pin survived run exit"

ss -Hlnptu | sort >"$work_dir/listeners-after"
cmp "$work_dir/listeners-before" "$work_dir/listeners-after" \
  || fail "a listener survived run exit"

echo "heimdall Ubuntu acceptance OK"
