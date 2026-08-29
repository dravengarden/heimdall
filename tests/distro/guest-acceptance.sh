#!/usr/bin/env bash
set -euo pipefail

fixture=/opt/heimdall-acceptance/fixture.py
runtime_config=/opt/heimdall-acceptance/runtime.toml
relay_config=/opt/heimdall-acceptance/relay.toml
benchmark_script=/opt/heimdall-acceptance/benchmark.py
benchmark_config=/opt/heimdall-acceptance/benchmark.toml
benchmark_relay_config=/opt/heimdall-acceptance/benchmark-relay.toml
benchmark_no_capture_config=/opt/heimdall-acceptance/benchmark-no-capture.toml
benchmark_capture_config=/opt/heimdall-acceptance/benchmark-capture.toml
benchmark_relay_capture_config=/opt/heimdall-acceptance/benchmark-relay-capture.toml
udp_throughput=/opt/heimdall-acceptance/udp-throughput.py
socks_fixture=/opt/heimdall-acceptance/socks5-fixture.py
tls_dir=/opt/heimdall-acceptance/tls
uid=$(id -u)
: "${HEIMDALL_EXPECTED_VERSION:?expected release version is required}"
run_benchmark=${HEIMDALL_RUN_BENCHMARK:-0}
benchmark_iterations=${HEIMDALL_BENCHMARK_ITERATIONS:-3}
export HOME=${HOME:-/home/tester}
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$uid}
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
export PATH=/usr/local/bin:/usr/bin:/bin

work_dir=$(mktemp -d)
fixture_pid=
socks_pid=
cleanup() {
  if [[ -n "$socks_pid" ]] && kill -0 "$socks_pid" 2>/dev/null; then
    kill "$socks_pid"
    wait "$socks_pid" 2>/dev/null || true
  fi
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

find_run_owner() {
  local marker=$1 candidate cmdline
  for candidate in $(pgrep -u "$uid" -x heimdall || true); do
    cmdline=$(tr '\0' ' ' <"/proc/$candidate/cmdline")
    if [[ $cmdline == *" --no-reentry "* && $cmdline == *"$marker"* ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

find_setup_helper() {
  local candidate cmdline
  for candidate in $(pgrep -u "$uid" -x heimdall || true); do
    cmdline=$(tr '\0' ' ' <"/proc/$candidate/cmdline")
    if [[ $cmdline == *" __setup-worker"* ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

assert_signal_forwarded() {
  local signal_name=$1 signal_number=$2 expected_status=$3
  local marker="signal-$signal_name" wrapper owner run_id status

  heimdall run --policy direct -- sh -c 'exec sleep 30' "$marker" &
  wrapper=$!
  owner=
  run_id=
  for _ in $(seq 1 200); do
    owner=$(find_run_owner "$marker" || true)
    run_id=$(heimdall logs list --json 2>/dev/null \
      | python3 "$fixture" latest-running-run 2>/dev/null || true)
    [[ -n $owner && -n $run_id ]] && break
    sleep 0.02
  done
  [[ -n $owner ]] || fail "$signal_name foreground owner was not observable"
  [[ -n $run_id ]] || fail "$signal_name run was not observable"

  kill "-$signal_name" "$owner"
  set +e
  wait "$wrapper"
  status=$?
  set -e
  [[ $status -eq $expected_status ]] \
    || fail "$signal_name returned $status instead of $expected_status"
  heimdall logs verify --run "$run_id" --json \
    | python3 "$fixture" verify-log closed
  heimdall logs query --run "$run_id" --jsonl \
    | python3 "$fixture" verify-close "$expected_status" "$signal_number"
}

[[ $(uname -m) == x86_64 ]] || fail "guest architecture is not x86_64"
[[ $run_benchmark == 0 || $run_benchmark == 1 ]] \
  || fail "HEIMDALL_RUN_BENCHMARK must be 0 or 1"
if [[ ! $benchmark_iterations =~ ^[0-9]+$ ]] \
  || ((benchmark_iterations < 1 || benchmark_iterations > 20)); then
  fail "HEIMDALL_BENCHMARK_ITERATIONS must be between 1 and 20"
fi
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

# Why: sudoers authorizes one immutable installation path plus one private
# subcommand. A copied binary must fail before child execution rather than
# widening the privilege boundary or prompting on a headless agent run.
cp /usr/local/bin/heimdall "$work_dir/unauthorized-heimdall"
set +e
authorization_failure=$("$work_dir/unauthorized-heimdall" \
  run --policy direct -- true 2>&1)
authorization_status=$?
set -e
[[ $authorization_status -ne 0 ]] \
  || fail "a copied binary bypassed exact setup-worker authorization"
grep -F 'non-interactive setup authorization must allow exactly' \
  <<<"$authorization_failure" >/dev/null \
  || fail "authorization denial did not provide the stable repair message"

python3 "$fixture" serve "$tls_dir/server.pem" "$tls_dir/server-key.pem" \
  >"$work_dir/fixture.log" 2>&1 &
fixture_pid=$!
for _ in $(seq 1 100); do
  if python3 "$fixture" tcp >/dev/null 2>&1 \
    && python3 "$fixture" udp >/dev/null 2>&1 \
    && python3 "$fixture" tls "$tls_dir/upstream-ca.pem" >/dev/null 2>&1; then
    break
  fi
  sleep 0.02
done
kill -0 "$fixture_pid" 2>/dev/null || {
  cat "$work_dir/fixture.log" >&2
  fail "loopback fixture did not start"
}
if [[ $run_benchmark == 1 ]]; then
  python3 "$socks_fixture" >"$work_dir/socks.log" 2>&1 &
  socks_pid=$!
  for _ in $(seq 1 100); do
    ss -Hlnpt | grep -Eq '127\.0\.0\.1:1080\b' && break
    sleep 0.02
  done
  kill -0 "$socks_pid" 2>/dev/null || {
    cat "$work_dir/socks.log" >&2
    fail "SOCKS5 benchmark fixture did not start"
  }
  ss -Hlnpt | grep -Eq '127\.0\.0\.1:1080\b' \
    || fail "SOCKS5 benchmark fixture did not listen"
fi
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
heimdall run --policy direct -- sh -c 'kill -TERM $$'
self_signal_status=$?
set -e
[[ $exit_status -eq 42 ]] || fail "wrapped exit status was $exit_status instead of 42"
[[ $self_signal_status -eq 143 ]] \
  || fail "self-signaled child returned $self_signal_status instead of 143"

# The immediate shell exits before its nested background process. Heimdall
# must retain interception and delay run.close until that descendant exits.
descendant_output="$work_dir/descendant.out"
heimdall run --policy direct -- sh -c \
  "(sleep 0.2; python3 '$fixture' tcp >'$descendant_output') &" descendant
[[ $(<"$descendant_output") == ubuntu-tcp-ok ]] \
  || fail "background descendant did not complete through Heimdall"
descendant_run_id=$(heimdall logs list --json | python3 "$fixture" latest-run)
heimdall logs query --run "$descendant_run_id" --jsonl \
  | python3 "$fixture" verify-events tcp 18080

# Each forwarded signal must reach the immediate child while the foreground
# owner remains alive long enough to finalize append-only evidence.
assert_signal_forwarded HUP 1 129
assert_signal_forwarded INT 2 130
assert_signal_forwarded QUIT 3 131
assert_signal_forwarded TERM 15 143

# Two runs must own distinct cgroups and logs without registering a daemon.
cgroup_root="/sys/fs/cgroup/user.slice/user-$uid.slice"
cgroup_baseline=$(find "$cgroup_root" -type d -name 'heimdall-cli-*' | wc -l)
heimdall run --policy direct -- sh -c 'exec sleep 3' concurrent-one &
parallel_one=$!
heimdall run --policy direct -- sh -c 'exec sleep 3' concurrent-two &
parallel_two=$!
parallel_ready=false
for _ in $(seq 1 200); do
  mapfile -t parallel_run_ids < <(
    heimdall logs list --json | python3 "$fixture" running-runs
  )
  cgroup_count=$(find "$cgroup_root" -type d -name 'heimdall-cli-*' | wc -l)
  if [[ ${#parallel_run_ids[@]} -ge 2 \
    && $cgroup_count -ge $((cgroup_baseline + 2)) ]]; then
    parallel_ready=true
    break
  fi
  sleep 0.02
done
[[ $parallel_ready == true ]] \
  || fail "two concurrent runs did not acquire isolated cgroups and logs"
[[ ${parallel_run_ids[0]} != "${parallel_run_ids[1]}" ]] \
  || fail "concurrent runs reused a run identifier"
[[ -z $(pgrep -u 0 -x heimdall || true) ]] \
  || fail "a concurrent setup helper retained root privileges"
wait "$parallel_one"
wait "$parallel_two"
for run_id in "${parallel_run_ids[@]:0:2}"; do
  heimdall logs verify --run "$run_id" --json \
    | python3 "$fixture" verify-log closed
done
for _ in $(seq 1 100); do
  cgroup_count=$(find "$cgroup_root" -type d -name 'heimdall-cli-*' | wc -l)
  [[ $cgroup_count -eq $cgroup_baseline ]] && break
  sleep 0.02
done
[[ $cgroup_count -eq $cgroup_baseline ]] \
  || fail "a concurrent command cgroup survived run exit"

# SIGKILL cannot be forwarded or logged by the owner. Its unprivileged setup
# helper must detect socket EOF, kill the workload cgroup, remove it, and leave
# the append-only run available for explicit recovery.
heimdall run --policy direct -- sh -c 'exec sleep 30' parent-death &
parent_wrapper=$!
parent_owner=
parent_helper=
parent_run_id=
parent_cgroup=
for _ in $(seq 1 200); do
  parent_owner=$(find_run_owner parent-death || true)
  parent_helper=$(find_setup_helper || true)
  parent_run_id=$(heimdall logs list --json 2>/dev/null \
    | python3 "$fixture" latest-running-run 2>/dev/null || true)
  if [[ -n $parent_owner ]]; then
    parent_cgroup=$(find "$cgroup_root" -type d \
      -name "heimdall-cli-$parent_owner-*" -print -quit)
  fi
  [[ -n $parent_owner && -n $parent_helper && -n $parent_run_id \
    && -n $parent_cgroup && -s $parent_cgroup/cgroup.procs ]] && break
  sleep 0.02
done
[[ -n $parent_owner ]] || fail "parent-death owner was not observable"
[[ -n $parent_helper ]] || fail "parent-death setup helper was not observable"
[[ -n $parent_run_id ]] || fail "parent-death run was not observable"
[[ -n $parent_cgroup ]] || fail "parent-death cgroup was not observable"
mapfile -t parent_workloads <"$parent_cgroup/cgroup.procs"
kill -KILL "$parent_owner"
wait "$parent_wrapper" 2>/dev/null || true
parent_cleaned=false
for _ in $(seq 1 500); do
  workloads_alive=false
  for process in "${parent_workloads[@]}"; do
    [[ -e /proc/$process ]] && workloads_alive=true
  done
  if [[ ! -e /proc/$parent_helper && ! -e $parent_cgroup \
    && $workloads_alive == false ]]; then
    parent_cleaned=true
    break
  fi
  sleep 0.02
done
[[ $parent_cleaned == true ]] \
  || fail "parent death left its helper, workload, or cgroup alive"
heimdall logs recover --run "$parent_run_id" --json \
  | python3 "$fixture" verify-recovery-preview
heimdall logs recover --run "$parent_run_id" --apply --json \
  | python3 "$fixture" verify-recovery-apply
heimdall logs verify --run "$parent_run_id" --json \
  | python3 "$fixture" verify-log failed

# Runtime and relay TLS remain foreground run modes on a conventional Ubuntu
# OpenSSL layout. Selecting either mode is accepted only after its emitted
# evidence proves the actual plaintext boundary.
heimdall --config "$runtime_config" config validate --json \
  | python3 "$fixture" verify-config
heimdall --config "$runtime_config" agent \
  | python3 "$fixture" verify-agent runtime
[[ $(heimdall --config "$runtime_config" run --policy direct -- \
  python3 "$fixture" tls "$tls_dir/upstream-ca.pem") == ubuntu-tls-ok ]]
runtime_run_id=$(heimdall logs list --json | python3 "$fixture" latest-run)
runtime_run_dir=$(heimdall logs path --run "$runtime_run_id" --json \
  | python3 "$fixture" run-dir)
heimdall logs verify --run "$runtime_run_id" --json \
  | python3 "$fixture" verify-log closed
python3 "$fixture" verify-tls runtime "$runtime_run_dir"

relay_dir=$HOME/.local/state/heimdall/acceptance-ca
rm -rf "$relay_dir"
mkdir -p "$relay_dir"
relay_ca_report=$(heimdall tls init-ca --dir "$relay_dir" --json)
python3 "$fixture" verify-ca <<<"$relay_ca_report"
[[ $(stat -c '%a' "$relay_dir/ca-key.pem") == 600 ]] \
  || fail "relay CA key permissions are not 0600"
heimdall --config "$relay_config" config validate --json \
  | python3 "$fixture" verify-config
heimdall --config "$relay_config" agent \
  | python3 "$fixture" verify-agent relay
[[ $(heimdall --config "$relay_config" run --policy direct -- \
  python3 "$fixture" tls "$relay_dir/ca.pem") == ubuntu-tls-ok ]]
relay_run_id=$(heimdall logs list --json | python3 "$fixture" latest-run)
relay_run_dir=$(heimdall logs path --run "$relay_run_id" --json \
  | python3 "$fixture" run-dir)
heimdall logs verify --run "$relay_run_id" --json \
  | python3 "$fixture" verify-log closed
python3 "$fixture" verify-tls relay "$relay_run_dir"

if [[ $run_benchmark == 1 ]]; then
  benchmark_ca_dir=$HOME/.local/state/heimdall/benchmark-ca
  rm -rf "$benchmark_ca_dir"
  benchmark_json=$(python3 "$benchmark_script" \
    --iterations "$benchmark_iterations" \
    --scope disposable-ubuntu-vm \
    --config "$benchmark_config" \
    --relay-config "$benchmark_relay_config" \
    --no-capture-config "$benchmark_no_capture_config" \
    --capture-config "$benchmark_capture_config" \
    --relay-capture-config "$benchmark_relay_capture_config" \
    --relay-ca-dir "$benchmark_ca_dir" \
    --fixture "$fixture" \
    --udp-throughput "$udp_throughput" \
    --udp-response-prefix ubuntu-udp: \
    --proxy-policy proxy \
    --rss-source procfs)
  python3 "$fixture" verify-benchmark <<<"$benchmark_json"
  printf 'HEIMDALL_BENCHMARK_JSON=%s\n' "$benchmark_json"
fi

while IFS= read -r run_id; do
  heimdall logs verify --run "$run_id" --json \
    | python3 "$fixture" verify-log closed-or-failed
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
