#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

fail() {
  echo "${distro_id:-Cloud} VM acceptance failed: $*" >&2
  exit 1
}

: "${HEIMDALL_DISTRO_ID:?enter a distro acceptance Nix shell}"
: "${HEIMDALL_RESOLVER_PROFILE:?resolver acceptance profile is required}"
: "${HEIMDALL_CLOUD_IMAGE:?cloud image path is required}"
distro_id=$HEIMDALL_DISTRO_ID
resolver_profile=$HEIMDALL_RESOLVER_PROFILE
cloud_image=$HEIMDALL_CLOUD_IMAGE
case "$distro_id" in
  ubuntu | debian) ;;
  *) fail "unsupported distribution identifier: $distro_id" ;;
esac
case "$resolver_profile" in
  apparmor-restricted | private-mount) ;;
  *) fail "unsupported resolver profile: $resolver_profile" ;;
esac
[[ $(uname -s) == Linux ]] || fail "the execution host is not Linux"
[[ $(uname -m) == x86_64 ]] || fail "the execution host is not x86_64"
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] \
  || fail "read/write access to /dev/kvm is required"
[[ -f "$cloud_image" ]] || fail "the pinned cloud image is missing"
run_benchmark=${HEIMDALL_DISTRO_BENCHMARK:-0}
benchmark_iterations=${HEIMDALL_DISTRO_BENCHMARK_ITERATIONS:-3}
[[ $run_benchmark == 0 || $run_benchmark == 1 ]] \
  || fail "HEIMDALL_DISTRO_BENCHMARK must be 0 or 1"
if [[ ! $benchmark_iterations =~ ^[0-9]+$ ]] \
  || ((benchmark_iterations < 1 || benchmark_iterations > 20)); then
  fail "HEIMDALL_DISTRO_BENCHMARK_ITERATIONS must be between 1 and 20"
fi
vm_memory_mib=2048
if [[ $run_benchmark == 1 ]]; then
  # Why: 50 isolated foreground sessions turn a 2 GiB compatibility guest into
  # a memory-pressure test instead of measuring the data path.
  vm_memory_mib=8192
fi

for command in cloud-localds ip nix python3 qemu-img qemu-system-x86_64 scp ssh ssh-keygen; do
  command -v "$command" >/dev/null || fail "required command is missing: $command"
done

work_dir=$(mktemp -d)
qemu_pid=
phase=host-preflight
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid"
    wait "$qemu_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM
diagnose_error() {
  local status=$?
  trap - ERR
  echo "$distro_id VM acceptance failed during $phase (exit $status)" >&2
  if [[ $phase == qemu-boot || $phase == cloud-init ]] \
    && [[ -f $work_dir/serial.log ]]; then
    if [[ -s $work_dir/qemu.log ]]; then
      tail -n 40 "$work_dir/qemu.log" >&2 || true
    fi
    tail -n 80 "$work_dir/serial.log" >&2 || true
  fi
  exit "$status"
}
trap diagnose_error ERR

network_snapshot() {
  local output=$1
  ip -j link show >"$output.links"
  ip -j route show table all >"$output.routes"
  ip -j rule show >"$output.rules"
  python3 - "$output" <<'PY'
import json
import sys

output = sys.argv[1]


def stable(value):
    if isinstance(value, dict):
        return {key: stable(item) for key, item in value.items() if key != "expires"}
    if isinstance(value, list):
        return [stable(item) for item in value]
    return value


snapshot = []
for suffix in ("links", "routes", "rules"):
    with open(f"{output}.{suffix}", encoding="utf-8") as source:
        records = [stable(record) for record in json.load(source)]
    records.sort(key=lambda record: json.dumps(record, sort_keys=True))
    snapshot.append(records)
with open(output, "w", encoding="utf-8") as target:
    json.dump(snapshot, target, sort_keys=True, separators=(",", ":"))
PY
}

network_snapshot "$work_dir/host-network-before"

phase=release-build
release_dir=$(nix build .#packages.x86_64-linux.release --no-link --print-out-paths)
mapfile -t archives < <(find "$release_dir" -maxdepth 1 -type f \
  -name 'heimdall-egress-*-x86_64-linux-musl.tar.gz' -print)
[[ ${#archives[@]} -eq 1 ]] \
  || fail "release output does not contain exactly one x86_64 archive"
archive=${archives[0]}
checksum=$archive.sha256
[[ -f "$checksum" ]] || fail "release checksum is missing"
archive_name=$(basename "$archive")
version=${archive_name#heimdall-egress-}
version=${version%-x86_64-linux-musl.tar.gz}
[[ -n $version && $version != "$archive_name" ]] \
  || fail "release archive has an unexpected name"

image_format=$(qemu-img info --output=json "$cloud_image" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["format"])')
[[ $image_format == qcow2 ]] || fail "the pinned cloud image is not qcow2"
qemu-img create -q -f qcow2 -F qcow2 -b "$cloud_image" \
  "$work_dir/cloud-overlay.qcow2"

ssh-keygen -q -t ed25519 -N '' -C "heimdall-$distro_id-acceptance" \
  -f "$work_dir/id_ed25519"
public_key=$(<"$work_dir/id_ed25519.pub")
cat >"$work_dir/user-data" <<EOF
#cloud-config
users:
  - name: provisioner
    uid: 1000
    groups: [adm, sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $public_key
  - name: tester
    uid: 1100
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: false
runcmd:
  - [loginctl, enable-linger, tester]
  - [systemctl, start, user@1100.service]
  - [touch, /var/lib/cloud/instance/heimdall-acceptance-ready]
EOF
cat >"$work_dir/meta-data" <<EOF
instance-id: heimdall-$distro_id-acceptance
local-hostname: heimdall-$distro_id
EOF
cloud-localds "$work_dir/seed.img" "$work_dir/user-data" "$work_dir/meta-data"

if [[ -n ${HEIMDALL_DISTRO_VM_SSH_PORT:-} ]]; then
  ssh_port=$HEIMDALL_DISTRO_VM_SSH_PORT
  if [[ ! $ssh_port =~ ^[0-9]+$ ]] \
    || ((ssh_port < 1024 || ssh_port > 65535)); then
    fail "HEIMDALL_DISTRO_VM_SSH_PORT must be an unprivileged TCP port"
  fi
else
  ssh_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
fi
python3 - "$ssh_port" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sock.bind(("127.0.0.1", int(sys.argv[1])))
PY

phase=qemu-boot
qemu-system-x86_64 \
  -machine type=q35,accel=kvm \
  -cpu host \
  -smp 2 \
  -m "$vm_memory_mib" \
  -drive "if=virtio,format=qcow2,file=$work_dir/cloud-overlay.qcow2" \
  -drive "if=virtio,format=raw,readonly=on,file=$work_dir/seed.img" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -monitor none \
  -serial "file:$work_dir/serial.log" \
  -no-reboot >"$work_dir/qemu.log" 2>&1 &
qemu_pid=$!

common_ssh_options=(
  -i "$work_dir/id_ed25519"
  -o BatchMode=yes
  -o ConnectTimeout=2
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)
admin_ssh=(ssh "${common_ssh_options[@]}" -p "$ssh_port" provisioner@127.0.0.1)
tester_ssh=(ssh "${common_ssh_options[@]}" -p "$ssh_port" tester@127.0.0.1)

guest_ready=false
for _ in $(seq 1 120); do
  if "${admin_ssh[@]}" true 2>/dev/null; then
    guest_ready=true
    break
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    tail -n 120 "$work_dir/serial.log" >&2 || true
    fail "QEMU exited before SSH became ready"
  fi
  sleep 1
done
if [[ $guest_ready != true ]]; then
  tail -n 120 "$work_dir/serial.log" >&2 || true
  fail "$distro_id SSH did not become ready"
fi
phase=cloud-init
"${admin_ssh[@]}" sudo cloud-init status --wait >/dev/null
"${admin_ssh[@]}" test -e /var/lib/cloud/instance/heimdall-acceptance-ready

phase=host-isolation-after-boot
network_snapshot "$work_dir/host-network-running"
cmp "$work_dir/host-network-before" "$work_dir/host-network-running" \
  || fail "QEMU changed host links, routes, or rules"

phase=artifact-transfer
scp "${common_ssh_options[@]}" -P "$ssh_port" \
  "$archive" "$checksum" \
  "$script_dir/config.toml" "$script_dir/runtime.toml" "$script_dir/relay.toml" \
  "$script_dir/benchmark.toml" "$script_dir/benchmark-relay.toml" \
  "$script_dir/benchmark-no-capture.toml" \
  "$script_dir/benchmark-capture.toml" \
  "$script_dir/benchmark-relay-capture.toml" \
  "$script_dir/fixture.py" "$script_dir/guest-acceptance.sh" \
  "$repo_root/tests/perf/vm-baseline.py" \
  "$repo_root/tests/perf/udp-throughput.py" \
  "$repo_root/tests/vm/socks5_fixture.py" \
  provisioner@127.0.0.1:/tmp/

phase=guest-provisioning
"${admin_ssh[@]}" bash -s -- "$archive_name" "$distro_id" <<'REMOTE'
set -euo pipefail

archive_name=$1
distro_id=$2
cd /tmp
for command in openssl /usr/sbin/update-ca-certificates; do
  command -v "$command" >/dev/null || {
    echo "$distro_id image is missing required TLS command: $command" >&2
    exit 1
  }
done
sha256sum -c "$archive_name.sha256"
tar -xzf "$archive_name"
bundle=${archive_name%.tar.gz}
sudo "./$bundle/heimdall-install" install
sudo /usr/local/lib/heimdall/heimdall-install verify
sudo install -d -m 0755 /etc/heimdall /opt/heimdall-acceptance
sudo install -m 0644 /tmp/config.toml /etc/heimdall/config.toml
sudo install -m 0644 /tmp/runtime.toml /opt/heimdall-acceptance/runtime.toml
sudo install -m 0644 /tmp/relay.toml /opt/heimdall-acceptance/relay.toml
sudo install -m 0644 /tmp/benchmark.toml /opt/heimdall-acceptance/benchmark.toml
sudo install -m 0644 /tmp/benchmark-relay.toml \
  /opt/heimdall-acceptance/benchmark-relay.toml
sudo install -m 0644 /tmp/benchmark-no-capture.toml \
  /opt/heimdall-acceptance/benchmark-no-capture.toml
sudo install -m 0644 /tmp/benchmark-capture.toml \
  /opt/heimdall-acceptance/benchmark-capture.toml
sudo install -m 0644 /tmp/benchmark-relay-capture.toml \
  /opt/heimdall-acceptance/benchmark-relay-capture.toml
sudo install -m 0755 /tmp/fixture.py /opt/heimdall-acceptance/fixture.py
sudo install -m 0755 /tmp/guest-acceptance.sh /opt/heimdall-acceptance/guest-acceptance.sh
sudo install -m 0755 /tmp/vm-baseline.py /opt/heimdall-acceptance/benchmark.py
sudo install -m 0755 /tmp/udp-throughput.py /opt/heimdall-acceptance/udp-throughput.py
sudo install -m 0755 /tmp/socks5_fixture.py /opt/heimdall-acceptance/socks5-fixture.py
sudo install -d -o tester -g tester -m 0755 /run/heimdall-test

rm -rf /tmp/heimdall-tls
mkdir /tmp/heimdall-tls
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/heimdall-tls/ca-key.pem -out /tmp/heimdall-tls/ca.pem \
  -subj /CN=Heimdall-Acceptance-Upstream-CA -days 36500 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout /tmp/heimdall-tls/server-key.pem -out /tmp/heimdall-tls/server.csr \
  -subj /CN=fixture.test >/dev/null 2>&1
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:fixture.test' > /tmp/heimdall-tls/server.ext
openssl x509 -req -in /tmp/heimdall-tls/server.csr \
  -CA /tmp/heimdall-tls/ca.pem -CAkey /tmp/heimdall-tls/ca-key.pem \
  -CAcreateserial -out /tmp/heimdall-tls/server.pem -days 36500 \
  -extfile /tmp/heimdall-tls/server.ext >/dev/null 2>&1
sudo install -d -m 0755 /opt/heimdall-acceptance/tls
sudo install -o tester -g tester -m 0644 \
  /tmp/heimdall-tls/ca.pem /opt/heimdall-acceptance/tls/upstream-ca.pem
sudo install -o tester -g tester -m 0644 \
  /tmp/heimdall-tls/server.pem /opt/heimdall-acceptance/tls/server.pem
sudo install -o tester -g tester -m 0600 \
  /tmp/heimdall-tls/server-key.pem /opt/heimdall-acceptance/tls/server-key.pem
sudo install -m 0644 /tmp/heimdall-tls/ca.pem \
  /usr/local/share/ca-certificates/heimdall-acceptance-upstream.crt
sudo /usr/sbin/update-ca-certificates >/dev/null
grep -Eq '^[[:space:]]*127\.0\.0\.1[[:space:]]+.*\bfixture\.test\b' /etc/hosts \
  || printf '%s\n' '127.0.0.1 fixture.test' | sudo tee -a /etc/hosts >/dev/null
printf '%s\n' 'tester ALL=(root) NOPASSWD: /usr/local/bin/heimdall __setup-worker' \
  | sudo tee /etc/sudoers.d/heimdall >/dev/null
sudo chmod 0440 /etc/sudoers.d/heimdall
sudo visudo -cf /etc/sudoers.d/heimdall >/dev/null
sudo loginctl enable-linger tester
sudo systemctl start user@1100.service
echo "heimdall $distro_id guest provisioning OK"
REMOTE

phase=guest-data-path
guest_output=$("${tester_ssh[@]}" env \
  HOME=/home/tester \
  XDG_RUNTIME_DIR=/run/user/1100 \
  HEIMDALL_DISTRO_ID="$distro_id" \
  HEIMDALL_RESOLVER_PROFILE="$resolver_profile" \
  HEIMDALL_EXPECTED_VERSION="$version" \
  HEIMDALL_RUN_BENCHMARK="$run_benchmark" \
  HEIMDALL_BENCHMARK_ITERATIONS="$benchmark_iterations" \
  /opt/heimdall-acceptance/guest-acceptance.sh)
printf '%s\n' "$guest_output"
if [[ $run_benchmark == 1 ]]; then
  grep -Fq 'HEIMDALL_BENCHMARK_JSON={"' <<<"$guest_output" \
    || fail "$distro_id guest did not emit the benchmark contract"
fi

phase=host-isolation-after-acceptance
network_snapshot "$work_dir/host-network-after"
cmp "$work_dir/host-network-before" "$work_dir/host-network-after" \
  || fail "acceptance changed host links, routes, or rules"

echo "heimdall pinned $distro_id VM acceptance OK"
if [[ $run_benchmark == 1 ]]; then
  echo "heimdall pinned $distro_id VM benchmark OK"
fi
