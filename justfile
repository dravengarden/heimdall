set shell := ["bash", "-euo", "pipefail", "-c"]

toolchain-check:
    required="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].rust_version')"; actual="$(rustc --version --verbose | awk '/^release:/ { print $2 }')"; test "$required" = "$actual" || { echo "rust-version $required does not match pinned stable rustc $actual" >&2; exit 1; }

# Type-check the target-selected CLI and portable explicit-proxy tests without
# linking against a macOS SDK. This proves Linux-only dependencies do not leak
# into Darwin; `test-macos-native` remains the real cooperative-backend gate.
check-macos:
    cargo check --package heimdall-egress --all-targets --target aarch64-apple-darwin --locked
    cargo check --package heimdall-egress --all-targets --target x86_64-apple-darwin --locked

# The explicit frontend is architecture-neutral and has its own native gate so
# Intel macOS does not inherit the Apple-silicon interpose/package boundary.
test-macos-explicit-native:
    test "$(uname -s)" = Darwin || { echo "macOS explicit acceptance requires macOS" >&2; exit 1; }
    cargo test --package heimdall-egress --all-targets --locked --release
    cargo build --package heimdall-egress --locked --release
    tests/macos/run-explicit-acceptance.sh

# Runs only on native Apple silicon. The gate proves the cooperative SOCKS
# environment, TCP route, evidence, exit status, explicit selection, and
# foreground listener teardown without making a transparent-scope claim.
test-macos-native:
    test "$(uname -s)" = Darwin || { echo "macOS native acceptance requires macOS" >&2; exit 1; }
    test "$(uname -m)" = arm64 || { echo "macOS native acceptance requires Apple silicon" >&2; exit 1; }
    cargo test --package heimdall-egress --all-targets --locked --release
    cargo build --package heimdall-egress --locked --release
    tests/macos/run-explicit-acceptance.sh
    tests/macos/run-interpose-acceptance.sh

test-macos-interpose-native:
    tests/macos/run-interpose-acceptance.sh

# Keeps the compile-only provider fail-closed on every development host. The
# native gate below remains responsible for Swift execution and bundle shape.
test-macos-companion-contract:
    tests/macos/check-companion-contract.sh

# Builds but never signs, installs, activates, or configures the companion.
# This deferred research gate is source evidence only and is intentionally not
# part of the macOS package or release path.
test-macos-companion-native:
    tests/macos/run-companion-acceptance.sh

# Records bounded loopback socket/resolver behavior and known bypasses behind
# the daemonless interpose research. It is not a backend availability gate.
test-macos-interpose-feasibility:
    tests/macos/run-interpose-feasibility.sh

# Proves the selectable, daemonless interpose backend on the native Linux host
# without requiring cgroup delegation, eBPF setup, or root.
test-linux-interpose-native: build-userspace
    tests/linux/run-interpose-acceptance.sh

# Proves the selectable, daemonless explicit backend on the native Linux host
# and guards it from entering the systemd/cgroup/eBPF path.
test-linux-explicit-native: build-userspace
    tests/linux/run-explicit-acceptance.sh

fmt:
    cargo fmt --all
    cargo fmt --manifest-path heimdall-ebpf/Cargo.toml
    nixfmt flake.nix

check-format:
    cargo fmt --all --check
    cargo fmt --manifest-path heimdall-ebpf/Cargo.toml --check
    nixfmt --check flake.nix

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

lint-ebpf:
    nix develop .#ebpf -c bash -euo pipefail -c 'cd heimdall-ebpf && cargo-nightly clippy --locked --release -- -D warnings'

dependencies:
    cargo deny check
    cargo machete --with-metadata
    cargo deny --manifest-path heimdall-ebpf/Cargo.toml check --config deny.toml
    cargo machete --with-metadata heimdall-ebpf

build-ebpf:
    nix develop .#ebpf -c bash -euo pipefail -c 'cd heimdall-ebpf && cargo-nightly build --locked --release'

sync-ebpf:
    scripts/sync-ebpf-object

check-embedded-ebpf:
    output="$(nix build .#heimdall-ebpf --print-out-paths --no-link -L)"; cmp "$output/heimdall-ebpf" heimdall/embedded/heimdall-ebpf
    tests/package/check-artifact-hygiene.sh heimdall/embedded/heimdall-ebpf ebpf

test:
    cargo test --workspace --all-features --locked --release

test-release-notes:
    tests/release/render-notes.sh

test-site:
    tests/site/content-contract.sh

test-npm:
    tests/npm/run-acceptance.sh

test-pypi:
    tests/pypi/run-acceptance.sh

test-cargo:
    tests/cargo/run-acceptance.sh

test-package-macos:
    stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT; scripts/build-macos-release-assets-remote --unsigned "$stage"

test-release-tooling:
    actionlint .github/workflows/docs-pages.yml .github/workflows/publish-cargo.yml .github/workflows/publish-npm.yml .github/workflows/publish-pypi.yml
    shellcheck scripts/build-cargo-release-assets scripts/build-macos-release-assets scripts/build-macos-release-assets-remote scripts/build-npm-package scripts/build-npm-release-assets scripts/build-pypi-release-assets scripts/publish-github-release scripts/render-release-notes scripts/sync-ebpf-object tests/cargo/run-acceptance.sh tests/distro/guest-acceptance.sh tests/distro/run-cloud-acceptance.sh tests/linux/run-explicit-acceptance.sh tests/linux/run-interpose-acceptance.sh tests/macos/check-companion-contract.sh tests/macos/run-companion-acceptance.sh tests/macos/run-explicit-acceptance.sh tests/macos/run-interpose-acceptance.sh tests/macos/run-interpose-feasibility.sh tests/npm/run-acceptance.sh tests/package/check-artifact-hygiene.sh tests/package/run-acceptance.sh tests/package/run-macos-acceptance.sh tests/pypi/run-acceptance.sh tests/release/cargo-workflow.sh tests/release/macos-workflow.sh tests/release/npm-workflow.sh tests/release/pypi-workflow.sh tests/release/render-notes.sh tests/site/content-contract.sh
    python3 -c 'paths = ("scripts/create-release-archive.py", "tests/distro/fixture.py", "tests/macos/fixture.py", "tests/perf/udp-throughput.py", "tests/perf/vm-baseline.py", "tests/vm/socks5_fixture.py"); [compile(open(path, encoding="utf-8").read(), path, "exec") for path in paths]'
    tests/release/cargo-workflow.sh
    tests/release/macos-workflow.sh
    tests/release/npm-workflow.sh
    tests/release/pypi-workflow.sh

test-fast:
    cargo nextest run --workspace --all-features --locked

# Boots current and LTS-kernel disposable NixOS guests and exercises the same
# real cgroup/eBPF data-path acceptance suite in both.
test-vm:
    # Each guest owns two vCPUs. Sequential execution keeps UDP stress timing
    # meaningful on two-core development and hosted runners.
    nix build .#checks.x86_64-linux.vm-proxy -L
    nix build .#checks.x86_64-linux.vm-proxy-lts -L

# Installs the native archive in a pinned Ubuntu 24.04 cloud guest and proves
# real TCP/UDP, lifecycle, runtime/relay TLS, and daemonless teardown outside
# NixOS.
test-vm-ubuntu:
    nix develop .#ubuntu-acceptance -c tests/distro/run-cloud-acceptance.sh

# Installs the same native archive in a pinned Debian 13 cloud guest and runs
# the complete distro acceptance suite against its stock NSS and kernel.
test-vm-debian:
    nix develop .#debian-acceptance -c tests/distro/run-cloud-acceptance.sh

# Runs the same current/LTS real-eBPF guests with an aarch64 userspace and
# kernel. The host guard prevents the x86 release host's qemu-user CLI check
# from being reported as the native aarch64 system gate.
test-vm-native-aarch64:
    test "$(uname -s)" = Linux || { echo "native aarch64 acceptance requires Linux" >&2; exit 1; }
    test "$(uname -m)" = aarch64 || { echo "native aarch64 acceptance requires an aarch64 host" >&2; exit 1; }
    nix build .#checks.aarch64-linux.vm-proxy -L
    nix build .#checks.aarch64-linux.vm-proxy-lts -L

# Runs environment-specific latency, memory, concurrency, sustained-throughput,
# and event-integrity baselines in current and LTS real-eBPF NixOS guests.
benchmark-vm:
    nix build .#checks.x86_64-linux.vm-benchmark .#checks.x86_64-linux.vm-benchmark-lts -L

# Why: the 8 GiB benchmark guest is intentionally too expensive for the normal
# release transaction; invoke its cross-distribution baseline explicitly.
benchmark-vm-ubuntu:
    HEIMDALL_DISTRO_BENCHMARK=1 nix develop .#ubuntu-acceptance -c tests/distro/run-cloud-acceptance.sh

# Runs the explicit performance contract in the pinned Debian guest.
benchmark-vm-debian:
    HEIMDALL_DISTRO_BENCHMARK=1 nix develop .#debian-acceptance -c tests/distro/run-cloud-acceptance.sh

# Verifies static archives and the npm/PyPI/Cargo distributions, including
# architecture/checksum/artifact hygiene, aarch64 inspection/emulation, and
# native x86_64 install, upgrade, and rollback paths.
test-package:
    nix build .#checks.x86_64-linux.release .#checks.x86_64-linux.release-aarch64 -L
    just test-npm
    just test-pypi
    just test-cargo

# Local publication is authoritative: source, real-kernel, and package gates
# all complete on the release host before any tag or GitHub asset is created.
release-check:
    nix develop -c just verify
    just test-vm
    just test-vm-ubuntu
    just test-vm-debian
    just test-package
    just test-package-macos

release-github:
    nix develop -c scripts/publish-github-release

# Explicitly opt in after confirming a representative workload benefits from
# compiler caching. On 2026-07-18, a same-path clean rebuild took 7.24s with
# 241 Rust cache hits versus 10.46s with plain Cargo; filling the cache took
# 12.78s and an unchanged incremental build took 0.09s.
build-cached:
    RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 cargo build --workspace --all-features --locked

build-userspace:
    cargo build --workspace --all-features --locked --release

cache-stats:
    sccache --show-stats

verify: toolchain-check check-format check-macos test-macos-companion-contract build-ebpf check-embedded-ebpf lint lint-ebpf dependencies test test-release-notes test-site test-release-tooling build-userspace test-linux-interpose-native test-linux-explicit-native
    @echo "verify OK"
