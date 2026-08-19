set shell := ["bash", "-euo", "pipefail", "-c"]

toolchain-check:
    required="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].rust_version')"; actual="$(rustc --version --verbose | awk '/^release:/ { print $2 }')"; test "$required" = "$actual" || { echo "rust-version $required does not match pinned stable rustc $actual" >&2; exit 1; }

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

test:
    cargo test --workspace --all-features --locked --release

test-fast:
    cargo nextest run --workspace --all-features --locked

# Boots current and LTS-kernel disposable NixOS guests and exercises the same
# real cgroup/eBPF data-path acceptance suite in both.
test-vm:
    nix build .#checks.x86_64-linux.vm-proxy .#checks.x86_64-linux.vm-proxy-lts -L

# Runs environment-specific latency, memory, concurrency, sustained-throughput,
# and event-integrity baselines in the same disposable real-eBPF NixOS guest.
benchmark-vm:
    nix build .#checks.x86_64-linux.vm-benchmark -L

# Verifies both static archives, architecture/checksum integrity, aarch64 CLI
# emulation, and native x86_64 install, upgrade, and rollback paths.
test-package:
    nix build .#checks.x86_64-linux.release .#checks.x86_64-linux.release-aarch64 -L

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

verify: toolchain-check check-format build-ebpf lint lint-ebpf dependencies test build-userspace
    @echo "verify OK"
