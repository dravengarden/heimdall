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

sync-ebpf:
    scripts/sync-ebpf-object

check-embedded-ebpf:
    output="$(nix build .#heimdall-ebpf --print-out-paths --no-link -L)"; cmp "$output/heimdall-ebpf" heimdall/embedded/heimdall-ebpf
    tests/package/check-artifact-hygiene.sh heimdall/embedded/heimdall-ebpf ebpf

test:
    cargo test --workspace --all-features --locked --release

test-release-notes:
    tests/release/render-notes.sh

test-npm:
    tests/npm/run-acceptance.sh

test-pypi:
    tests/pypi/run-acceptance.sh

test-cargo:
    tests/cargo/run-acceptance.sh

test-release-tooling:
    actionlint .github/workflows/publish-cargo.yml .github/workflows/publish-npm.yml .github/workflows/publish-pypi.yml
    shellcheck scripts/build-cargo-release-assets scripts/build-npm-package scripts/build-npm-release-assets scripts/build-pypi-release-assets scripts/publish-github-release scripts/render-release-notes scripts/sync-ebpf-object tests/cargo/run-acceptance.sh tests/npm/run-acceptance.sh tests/package/check-artifact-hygiene.sh tests/package/run-acceptance.sh tests/pypi/run-acceptance.sh tests/release/cargo-workflow.sh tests/release/npm-workflow.sh tests/release/pypi-workflow.sh tests/release/render-notes.sh
    tests/release/cargo-workflow.sh
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
    just test-package

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

verify: toolchain-check check-format build-ebpf check-embedded-ebpf lint lint-ebpf dependencies test test-release-notes test-release-tooling build-userspace
    @echo "verify OK"
