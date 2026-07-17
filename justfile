set shell := ["bash", "-euo", "pipefail", "-c"]

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

build-ui:
    cd heimdall-ui && deno install --frozen --allow-scripts && deno task typecheck && deno task build

test:
    cargo test --workspace --all-features --locked --release

test-fast:
    cargo nextest run --workspace --all-features --locked

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

verify: check-format build-ebpf build-ui lint lint-ebpf dependencies test build-userspace
    @echo "verify OK"
