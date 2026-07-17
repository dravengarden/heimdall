set shell := ["bash", "-euo", "pipefail", "-c"]

fmt:
    cargo fmt --all
    nixfmt flake.nix

check-format:
    cargo fmt --all --check
    nixfmt --check flake.nix

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

build-ebpf:
    nix develop .#ebpf -c bash -euo pipefail -c 'cd heimdall-ebpf && cargo-nightly build --locked --release'

build-ui:
    cd heimdall-ui && deno install --frozen --allow-scripts && deno task typecheck && deno task build

test:
    cargo test --workspace --all-features --locked --release

test-fast:
    cargo nextest run --workspace --all-features --locked

# Explicitly opt in after confirming a representative workload benefits from
# compiler caching. Fresh local builds are currently faster without sccache.
check-cached:
    RUSTC_WRAPPER=sccache cargo check --workspace --all-features --locked

build-userspace:
    cargo build --workspace --all-features --locked --release

cache-stats:
    sccache --show-stats

verify: check-format build-ebpf build-ui lint test build-userspace
    @echo "verify OK"
