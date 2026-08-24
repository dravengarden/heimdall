#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/publish-cargo.yml

grep -Fq 'release:' "$workflow"
grep -Fq 'types: [published]' "$workflow"
grep -Fq 'id-token: write' "$workflow"
grep -Fq "vars.CARGO_TRUSTED_PUBLISHING_ENABLED == 'true'" "$workflow"
grep -Fq 'rustup toolchain install 1.95.0 --profile minimal' "$workflow"
grep -Fq 'cargo package --package' "$workflow"
grep -Fq 'patch.crates-io.heimdall-common.path="heimdall-common"' "$workflow"
grep -Fq 'cargo publish --package' "$workflow"
grep -Fq 'rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18' "$workflow"

for forbidden in workflow_dispatch 'cargo login' CARGO_REGISTRY_TOKEN= 'lasso '; do
  if grep -Fq "$forbidden" "$workflow"; then
    printf 'Cargo workflow contains forbidden auth or release wrapper: %s\n' \
      "$forbidden" >&2
    exit 1
  fi
done

printf 'native Cargo release workflow acceptance OK\n'
