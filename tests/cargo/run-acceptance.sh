#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
version=$(nix eval --raw .#packages.x86_64-linux.release.version)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

scripts/build-cargo-release-assets "$work_dir/dist"
(cd "$work_dir/dist" && sha256sum -c ./*.crate.sha256)

expected_files=$(
  for package in heimdall-common heimdall-config heimdall-egress; do
    printf '%s\n' "$package-$version.crate" "$package-$version.crate.sha256"
  done | sort
)
actual_files=$(find "$work_dir/dist" -maxdepth 1 -type f -printf '%f\n' | sort)
[[ "$actual_files" == "$expected_files" ]] || {
  echo 'Cargo release assets have unexpected files:' >&2
  printf '%s\n' "$actual_files" >&2
  exit 1
}

archive="$work_dir/dist/heimdall-egress-$version.crate"
mkdir "$work_dir/unpacked"
tar -xzf "$archive" -C "$work_dir/unpacked"
root="$work_dir/unpacked/heimdall-egress-$version"
cmp heimdall/embedded/heimdall-ebpf "$root/embedded/heimdall-ebpf"
grep -Fq 'name = "heimdall-egress"' "$root/Cargo.toml"
grep -Fq 'name = "heimdall"' "$root/Cargo.toml"
grep -Fq 'version = "0.1.3"' "$root/Cargo.toml"

for expected in \
  'cargo install heimdall-egress --locked' \
  '## Architecture' \
  '## Modes' \
  'There is no persistent Heimdall daemon'; do
  grep -Fq "$expected" "$root/README.md" || {
    printf 'crates.io package page is missing: %s\n' "$expected" >&2
    exit 1
  }
done

file "$root/embedded/heimdall-ebpf" | grep -Fq 'eBPF'
printf 'Cargo package acceptance OK\n'
