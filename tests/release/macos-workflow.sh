#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

grep -Fq "scripts/build-macos-release-assets-remote \"\$stage/dist\"" \
  scripts/publish-github-release
if grep -F 'build-macos-release-assets-remote' scripts/publish-github-release |
  grep -Fq -- '--unsigned'; then
  printf 'GitHub publication selects the unsigned macOS path\n' >&2
  exit 1
fi
grep -Fq 'git archive HEAD' scripts/build-macos-release-assets-remote
grep -Fq 'Developer ID Application' scripts/build-macos-release-assets
grep -Fq -- '--options runtime --timestamp' scripts/build-macos-release-assets
grep -Fq "grep -Eq '^Timestamp=.+'" scripts/build-macos-release-assets
grep -Fq 'notarytool submit' scripts/build-macos-release-assets
grep -Fq 'notarytool log' scripts/build-macos-release-assets
grep -Fq 'spctl --assess --type execute' scripts/build-macos-release-assets
grep -Fq 'tests/macos/run-companion-acceptance.sh' \
  scripts/build-macos-release-assets
grep -Fq 'uninstall)' packaging/heimdall-install

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
root=$work_dir/heimdall-egress-1.2.3-aarch64-apple-darwin
mkdir -p "$root"
printf 'license\n' >"$root/LICENSE"
printf 'readme\n' >"$root/README.md"
printf '#!/bin/sh\nexit 0\n' >"$root/heimdall"
printf '#!/bin/sh\nexit 0\n' >"$root/heimdall-install"
chmod 0755 "$root/heimdall" "$root/heimdall-install"

scripts/create-release-archive.py "$root" "$work_dir/one.tar.gz"
touch -t 203001010101 "$root"/*
scripts/create-release-archive.py "$root" "$work_dir/two.tar.gz"
cmp "$work_dir/one.tar.gz" "$work_dir/two.tar.gz"
python3 -c '
import pathlib, sys, tarfile
archive = pathlib.Path(sys.argv[1])
with tarfile.open(archive, "r:gz") as stream:
    members = stream.getmembers()
assert [item.name for item in members] == [
    "heimdall-egress-1.2.3-aarch64-apple-darwin",
    "heimdall-egress-1.2.3-aarch64-apple-darwin/LICENSE",
    "heimdall-egress-1.2.3-aarch64-apple-darwin/README.md",
    "heimdall-egress-1.2.3-aarch64-apple-darwin/heimdall",
    "heimdall-egress-1.2.3-aarch64-apple-darwin/heimdall-install",
]
assert all(item.uid == 0 and item.gid == 0 for item in members)
assert all(item.uname == "root" and item.gname == "root" for item in members)
assert all(item.mtime == 1 for item in members)
assert [item.mode for item in members] == [0o755, 0o644, 0o644, 0o755, 0o755]
' "$work_dir/one.tar.gz"

printf 'native macOS release workflow contract OK\n'
