#!/usr/bin/env bash
set -euo pipefail

release_dir=${1:?usage: run-macos-acceptance.sh RELEASE_DIRECTORY VERSION MODE}
version=${2:?usage: run-macos-acceptance.sh RELEASE_DIRECTORY VERSION MODE}
mode=${3:?usage: run-macos-acceptance.sh RELEASE_DIRECTORY VERSION MODE}
[[ $mode == signed || $mode == unsigned ]] || {
  printf 'unknown macOS package acceptance mode: %s\n' "$mode" >&2
  exit 2
}
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || {
  printf 'macOS package acceptance requires Apple silicon\n' >&2
  exit 1
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
archive_root=heimdall-egress-$version-aarch64-apple-darwin
archive_name=$archive_root.tar.gz
archive=$release_dir/$archive_name
(cd "$release_dir" && shasum -a 256 -c "$archive_name.sha256")

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-macos-package.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
tar -xzf "$archive" -C "$work_dir"
bundle=$work_dir/$archive_root

expected_entries='LICENSE
README.md
heimdall
heimdall-install'
actual_entries=$(
  for entry in "$bundle"/*; do
    basename "$entry"
  done | sort
)
[[ $actual_entries == "$expected_entries" ]] || {
  printf 'macOS release bundle has unexpected entries:\n%s\n' "$actual_entries" >&2
  exit 1
}

"$script_dir/check-artifact-hygiene.sh" "$bundle/heimdall" macos-executable
codesign --verify --strict "$bundle/heimdall" >/dev/null 2>&1
signature=$(codesign -d --verbose=4 "$bundle/heimdall" 2>&1)
grep -Eq 'flags=.*runtime' <<<"$signature"
if [[ $mode == signed ]]; then
  grep -Fq 'Authority=Developer ID Application:' <<<"$signature" || {
    printf 'official macOS archive is not signed with Developer ID Application\n' >&2
    exit 1
  }
  grep -Eq '^Timestamp=.+' <<<"$signature" || {
    printf 'official macOS archive is missing a secure signing timestamp\n' >&2
    exit 1
  }
  spctl --assess --type execute "$bundle/heimdall" >/dev/null 2>&1 || {
    printf 'Gatekeeper rejected the packaged Heimdall executable\n' >&2
    exit 1
  }
else
  grep -Fq 'Signature=adhoc' <<<"$signature" || {
    printf 'unsigned acceptance archive lacks its required ad hoc integrity signature\n' >&2
    exit 1
  }
fi

[[ $("$bundle/heimdall" --version) == "heimdall $version" ]]
flow_schema=$("$bundle/heimdall" logs schema --flow v1)
grep -Eq '"const"[[:space:]]*:[[:space:]]*"heimdall\.logs\.flow/v1"' <<<"$flow_schema"

prefix=$work_dir/prefix
install_output=$("$bundle/heimdall-install" install --prefix "$prefix")
grep -Fq 'macos-explicit requires no privileged setup' <<<"$install_output"
if grep -Fq '__setup-worker' <<<"$install_output"; then
  printf 'macOS installer printed Linux setup authorization\n' >&2
  exit 1
fi
"$prefix/lib/heimdall/heimdall-install" verify --prefix "$prefix" >/dev/null
[[ -f $prefix/bin/heimdall && ! -L $prefix/bin/heimdall ]]
cp "$prefix/bin/heimdall" "$work_dir/original"

next_bundle=$work_dir/next
cp -R "$bundle" "$next_bundle"
codesign --force --sign - --options runtime \
  --identifier io.github.dravengarden.heimdall.acceptance-next \
  "$next_bundle/heimdall" >/dev/null 2>&1
"$next_bundle/heimdall-install" install --prefix "$prefix" >/dev/null
"$prefix/lib/heimdall/heimdall-install" rollback --prefix "$prefix" >/dev/null
cmp -s "$prefix/bin/heimdall" "$work_dir/original"
"$prefix/bin/heimdall" --help >/dev/null

touch "$prefix/unrelated-file"
"$prefix/lib/heimdall/heimdall-install" uninstall --prefix "$prefix" >/dev/null
[[ ! -e $prefix/bin/heimdall ]]
[[ ! -e $prefix/lib/heimdall ]]
[[ -f $prefix/unrelated-file ]]

printf 'macOS %s release package acceptance OK\n' "$mode"
