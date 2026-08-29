#!/bin/sh
set -eu

release_dir=${1:?usage: run-acceptance.sh RELEASE_DIRECTORY}
version=${2:?usage: run-acceptance.sh RELEASE_DIRECTORY VERSION}
architecture=${3:?usage: run-acceptance.sh RELEASE_DIRECTORY VERSION ARCHITECTURE ELF_MACHINE [RUNNER]}
elf_machine=${4:?usage: run-acceptance.sh RELEASE_DIRECTORY VERSION ARCHITECTURE ELF_MACHINE [RUNNER]}
runner=${5:-}
archive_name=heimdall-egress-$version-$architecture-linux-musl.tar.gz
archive=$release_dir/$archive_name
script_dir=$(
  CDPATH=''
  cd -- "$(dirname -- "$0")"
  pwd
)

(cd "$release_dir" && sha256sum -c "$archive_name.sha256")

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' 0 HUP INT TERM
tar -xzf "$archive" -C "$work_dir"
bundle=$work_dir/heimdall-egress-$version-$architecture-linux-musl

expected_entries='LICENSE
README.md
heimdall
heimdall-install'
actual_entries=$(find "$bundle" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
[ "$actual_entries" = "$expected_entries" ] || {
  echo "release bundle has unexpected entries:" >&2
  printf '%s\n' "$actual_entries" >&2
  exit 1
}

"$script_dir/check-artifact-hygiene.sh" "$bundle/heimdall" linux-executable
readelf -h "$bundle/heimdall" | grep -F "Machine:" | grep -Fq "$elf_machine" || {
  echo "release binary has the wrong ELF architecture" >&2
  exit 1
}

if [ -n "$runner" ]; then
  [ "$("$runner" "$bundle/heimdall" --version)" = "heimdall $version" ]
  "$runner" "$bundle/heimdall" --help >/dev/null
  flow_schema=$("$runner" "$bundle/heimdall" logs schema --flow v1)
  printf '%s\n' "$flow_schema" |
    grep -Eq '"const"[[:space:]]*:[[:space:]]*"heimdall\.logs\.flow/v1"'
  echo "release package structural and emulated CLI acceptance OK"
  exit 0
fi

[ "$("$bundle/heimdall" --version)" = "heimdall $version" ]
flow_schema=$("$bundle/heimdall" logs schema --flow v1)
printf '%s\n' "$flow_schema" |
  grep -Eq '"const"[[:space:]]*:[[:space:]]*"heimdall\.logs\.flow/v1"'

prefix=$work_dir/prefix
"$bundle/heimdall-install" install --prefix "$prefix"
"$prefix/lib/heimdall/heimdall-install" verify --prefix "$prefix"
[ -f "$prefix/bin/heimdall" ]
[ ! -L "$prefix/bin/heimdall" ]

cp "$prefix/bin/heimdall" "$work_dir/original"
cp "$bundle/heimdall" "$bundle/heimdall.next"
printf '\0' >> "$bundle/heimdall.next"
mv "$bundle/heimdall.next" "$bundle/heimdall"
"$bundle/heimdall-install" install --prefix "$prefix"
"$prefix/lib/heimdall/heimdall-install" rollback --prefix "$prefix"
cmp -s "$prefix/bin/heimdall" "$work_dir/original"
"$prefix/bin/heimdall" --help >/dev/null
flow_schema=$("$prefix/bin/heimdall" logs schema --flow v1)
printf '%s\n' "$flow_schema" |
  grep -Eq '"const"[[:space:]]*:[[:space:]]*"heimdall\.logs\.flow/v1"'

touch "$prefix/unrelated-file"
"$prefix/lib/heimdall/heimdall-install" uninstall --prefix "$prefix"
[ ! -e "$prefix/bin/heimdall" ]
[ ! -e "$prefix/lib/heimdall" ]
[ -f "$prefix/unrelated-file" ]

echo "release package acceptance OK"
