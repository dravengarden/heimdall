#!/bin/sh
set -eu

release_dir=${1:?usage: run-acceptance.sh RELEASE_DIRECTORY}
version=${2:?usage: run-acceptance.sh RELEASE_DIRECTORY VERSION}
archive_name=heimdall-$version-x86_64-linux-musl.tar.gz
archive=$release_dir/$archive_name

(cd "$release_dir" && sha256sum -c "$archive_name.sha256")

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' 0 HUP INT TERM
tar -xzf "$archive" -C "$work_dir"
bundle=$work_dir/heimdall-$version-x86_64-linux-musl

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

if readelf -l "$bundle/heimdall" | grep -q 'interpreter'; then
  echo "release binary has a dynamic ELF interpreter" >&2
  exit 1
fi
if readelf -d "$bundle/heimdall" | grep -q 'NEEDED'; then
  echo "release binary has dynamic library dependencies" >&2
  exit 1
fi
[ "$("$bundle/heimdall" --version)" = "heimdall $version" ]

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

echo "release package acceptance OK"
