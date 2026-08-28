#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
version=$(nix eval --raw .#packages.x86_64-linux.release.version)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

scripts/build-npm-release-assets "$work_dir"
tarball="heimdall-egress-$version.tgz"
(cd "$work_dir" && sha256sum -c "$tarball.sha256")

expected_files='LICENSE
README.md
bin/heimdall.js
package.json
vendor/linux-arm64/heimdall
vendor/linux-x64/heimdall'
actual_files=$(tar -tzf "$work_dir/$tarball" |
  sed -n 's#^package/##p' | sed '/\/$/d' | sort)
[[ "$actual_files" == "$expected_files" ]] || {
  echo "npm package has unexpected files:" >&2
  printf '%s\n' "$actual_files" >&2
  exit 1
}

package_json=$(tar -xOf "$work_dir/$tarball" package/package.json)
package_readme=$(tar -xOf "$work_dir/$tarball" package/README.md)
node -e '
  const packageJson = JSON.parse(process.argv[1]);
  if (packageJson.name !== "heimdall-egress") process.exit(1);
  if (packageJson.version !== process.argv[2]) process.exit(1);
  if (packageJson.scripts !== undefined) process.exit(1);
' "$package_json" "$version"

for expected in \
  'npm install --global heimdall-egress' \
  'pnpm add --global heimdall-egress' \
  'yarn global add heimdall-egress' \
  'bun add --global heimdall-egress' \
  'deno install --global -A --name heimdall npm:heimdall-egress' \
  'npx --yes --package=heimdall-egress -- heimdall --version' \
  'pnpm dlx --package heimdall-egress heimdall --version' \
  'yarn dlx --package heimdall-egress heimdall --version' \
  'bunx --package heimdall-egress heimdall --version' \
  'deno x -A --package heimdall-egress heimdall --version' \
  '## Architecture' \
  '## Modes' \
  'No persistent Heimdall daemon'; do
  grep -Fq "$expected" <<<"$package_readme" || {
    printf 'npm package README is missing: %s\n' "$expected" >&2
    exit 1
  }
done

prefix="$work_dir/prefix"
npm install --global --ignore-scripts --prefix "$prefix" "$work_dir/$tarball" \
  --no-audit --no-fund
[[ "$("$prefix/bin/heimdall" --version)" == "heimdall $version" ]]
[[ "$("$prefix/bin/heimdall-egress" --version)" == "heimdall $version" ]]
native_path=$("$prefix/bin/heimdall-egress" --print-native-path)
[[ "$native_path" == "$prefix/lib/node_modules/heimdall-egress/vendor/linux-x64/heimdall" ]]
[[ -x "$native_path" && ! -L "$native_path" ]]

npm exec --yes --package="$work_dir/$tarball" -- \
  heimdall-egress --version | grep -Fxq "heimdall $version"

mkdir "$work_dir/extracted"
tar -xzf "$work_dir/$tarball" -C "$work_dir/extracted" \
  package/vendor/linux-arm64/heimdall \
  package/vendor/linux-x64/heimdall
arm_binary="$work_dir/extracted/package/vendor/linux-arm64/heimdall"
x86_binary="$work_dir/extracted/package/vendor/linux-x64/heimdall"
cmp "$native_path" "$x86_binary"
tests/package/check-artifact-hygiene.sh "$x86_binary" linux-executable
tests/package/check-artifact-hygiene.sh "$arm_binary" linux-executable
readelf -h "$arm_binary" |
  grep -F 'Machine:' | grep -Fq AArch64

echo 'npm package acceptance OK'
