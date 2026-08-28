#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
version=$(nix eval --raw .#packages.x86_64-linux.release.version)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

scripts/build-pypi-release-assets "$work_dir/dist"
(cd "$work_dir/dist" && sha256sum -c ./*.whl.sha256)

x86_wheel="heimdall_egress-${version}-py3-none-manylinux_2_17_x86_64.musllinux_1_2_x86_64.whl"
arm_wheel="heimdall_egress-${version}-py3-none-manylinux_2_17_aarch64.musllinux_1_2_aarch64.whl"
expected_files=$(printf '%s\n' \
  "$arm_wheel" "$arm_wheel.sha256" "$x86_wheel" "$x86_wheel.sha256" | sort)
actual_files=$(find "$work_dir/dist" -maxdepth 1 -type f -printf '%f\n' | sort)
[[ "$actual_files" == "$expected_files" ]] || {
  echo 'PyPI release assets have unexpected files:' >&2
  printf '%s\n' "$actual_files" >&2
  exit 1
}

python -m twine check "$work_dir/dist"/*.whl

for expected in \
  'uv tool install heimdall-egress' \
  'pipx install heimdall-egress' \
  'python -m pip install heimdall-egress' \
  'uvx --from heimdall-egress heimdall --version' \
  '## Architecture' \
  '## Modes' \
  'No persistent Heimdall daemon'; do
  unzip -p "$work_dir/dist/$x86_wheel" \
    "heimdall_egress-${version}.dist-info/METADATA" | grep -Fq "$expected" || {
      printf 'PyPI package page is missing: %s\n' "$expected" >&2
      exit 1
    }
done

uv venv --python python3 "$work_dir/venv"
uv pip install --python "$work_dir/venv/bin/python" --no-cache \
  "$work_dir/dist/$x86_wheel"
[[ "$("$work_dir/venv/bin/heimdall" --version)" == "heimdall $version" ]]
[[ "$("$work_dir/venv/bin/heimdall-egress" --version)" == "heimdall $version" ]]
native_path=$("$work_dir/venv/bin/heimdall-egress" --print-native-path)
[[ "$native_path" == "$work_dir/venv/lib/python"*/site-packages/heimdall_egress/native/heimdall ]]
[[ -x "$native_path" && ! -L "$native_path" ]]

UV_TOOL_DIR="$work_dir/uv-tools" UV_TOOL_BIN_DIR="$work_dir/uv-bin" \
  UV_CACHE_DIR="$work_dir/uv-cache" uv tool install "$work_dir/dist/$x86_wheel"
[[ "$("$work_dir/uv-bin/heimdall" --version)" == "heimdall $version" ]]
UV_CACHE_DIR="$work_dir/uvx-cache" \
  uvx --from "$work_dir/dist/$x86_wheel" heimdall --version |
  grep -Fxq "heimdall $version"

mkdir "$work_dir/arm"
unzip -q "$work_dir/dist/$arm_wheel" -d "$work_dir/arm"
arm_binary="$work_dir/arm/heimdall_egress/native/heimdall"
readelf -h "$arm_binary" | grep -F 'Machine:' | grep -Fq AArch64
tests/package/check-artifact-hygiene.sh "$native_path" linux-executable
tests/package/check-artifact-hygiene.sh "$arm_binary" linux-executable

printf 'PyPI package acceptance OK\n'
