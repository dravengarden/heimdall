#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Darwin ]] || {
  printf 'macOS companion acceptance requires macOS\n' >&2
  exit 1
}
[[ $(uname -m) == arm64 ]] || {
  printf 'macOS companion acceptance requires Apple silicon\n' >&2
  exit 1
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
cd "$repo_root"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-companion-acceptance.XXXXXX")
cleanup() {
  find "$test_root" -depth -delete
}
trap cleanup EXIT

xcrun swift format lint --recursive --strict \
  macos/Package.swift \
  macos/Sources \
  macos/Tests \
  macos/HeimdallCompanion/App \
  macos/HeimdallCompanion/Extension
xcrun swift test \
  --package-path macos \
  --scratch-path "$test_root/swift-build" \
  --configuration release

build_root=$test_root/build
build_log=$test_root/xcodebuild.log
if ! xcodebuild \
  -project macos/HeimdallCompanion/HeimdallCompanion.xcodeproj \
  -scheme HeimdallCompanion \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "$build_root" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  build >"$build_log" 2>&1; then
  grep -n -B3 -A7 'error:' "$build_log" || tail -120 "$build_log"
  exit 1
fi

app=$build_root/Build/Products/Release/HeimdallCompanion.app
extension_id=io.github.dravengarden.heimdall.transparent-proxy
extension=$app/Contents/Library/SystemExtensions/$extension_id.systemextension
app_binary=$app/Contents/MacOS/HeimdallCompanion
extension_binary=$extension/Contents/MacOS/$extension_id

[[ -x $app_binary && -x $extension_binary ]] || {
  printf 'the companion build is missing an executable product\n' >&2
  exit 1
}

for binary in "$app_binary" "$extension_binary"; do
  file "$binary" | grep -Fq 'Mach-O 64-bit executable arm64' || {
    printf 'the companion build is not an arm64 Mach-O executable: %s\n' \
      "$binary" >&2
    exit 1
  }
  minimum_macos=$(otool -l "$binary" | awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { build = 1; next }
    build && $1 == "minos" { print $2; exit }
  ')
  [[ $minimum_macos == 11.0 ]] || {
    printf 'the companion build has an unexpected deployment target: %s\n' \
      "$minimum_macos" >&2
    exit 1
  }
done

extension_count=$(find "$app/Contents/Library/SystemExtensions" \
  -mindepth 1 -maxdepth 1 -type d -name '*.systemextension' | wc -l | tr -d ' ')
[[ $extension_count == 1 ]] || {
  printf 'the companion contains %s system extensions instead of one\n' \
    "$extension_count" >&2
  exit 1
}

python3 - "$app/Contents/Info.plist" "$extension/Contents/Info.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    app = plistlib.load(stream)
with open(sys.argv[2], "rb") as stream:
    extension = plistlib.load(stream)

assert app["CFBundleIdentifier"] == "io.github.dravengarden.heimdall.companion"
assert extension["CFBundleIdentifier"] == (
    "io.github.dravengarden.heimdall.transparent-proxy"
)
providers = extension["NetworkExtension"]["NEProviderClasses"]
assert providers["com.apple.networkextension.app-proxy"].endswith(
    ".TransparentProxyProvider"
)
PY

if codesign --verify "$app" >/dev/null 2>&1 \
  || codesign --verify "$extension" >/dev/null 2>&1; then
  printf 'the compile-only companion unexpectedly produced a signed bundle\n' >&2
  exit 1
fi

printf 'macOS unsigned companion acceptance OK\n'
