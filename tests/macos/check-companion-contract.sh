#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

provider=macos/HeimdallCompanion/Extension/TransparentProxyProvider.swift
provider_info=macos/HeimdallCompanion/Extension/Info.plist
provider_entitlements=macos/HeimdallCompanion/Extension/HeimdallTransparentProxy.entitlements
app_source=macos/HeimdallCompanion/App/SystemExtensionPrototype.swift
app_entitlements=macos/HeimdallCompanion/App/HeimdallCompanion.entitlements
project=macos/HeimdallCompanion/HeimdallCompanion.xcodeproj/project.pbxproj
swift_control=macos/Sources/HeimdallMacControl/MacControl.swift
swift_tests=macos/Tests/HeimdallMacControlTests/MacControlTests.swift

grep -Fq 'final class TransparentProxyProvider: NETransparentProxyProvider' "$provider"
grep -Fq 'prototype activation is disabled' "$provider"
grep -Fq 'flow.closeReadWithError(error)' "$provider"
grep -Fq 'flow.closeWriteWithError(error)' "$provider"
grep -Eq '^[[:space:]]*return true$' "$provider"
if grep -Eq '^[[:space:]]*return false$' "$provider"; then
  printf 'the transparent prototype can return a flow to its normal route\n' >&2
  exit 1
fi

grep -Fq 'NEProvider.startSystemExtensionMode()' \
  macos/HeimdallCompanion/Extension/main.swift
grep -Fq '<key>com.apple.networkextension.app-proxy</key>' "$provider_info"
grep -Fq '<string>app-proxy-provider-systemextension</string>' \
  "$provider_entitlements"
grep -Fq '<key>com.apple.developer.system-extension.install</key>' \
  "$app_entitlements"
grep -Fq 'OSSystemExtensionRequest.activationRequest' "$app_source"

if rg -q \
  'OSSystemExtensionManager\.shared\.submitRequest|NETransparentProxyManager|saveToPreferences' \
  macos; then
  printf 'the compile-only companion prototype can install network configuration\n' >&2
  exit 1
fi

grep -Fq 'productType = "com.apple.product-type.system-extension"' "$project"
# Why: the Xcode build setting must remain literal in the project file.
# shellcheck disable=SC2016
grep -Fq 'dstPath = "$(SYSTEM_EXTENSIONS_FOLDER_PATH)"' "$project"
grep -Fq 'dstSubfolderSpec = 16' "$project"

grep -Fq 'public let macControlContract = "heimdall.macos.control/v1"' \
  "$swift_control"
grep -Fq 'eb390e73297ba508ab1ae2ad10cb22bb86d8b92502e277fc2c2e08ee61138569' \
  "$swift_tests"

printf 'macOS companion source contract OK\n'
