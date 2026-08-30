#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Darwin ]] || {
  printf 'macOS interpose feasibility requires macOS\n' >&2
  exit 1
}
[[ $(uname -m) == arm64 ]] || {
  printf 'macOS interpose feasibility requires Apple silicon\n' >&2
  exit 1
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-interpose-feasibility.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

xcrun clang -dynamiclib -arch arm64 \
  -o "$work_dir/libheimdall_probe.dylib" -x c - <<'SOURCE'
#include <stdio.h>

__attribute__((constructor)) static void heimdall_probe_loaded(void) {
    fputs("HEIMDALL_INTERPOSE_LOADED\n", stderr);
}
SOURCE

xcrun clang -arch arm64 -o "$work_dir/plain-target" -x c - <<'SOURCE'
#include <stdio.h>

int main(void) {
    puts("HEIMDALL_TARGET_OK");
    return 0;
}
SOURCE

codesign --force --sign - "$work_dir/libheimdall_probe.dylib" >/dev/null 2>&1
codesign --force --sign - "$work_dir/plain-target" >/dev/null 2>&1
cp "$work_dir/plain-target" "$work_dir/hardened-target"
codesign --force --sign - --options runtime \
  "$work_dir/hardened-target" >/dev/null 2>&1

plain_output=$(
  DYLD_INSERT_LIBRARIES="$work_dir/libheimdall_probe.dylib" \
    "$work_dir/plain-target" 2>&1
)
grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$plain_output" || {
  printf 'ordinary dynamic target did not load the injected library\n' >&2
  exit 1
}
grep -Fq 'HEIMDALL_TARGET_OK' <<<"$plain_output" || {
  printf 'ordinary dynamic target did not complete\n' >&2
  exit 1
}

set +e
hardened_output=$(
  DYLD_INSERT_LIBRARIES="$work_dir/libheimdall_probe.dylib" \
    "$work_dir/hardened-target" 2>&1
)
hardened_status=$?
set -e
if grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$hardened_output"; then
  printf 'Hardened Runtime target unexpectedly loaded the injected library\n' >&2
  exit 1
fi

set +e
protected_output=$(
  DYLD_INSERT_LIBRARIES="$work_dir/libheimdall_probe.dylib" \
    /usr/bin/true 2>&1
)
protected_status=$?
set -e
if grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$protected_output"; then
  printf 'SIP-protected target unexpectedly loaded the injected library\n' >&2
  exit 1
fi

printf 'macOS interpose feasibility boundary OK '
printf '(ordinary=loaded hardened=blocked:%s sip=blocked:%s)\n' \
  "$hardened_status" "$protected_status"
