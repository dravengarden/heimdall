#!/bin/sh
set -eu

artifact=${1:?usage: check-artifact-hygiene.sh ARTIFACT KIND}
kind=${2:?usage: check-artifact-hygiene.sh ARTIFACT KIND}

[ -f "$artifact" ] || {
  printf 'artifact does not exist: %s\n' "$artifact" >&2
  exit 1
}

forbidden_paths=$(LC_ALL=C strings -a "$artifact" \
  | grep -E '/build/|/nix/store/|/home/[^[:space:]]*|/Users/[^[:space:]]*' \
  || true)
if [ -n "$forbidden_paths" ]; then
  echo 'artifact contains private or build-time paths:' >&2
  printf '%s\n' "$forbidden_paths" >&2
  exit 1
fi

case "$kind" in
  ebpf)
    sections=$(readelf -W -S "$artifact")
    debug_sections=$(printf '%s\n' "$sections" \
      | grep -E '\.(z?debug|rel\.debug|rela\.debug|gnu_debug)[[:alnum:]_.-]*' \
      || true)
    if [ -n "$debug_sections" ]; then
      echo 'artifact contains DWARF sections:' >&2
      printf '%s\n' "$debug_sections" >&2
      exit 1
    fi
    for section in .BTF .BTF.ext .rel.BTF .rel.BTF.ext; do
      printf '%s\n' "$sections" | grep -F " $section " >/dev/null || {
        printf 'eBPF artifact is missing required section %s\n' "$section" >&2
        exit 1
      }
    done
    ;;
  linux-executable)
    sections=$(readelf -W -S "$artifact")
    debug_sections=$(printf '%s\n' "$sections" \
      | grep -E '\.(z?debug|rel\.debug|rela\.debug|gnu_debug)[[:alnum:]_.-]*' \
      || true)
    if [ -n "$debug_sections" ]; then
      echo 'artifact contains DWARF sections:' >&2
      printf '%s\n' "$debug_sections" >&2
      exit 1
    fi
    if readelf -l "$artifact" | grep -q 'interpreter'; then
      echo 'release binary has a dynamic ELF interpreter' >&2
      exit 1
    fi
    if readelf -d "$artifact" | grep -q 'NEEDED'; then
      echo 'release binary has dynamic library dependencies' >&2
      exit 1
    fi
    ;;
  macos-executable)
    file "$artifact" | grep -Fq 'Mach-O 64-bit executable arm64' || {
      echo 'release binary is not an arm64 Mach-O executable' >&2
      exit 1
    }
    [ "$(lipo -archs "$artifact")" = arm64 ] || {
      echo 'release binary has an unexpected Mach-O architecture set' >&2
      exit 1
    }
    if otool -l "$artifact" | grep -Fq 'segname __DWARF'; then
      echo 'release binary contains a Mach-O DWARF segment' >&2
      exit 1
    fi
    if otool -l "$artifact" | grep -Fq 'cmd LC_RPATH'; then
      echo 'release binary contains an LC_RPATH load command' >&2
      exit 1
    fi
    minimum_macos=$(otool -l "$artifact" | awk '
      $1 == "cmd" && $2 == "LC_BUILD_VERSION" { build = 1; next }
      build && $1 == "minos" { print $2; exit }
    ')
    [ "$minimum_macos" = 11.0 ] || {
      printf 'release binary has an unexpected minimum macOS version: %s\n' \
        "$minimum_macos" >&2
      exit 1
    }
    otool -L "$artifact" | sed '1d' | awk '{print $1}' | while IFS= read -r dependency; do
      case "$dependency" in
        /usr/lib/*|/System/Library/*) ;;
        *) printf 'release binary has a non-system dependency: %s\n' "$dependency" >&2; exit 1 ;;
      esac
    done
    ;;
  *)
    printf 'unknown artifact kind: %s\n' "$kind" >&2
    exit 1
    ;;
esac
