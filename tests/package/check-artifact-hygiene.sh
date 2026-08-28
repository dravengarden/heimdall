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

sections=$(readelf -W -S "$artifact")
debug_sections=$(printf '%s\n' "$sections" \
  | grep -E '\.(z?debug|rel\.debug|rela\.debug|gnu_debug)[[:alnum:]_.-]*' \
  || true)
if [ -n "$debug_sections" ]; then
  echo 'artifact contains DWARF sections:' >&2
  printf '%s\n' "$debug_sections" >&2
  exit 1
fi

case "$kind" in
  ebpf)
    for section in .BTF .BTF.ext .rel.BTF .rel.BTF.ext; do
      printf '%s\n' "$sections" | grep -F " $section " >/dev/null || {
        printf 'eBPF artifact is missing required section %s\n' "$section" >&2
        exit 1
      }
    done
    ;;
  linux-executable)
    if readelf -l "$artifact" | grep -q 'interpreter'; then
      echo 'release binary has a dynamic ELF interpreter' >&2
      exit 1
    fi
    if readelf -d "$artifact" | grep -q 'NEEDED'; then
      echo 'release binary has dynamic library dependencies' >&2
      exit 1
    fi
    ;;
  *)
    printf 'unknown artifact kind: %s\n' "$kind" >&2
    exit 1
    ;;
esac
