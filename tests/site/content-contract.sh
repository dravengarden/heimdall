#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

source_tracks=$(grep -Ec '^### [0-9]+\. ' ROADMAP.md)
site_tracks=$(grep -oE '>Track [0-9]{2}<' site/docs/roadmap.html | wc -l)

[[ "$site_tracks" -eq "$source_tracks" ]] || {
  printf 'roadmap track count drifted: source=%s site=%s\n' \
    "$source_tracks" "$site_tracks" >&2
  exit 1
}

for index in $(seq 1 "$source_tracks"); do
  track=$(printf '%02d' "$index")
  grep -Fq ">Track $track<" site/docs/roadmap.html || {
    printf 'site roadmap is missing Track %s\n' "$track" >&2
    exit 1
  }
done

for heading in \
  'Daemonless lifecycle' \
  'Agent event evidence' \
  'Proxy compatibility' \
  'TLS boundaries' \
  'Capture analysis' \
  'Performance and observability' \
  'Native ARM completion'; do
  grep -Fq "<h3>$heading</h3>" site/docs/roadmap.html || {
    printf 'site roadmap is missing track heading: %s\n' "$heading" >&2
    exit 1
  }
done

for runbook in docs/runbook.md site/docs/runbook.html; do
  grep -Fq 'native archive, npm, PyPI, and Cargo package' "$runbook" || {
    printf '%s does not describe all four package gates\n' "$runbook" >&2
    exit 1
  }
  if grep -Fq 'both package checks' "$runbook"; then
    printf '%s retained the obsolete two-package claim\n' "$runbook" >&2
    exit 1
  fi
  grep -Fq 'just test-vm-ubuntu' "$runbook" || {
    printf '%s does not expose the Ubuntu acceptance gate\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'Ubuntu 24.04' "$runbook" || {
    printf '%s does not identify the pinned compatibility guest\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'parent-death' "$runbook" || {
    printf '%s does not expose Ubuntu owner-death acceptance\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'runtime and relay TLS' "$runbook" || {
    printf '%s does not expose Ubuntu TLS-mode acceptance\n' "$runbook" >&2
    exit 1
  }
done

grep -A4 '^release-check:' justfile | grep -Fq 'just test-vm-ubuntu' || {
  printf 'release-check does not include the Ubuntu acceptance gate\n' >&2
  exit 1
}

for status_page in README.md ROADMAP.md site/docs/roadmap.html; do
  grep -Fq 'Ubuntu 24.04' "$status_page" || {
    printf '%s does not report Ubuntu compatibility coverage\n' "$status_page" >&2
    exit 1
  }
done

printf 'documentation site contract OK\n'
