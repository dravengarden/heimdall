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
done

printf 'documentation site contract OK\n'
