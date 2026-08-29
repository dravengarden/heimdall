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
  'Native ARM completion' \
  'macOS backend'; do
  grep -Fq "<h3>$heading</h3>" site/docs/roadmap.html || {
    printf 'site roadmap is missing track heading: %s\n' "$heading" >&2
    exit 1
  }
done

for macos_page in \
  docs/design/macos-backend.md \
  docs/product-contract.md \
  site/docs/macos.html \
  site/docs/product-contract.html; do
  for boundary in \
    'NETransparentProxyProvider' \
    'NEAppProxyProvider' \
    'process group' \
    'persistent user-managed Heimdall daemon' \
    'not available'; do
    grep -Fq "$boundary" "$macos_page" || {
      printf '%s does not preserve the macOS boundary: %s\n' \
        "$macos_page" "$boundary" >&2
      exit 1
    }
  done
done

grep -Fq 'aarch64-apple-darwin' rust-toolchain.toml || {
  printf 'the pinned toolchain does not include the Darwin check target\n' >&2
  exit 1
}

grep -A6 '^check-macos:' justfile | grep -Fq 'aarch64-apple-darwin' || {
  printf 'check-macos does not type-check the pinned Darwin target\n' >&2
  exit 1
}

grep '^verify:' justfile | grep -Fq 'check-macos' || {
  printf 'verify does not include the Darwin compile boundary\n' >&2
  exit 1
}

for macos_runbook in docs/runbook.md site/docs/runbook.html; do
  grep -Fq 'just check-macos' "$macos_runbook" || {
    printf '%s does not expose the Darwin compile boundary\n' \
      "$macos_runbook" >&2
    exit 1
  }
  grep -Fq 'aarch64-apple-darwin' "$macos_runbook" || {
    printf '%s does not name the pinned Darwin target\n' \
      "$macos_runbook" >&2
    exit 1
  }
done

for evidence_page in \
  docs/design/agent-event-log.md \
  docs/runbook.md \
  skills/heimdall/references/commands.md \
  skills/heimdall/references/events.md \
  site/docs/commands.html; do
  grep -Fq 'heimdall.logs.flow/v1' "$evidence_page" || {
    printf '%s does not name the per-flow evidence contract\n' \
      "$evidence_page" >&2
    exit 1
  }
  grep -Fq 'logs schema --flow v1' "$evidence_page" || {
    printf '%s does not expose the offline flow schema\n' \
      "$evidence_page" >&2
    exit 1
  }
  grep -Fq 'logs flow --run' "$evidence_page" || {
    printf '%s does not expose bounded flow explanation\n' \
      "$evidence_page" >&2
    exit 1
  }
done

for contract_page in docs/product-contract.md site/docs/product-contract.html; do
  grep -Fq 'heimdall.logs.flow/v1' "$contract_page" || {
    printf '%s does not preserve the per-flow evidence boundary\n' \
      "$contract_page" >&2
    exit 1
  }
done

for runbook in docs/runbook.md site/docs/runbook.html; do
  grep -Fq 'just sync-ebpf' "$runbook" || {
    printf '%s does not expose the canonical eBPF sync command\n' "$runbook" >&2
    exit 1
  }
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
  grep -Fq 'just test-vm-debian' "$runbook" || {
    printf '%s does not expose the Debian acceptance gate\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'Debian 13' "$runbook" || {
    printf '%s does not identify the pinned Debian guest\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'private_mount' "$runbook" || {
    printf '%s does not expose Debian private-mount acceptance\n' "$runbook" >&2
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
  grep -Fq 'fake DNS' "$runbook" || {
    printf '%s does not expose Ubuntu fake-DNS acceptance\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'user-namespace restriction' "$runbook" || {
    printf '%s does not preserve the Ubuntu security boundary\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'decision.resolver' "$runbook" || {
    printf '%s does not expose resolver preflight\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'actions.resolver_inspect' "$runbook" || {
    printf '%s does not expose shell-safe resolver inspection\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'fake_dns_user_namespace_disabled' "$runbook" || {
    printf '%s does not expose the stable userns blocker\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'just benchmark-vm-ubuntu' "$runbook" || {
    printf '%s does not expose the Ubuntu performance baseline\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'just benchmark-vm-debian' "$runbook" || {
    printf '%s does not expose the Debian performance baseline\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'ca_material_ready' "$runbook" || {
    printf '%s does not expose relay CA preflight\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'relay_ca_material_invalid' "$runbook" || {
    printf '%s does not expose relay CA repair diagnostics\n' "$runbook" >&2
    exit 1
  }
  grep -Fq 'not part of' "$runbook" || {
    printf '%s does not separate performance from release gates\n' "$runbook" >&2
    exit 1
  }
done

for contract_page in docs/product-contract.md site/docs/product-contract.html; do
  grep -Fq 'decision.resolver' "$contract_page" || {
    printf '%s does not define resolver decision evidence\n' "$contract_page" >&2
    exit 1
  }
  grep -Fq 'actions.resolver_inspect' "$contract_page" || {
    printf '%s does not preserve argv-safe resolver inspection\n' "$contract_page" >&2
    exit 1
  }
done

grep -A5 '^release-check:' justfile | grep -Fq 'just test-vm-ubuntu' || {
  printf 'release-check does not include the Ubuntu acceptance gate\n' >&2
  exit 1
}

grep -A5 '^release-check:' justfile | grep -Fq 'just test-vm-debian' || {
  printf 'release-check does not include the Debian acceptance gate\n' >&2
  exit 1
}

grep -Fq 'benchmark-vm-ubuntu:' justfile || {
  printf 'justfile does not expose the Ubuntu performance baseline\n' >&2
  exit 1
}

grep -Fq 'benchmark-vm-debian:' justfile || {
  printf 'justfile does not expose the Debian performance baseline\n' >&2
  exit 1
}

if grep -A5 '^release-check:' justfile | grep -Fq 'benchmark-vm-'; then
  printf 'release-check unexpectedly includes a performance baseline\n' >&2
  exit 1
fi

for status_page in README.md ROADMAP.md site/docs/roadmap.html; do
  grep -Fq 'Ubuntu 24.04' "$status_page" || {
    printf '%s does not report Ubuntu compatibility coverage\n' "$status_page" >&2
    exit 1
  }
  grep -Fq 'Debian 13' "$status_page" || {
    printf '%s does not report Debian compatibility coverage\n' "$status_page" >&2
    exit 1
  }
done

printf 'documentation site contract OK\n'
