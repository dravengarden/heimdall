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
    'macos-explicit' \
    'cooperative' \
    'macos-transparent' \
    'NETransparentProxyProvider' \
    'persistent user-managed Heimdall daemon'; do
    grep -Fq "$boundary" "$macos_page" || {
      printf '%s does not preserve the macOS boundary: %s\n' \
        "$macos_page" "$boundary" >&2
      exit 1
    }
  done
done

for macos_design in docs/design/macos-backend.md site/docs/macos.html; do
  for boundary in 'NEAppProxyProvider' 'process group' 'official macOS'; do
    grep -Fiq "$boundary" "$macos_design" || {
      printf '%s does not preserve the deep macOS boundary: %s\n' \
        "$macos_design" "$boundary" >&2
      exit 1
    }
  done
done

for macos_package_page in \
  docs/design/macos-backend.md \
  docs/releasing.md \
  docs/runbook.md \
  site/docs/macos.html \
  site/docs/runbook.html; do
  rg -iq 'package[- ]mechanics' "$macos_package_page" || {
    printf '%s does not preserve the macOS package-mechanics boundary\n' \
      "$macos_package_page" >&2
    exit 1
  }
  for boundary in 'Developer ID' 'notar' 'Gatekeeper' 'uninstall'; do
    grep -Fiq "$boundary" "$macos_package_page" || {
      printf '%s does not preserve the macOS package boundary: %s\n' \
        "$macos_package_page" "$boundary" >&2
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

grep -A1 '^check-macos:' justfile | grep -Fq -- '--all-targets' || {
  printf 'check-macos does not type-check portable protocol tests\n' >&2
  exit 1
}

grep '^verify:' justfile | grep -Fq 'check-macos' || {
  printf 'verify does not include the Darwin compile boundary\n' >&2
  exit 1
}

grep -Fq 'mod event_log;' heimdall/src/main.rs || {
  printf 'the event store is not owned by the shared target root\n' >&2
  exit 1
}

grep -Fq 'mod relay_transport;' heimdall/src/main.rs || {
  printf 'the outbound relay transport is not owned by the shared target root\n' >&2
  exit 1
}

grep -Fq 'pub(crate) async fn open_socks5_udp_association' \
  heimdall/src/relay_transport.rs || {
  printf 'the shared relay transport does not own SOCKS5 UDP setup\n' >&2
  exit 1
}

if grep -Fq 'async fn socks5_connect' heimdall/src/main_linux.rs; then
  printf 'the Linux root still owns the SOCKS5 CONNECT implementation\n' >&2
  exit 1
fi

grep -Fq 'Logs(crate::cli::logs::LogsCmd)' heimdall/src/main_macos.rs || {
  printf 'the Darwin backend does not expose portable log inspection\n' >&2
  exit 1
}

grep -Fq '"offline_schema_validation": true' heimdall/src/cli/agent_macos.rs || {
  printf 'the Darwin agent does not advertise offline log validation\n' >&2
  exit 1
}

grep -Fq 'mod explicit_proxy;' heimdall/src/main.rs || {
  printf 'the shared target root does not own the explicit proxy backend\n' >&2
  exit 1
}

grep -Fq 'mod macos_control;' heimdall/src/main.rs || {
  printf 'the shared target root does not own the macOS control protocol\n' >&2
  exit 1
}

grep -Fq 'heimdall.macos.control/v1' \
  heimdall/schemas/heimdall.macos.control.v1.schema.json || {
  printf 'the macOS control protocol does not have a versioned schema\n' >&2
  exit 1
}

for macos_control_page in \
  docs/design/macos-backend.md \
  docs/design/macos-control-protocol.md \
  ROADMAP.md \
  site/docs/macos.html \
  site/docs/roadmap.html; do
  for boundary in \
    'heimdall.macos.control/v1' \
    'optional'; do
    grep -Fq "$boundary" "$macos_control_page" || {
      printf '%s does not preserve the macOS attribution boundary: %s\n' \
        "$macos_control_page" "$boundary" >&2
      exit 1
    }
  done
done

for macos_attribution_page in \
  docs/design/macos-backend.md \
  docs/design/macos-control-protocol.md \
  ROADMAP.md \
  site/docs/macos.html; do
  for boundary in 'sourceAppAuditToken' 'native evidence'; do
    grep -Fq "$boundary" "$macos_attribution_page" || {
      printf '%s does not preserve the native attribution gate: %s\n' \
        "$macos_attribution_page" "$boundary" >&2
      exit 1
    }
  done
done

if rg -Fq 'process-group best-effort' docs/design/macos-backend.md site/docs/macos.html; then
  printf 'macOS docs still claim an unproven process-group boundary\n' >&2
  exit 1
fi

grep -Fq '"provider_wired": false' heimdall/src/cli/agent_macos.rs || {
  printf 'the Darwin agent does not report the control protocol as unwired\n' >&2
  exit 1
}

grep -Fq '"strict_command_scope_proven": false' \
  heimdall/src/cli/agent_macos.rs || {
  printf 'the Darwin agent claims unproven transparent command scope\n' >&2
  exit 1
}

if rg -Fq '#[value(name = "macos-transparent")]' heimdall/src/main_macos.rs; then
  printf 'the unavailable transparent backend is selectable\n' >&2
  exit 1
fi

grep -Fq 'TcpListener::bind((Ipv4Addr::LOCALHOST, 0))' heimdall/src/explicit_proxy.rs || {
  printf 'macos-explicit does not bind a kernel-assigned loopback listener\n' >&2
  exit 1
}

grep -Fq 'MacBackend::Explicit' heimdall/src/main_macos.rs || {
  printf 'Darwin run does not require explicit backend selection\n' >&2
  exit 1
}

grep -Fq '"execute_prefix": execute_prefix' heimdall/src/cli/agent_macos.rs || {
  printf 'the Darwin agent does not publish its guarded execution action\n' >&2
  exit 1
}

grep -Fq '"scope": { "const": "cooperative_environment" }' \
  heimdall/schemas/heimdall.event.v1.schema.json || {
  printf 'the event schema does not encode the cooperative source boundary\n' >&2
  exit 1
}

if rg -q 'Command::new\("(networksetup|scutil)"' heimdall/src; then
  printf 'the macOS backend attempts to modify system proxy settings\n' >&2
  exit 1
fi

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
  grep -Fq 'JSONL' "$macos_runbook" || {
    printf '%s does not document the portable evidence boundary\n' \
      "$macos_runbook" >&2
    exit 1
  }
  grep -Fq 'relay_transport' "$macos_runbook" || {
    printf '%s does not document the portable transport boundary\n' \
      "$macos_runbook" >&2
    exit 1
  }
  grep -Fq 'just test-macos-native' "$macos_runbook" || {
    printf '%s does not expose the native explicit acceptance gate\n' \
      "$macos_runbook" >&2
    exit 1
  }
  grep -Fq 'just test-package-macos' "$macos_runbook" || {
    printf '%s does not expose the native package-mechanics gate\n' \
      "$macos_runbook" >&2
    exit 1
  }
  grep -Fq 'cooperative' "$macos_runbook" || {
    printf '%s does not preserve the reduced explicit scope\n' \
      "$macos_runbook" >&2
    exit 1
  }
done

for transport_page in \
  docs/architecture.md \
  docs/design/macos-backend.md \
  site/docs/architecture.html \
  site/docs/macos.html; do
  grep -Fq 'relay_transport' "$transport_page" || {
    printf '%s does not document the shared outbound transport boundary\n' \
      "$transport_page" >&2
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
  for package_gate in 'just test-package' 'just test-package-macos' 'npm' 'PyPI' 'Cargo'; do
    grep -Fq "$package_gate" "$runbook" || {
      printf '%s does not describe the package gate: %s\n' \
        "$runbook" "$package_gate" >&2
      exit 1
    }
  done
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

grep -A7 '^release-check:' justfile | grep -Fq 'just test-vm-ubuntu' || {
  printf 'release-check does not include the Ubuntu acceptance gate\n' >&2
  exit 1
}

grep -A7 '^release-check:' justfile | grep -Fq 'just test-vm-debian' || {
  printf 'release-check does not include the Debian acceptance gate\n' >&2
  exit 1
}

grep -A7 '^release-check:' justfile | grep -Fq 'just test-package-macos' || {
  printf 'release-check does not include the native macOS package gate\n' >&2
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

if grep -A7 '^release-check:' justfile | grep -Fq 'benchmark-vm-'; then
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
