#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

current_docs=(
  AGENTS.md
  README.md
  ROADMAP.md
  docs
  skills/heimdall
  site
  packaging/cargo/README.md
)

if rg -n 'heimdall\.agent/v(8|9)' "${current_docs[@]}"; then
  fail 'current documentation still names a retired Agent contract'
fi

if rg -n -- '--backend macos-(explicit|interpose)|backend = "macos-(explicit|interpose)"|"backend": "macos-(explicit|interpose)"' \
  "${current_docs[@]}"; then
  fail 'current documentation still uses a retired platform-specific backend value'
fi

for backend in ebpf interpose explicit; do
  grep -Fq "$backend" docs/config.md || fail "config docs omit backend: $backend"
  grep -Fq "$backend" site/docs/configuration.html || fail "site config omits backend: $backend"
done

for page in site/index.html site/docs/*.html; do
  grep -Fq 'name="viewport"' "$page" || fail "$page has no mobile viewport"
done

for page in README.md docs/product-contract.md docs/architecture.md \
  skills/heimdall/SKILL.md site/docs/product-contract.html \
  site/docs/architecture.html site/docs/macos.html; do
  grep -Fq 'interpose' "$page" || fail "$page omits interpose"
  grep -Fq 'explicit' "$page" || fail "$page omits explicit"
  grep -Fq 'daemon' "$page" || fail "$page omits the daemon boundary"
done

for page in docs/design/macos-backend.md docs/design/macos-fallbacks.md \
  site/docs/macos.html; do
  for boundary in \
    'interposed_dynamic_calls' \
    'client_can_bypass' \
    'direct syscalls' \
    'Hardened Runtime' \
    'NETransparentProxyProvider' \
    'Developer ID' \
    'notar' \
    'Gatekeeper'; do
    grep -Fiq "$boundary" "$page" || fail "$page omits boundary: $boundary"
  done
done

grep -Fq 'enum ExecutionBackend' heimdall/src/internal/config.rs ||
  fail 'the strict config does not own execution backend selection'
for variant in Ebpf Interpose Explicit; do
  grep -Fq "$variant" heimdall/src/internal/config.rs ||
    fail "execution backend enum omits $variant"
done
if grep -Fq 'Auto,' heimdall/src/internal/config.rs; then
  fail 'execution backend enum still permits auto selection'
fi

[[ $(grep -c 'backend.*ebpf' heimdall/src/cli/init.rs) -ge 3 ]] ||
  fail 'all three starter templates must select ebpf explicitly'

grep -Fq 'mod interpose;' heimdall/src/main.rs ||
  fail 'the shared target root does not own interpose'
grep -Fq 'mod explicit_proxy;' heimdall/src/main.rs ||
  fail 'the shared target root does not own explicit proxying'
grep -Fq 'include_bytes!' heimdall/src/interpose.rs ||
  fail 'the native interpose library is not embedded in the CLI'
grep -Fq 'interpose/**' heimdall/Cargo.toml ||
  fail 'the crates.io source package omits the interpose source'

for hook in connect getaddrinfo send sendto sendmsg; do
  grep -Fq "heimdall_$hook" heimdall/interpose/interpose.c ||
    fail "the native library omits $hook"
done
grep -Fq 'SOCKS_USERNAME_PASSWORD' heimdall/interpose/interpose.c ||
  fail 'the interpose frontend is not authenticated'
grep -Fq 'HEIMDALL_INTERPOSE_TOKEN' heimdall/interpose/interpose.c ||
  fail 'the injected library has no per-run credential'

grep -Fq 'ExecutionBackend::Interpose' heimdall/src/cli/run.rs ||
  fail 'Linux run cannot select interpose'
grep -Fq 'ExecutionBackend::Explicit' heimdall/src/cli/run.rs ||
  fail 'Linux run cannot select explicit'
grep -Fq 'ExecutionBackend::Interpose' heimdall/src/main_macos.rs ||
  fail 'macOS run cannot select interpose'
grep -Fq 'ExecutionBackend::Explicit' heimdall/src/main_macos.rs ||
  fail 'macOS run cannot select explicit'
if rg -q 'explicit_architecture_unavailable|native_arch_supported' heimdall/src; then
  fail 'explicit still has an architecture gate'
fi
grep -Fq 'x86_64-apple-darwin' rust-toolchain.toml ||
  fail 'the pinned toolchain omits Intel macOS explicit support'
grep -A3 '^check-macos:' justfile | grep -Fq 'x86_64-apple-darwin' ||
  fail 'the Darwin compile gate omits Intel macOS'
grep -A5 '^test-macos-explicit-native:' justfile |
  grep -Fq 'run-explicit-acceptance.sh' ||
  fail 'the architecture-neutral macOS explicit gate is missing'

grep -Fq 'heimdall.agent/v10' heimdall/src/cli/mod.rs ||
  fail 'Linux agent does not expose v10'
grep -Fq 'heimdall.agent/v10' heimdall/src/cli/agent_macos.rs ||
  fail 'macOS agent does not expose v10'
for boundary in \
  '"backend": "interpose"' \
  '"failure_boundary": "interposed_calls_only"' \
  '"routing_implemented": true' \
  '"authenticated_constructor_implemented": true' \
  '"uninterposed_udp_calls_bypass": true'; do
  grep -Fq "$boundary" heimdall/src/cli/agent_macos.rs ||
    fail "macOS Agent v10 omits: $boundary"
done

for boundary in \
  '"status": "deferred"' \
  '"release_included": false' \
  '"provider_wired": false' \
  '"activation_enabled": false'; do
  grep -Fq "$boundary" heimdall/src/cli/agent_macos.rs ||
    fail "the deferred Network Extension boundary drifted: $boundary"
done

grep -Fq '"backend": { "const": "interpose" }' \
  heimdall/schemas/heimdall.event.v1.schema.json ||
  fail 'event schema omits interpose source'
grep -Fq '"scope": { "const": "interposed_dynamic_calls" }' \
  heimdall/schemas/heimdall.event.v1.schema.json ||
  fail 'event schema omits interpose scope'
grep -Fq '"backend": { "const": "explicit" }' \
  heimdall/schemas/heimdall.event.v1.schema.json ||
  fail 'event schema omits explicit source'
grep -Fq '"scope": { "const": "cooperative_environment" }' \
  heimdall/schemas/heimdall.event.v1.schema.json ||
  fail 'event schema omits explicit scope'

grep '^verify:' justfile | grep -Fq 'test-linux-interpose-native' ||
  fail 'verify omits Linux native interpose acceptance'
grep -A8 '^test-macos-native:' justfile | grep -Fq 'run-interpose-acceptance.sh' ||
  fail 'the macOS native gate omits interpose acceptance'
grep -A2 '^test-macos-interpose-native:' justfile |
  grep -Fq 'run-interpose-acceptance.sh' ||
  fail 'the dedicated macOS interpose gate is missing'

grep -Fq 'HEIMDALL_INTERPOSE_SIGNING_IDENTITY_SHA1' \
  scripts/build-macos-release-assets ||
  fail 'the macOS builder does not sign the embedded dylib with the release identity'
grep -Fq 'run-interpose-acceptance.sh' scripts/build-macos-release-assets ||
  fail 'the macOS package builder omits interpose acceptance'
if grep -Fq 'run-companion-acceptance.sh' scripts/build-macos-release-assets; then
  fail 'the macOS package builder invokes the deferred companion'
fi

tests/macos/check-companion-contract.sh

if rg -q 'Command::new\("(networksetup|scutil)"' heimdall/src; then
  fail 'a reduced backend attempts to modify system proxy settings'
fi

for evidence_page in docs/design/agent-event-log.md docs/runbook.md \
  skills/heimdall/references/commands.md skills/heimdall/references/events.md \
  site/docs/commands.html; do
  grep -Fq 'heimdall.logs.flow/v1' "$evidence_page" ||
    fail "$evidence_page omits the per-flow evidence contract"
  grep -Fq 'logs flow --run' "$evidence_page" ||
    fail "$evidence_page omits bounded flow inspection"
done

grep -A8 '^release-check:' justfile | grep -Fq 'just test-vm-ubuntu' ||
  fail 'release-check omits Ubuntu acceptance'
grep -A8 '^release-check:' justfile | grep -Fq 'just test-vm-debian' ||
  fail 'release-check omits Debian acceptance'
grep -A8 '^release-check:' justfile | grep -Fq 'just test-package-macos' ||
  fail 'release-check omits macOS package acceptance'
if grep -A8 '^release-check:' justfile | grep -Fq 'benchmark-vm-'; then
  fail 'release-check unexpectedly includes performance baselines'
fi

printf 'documentation site contract OK\n'
