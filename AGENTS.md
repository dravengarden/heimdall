# AGENTS.md — heimdall

Operating rules for Codex working in this repo. Humans should also follow
these rules; this file is the standardized project entry point.

## Project at a glance

- **What**: command-scoped transparent egress proxy for CLI processes
  started through `heimdall run`, written
  in Rust + aya eBPF.
- **Where to start reading**: [`README.md`](README.md) for the
  90-second pitch, [`docs/architecture.md`](docs/architecture.md) for
  the data flow + control loops.
- **Where to start coding**: pick a doc that mentions the file you
  want to change. Most non-trivial changes touch `heimdall/` (CLI and
  daemon), `heimdall-ebpf/` (kernel programs), or `heimdall-config/`
  (the small format-independent schema). See `docs/runbook.md` for build order.

## House rules

### No private info in code (including comments)

This is a public OSS repo. **Don't commit private hostnames, LAN IPs,
internal domain names, employer/org-specific identifiers, real user
paths, or colleagues' emails** — not in source, not in comments, not
in docs, not in commit messages, not in test fixtures. The user's own
git author email is the only exception (it's already in commit
metadata; don't bother scrubbing).

When you need a stand-in, use these placeholders consistently:

| Concept | Placeholder |
|---|---|
| Generic corporate VPN connection name | `corp` (or pick another generic noun — `internal`, `office` — for examples) |
| Public-internet connection name | `default` |
| Host LAN IP | `<HOST_IP>` (or `127.0.0.1` when an example would actually run on localhost) |
| Upstream SOCKS5 IP | `<UPSTREAM_IP>` |
| Hostname-of-this-host | `<host>` or `localhost` |
| Internal hostnames | `internal.example.com`, `vault.prod.internal`, etc. |
| User's checkout path | `~/heimdall` (or `<repo>` in prose) |
| Cluster admin path | `/etc/heimdall/...` is fine (that's where heimdall actually installs); avoid host-config paths like `/etc/<host-config>/...` |
| Colleague's email | `your.colleague@example.com` |

If you discover an existing private string while editing, scrub it in
the same change rather than writing around it. The PR template
includes a checklist box for this.

### Comment style: WHY, not WHAT

A reader can read the code. Comment hidden constraints, past
incidents, kernel quirks, surprising invariants. Skip narration
("loop over units", "handle error case"). The eBPF programs in
`heimdall-ebpf/src/main.rs` and the cgroup policy glue in
`heimdall/src/policy.rs` are the reference style — every
non-obvious line has a "Why:" block.

### Don't add backwards-compatibility shims

Pre-1.0. Schema changes don't need migration helpers, removed fields
don't need deprecation warnings, renamed types don't need re-exports.
Just change the code. Bump `CHANGELOG.md` if it's user-visible.

### Build flow

eBPF must be built **before** the userspace daemon (it's
`include_bytes!`'d into the binary). `docs/runbook.md` has the
canonical incantation.

```bash
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'
nix develop -c just verify
```

### Config changes stay small

`heimdall-config/src/lib.rs` is the source of truth. Keep the three embedded
`heimdall init` templates, `docs/config.md`, and
`skills/heimdall/references/config.md` in sync. Every syntax must enter the same
strict schema; do not add a workload policy language.

### Commit messages

- Subject in imperative voice (`add X`, not `added X`).
- Optional `<scope>: ` prefix when touching one area (`run: …`,
  `dns: …`, `runbook: …`, `ebpf: …`).
- Body explains WHY when non-obvious; reference incidents/links.
- Don't add automated-agent `Co-Authored-By` lines. The agent
  isn't a coauthor in the legal sense and the noise piles up over
  time. Attribution belongs in the PR description if anywhere.

### Don't touch what you don't need to

Bug fixes shouldn't drag in surrounding cleanup. One-shot operations
shouldn't grow helpers "for next time". Three near-duplicate lines
beat a premature abstraction. Keep PRs tight; the reviewer will
remember to ask for more if needed.

## Pitfalls (specific to this codebase)

- `parking_lot::MutexGuard` is **not Send across `.await`**. Take
  what you need out of the lock into a local before any await point.
  This caused mysterious axum Handler trait failures historically.
- **One help command, two verbosity levels.** Don't multiply flags.
  - `heimdall help [path…]` — concise per-command help (same content
    as `<sub> --help`). Drill with `heimdall help config validate` etc.
  - `heimdall help [path…] -v` — verbose: recurse into every
    subcommand and inline every option. **AI agents that want the
    full surface in one read should use this.**
  - `heimdall --help` / `-h` — kept for muscle memory; identical to
    `heimdall help` at the corresponding scope.
  The concise help has a footer line (`Tip: heimdall help -v …`)
  that points AI agents at the verbose form. Don't strip the footer.
- `heimdall agent` is the stable automation entry point. Keep it read-only,
  single-document JSON, currently versioned as `heimdall.agent/v4`, and shell-safe by
  representing commands as argv arrays. Exit 0 means ready, 1 means not ready,
  and 2 remains clap usage failure. Additive v4 fields are allowed; renaming or
  changing existing field semantics requires a new contract version.
- `heimdall init` preserves `config.<ext>` unless `--force`. Don't change this:
  losing live config to a doc refresh has bitten the user already.
- The internal relay uses one kernel-assigned port shared by its IPv4/IPv6
  TCP/UDP loopback listeners. The active port is published by daemon health
  and written to the eBPF map; it is not user-configurable.
- Registered cgroups have no implicit destination bypass except relay
  self-protection and policy-selected system DNS. Express private-network
  exceptions as ordered `direct` rules; fake-IP ranges must remain eligible
  for relay redirection.
- v2raya (or any other transparent-host-proxy) on the same node can
  TPROXY-trap Heimdall's loopback relay traffic. Document a loopback
  self-traffic exclusion in deploy notes for any environment that runs both;
  do not hard-code a relay port because Heimdall allocates it at runtime.

## When the agent doesn't know what to do

Read the doc in `docs/` whose name matches the area, or grep for the
function name. If still stuck, leave a `TODO:` with a question
phrased for the human reviewer rather than guessing. Guessing in eBPF
land tends to produce silent breakage.
