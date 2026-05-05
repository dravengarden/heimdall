# AGENTS.md — heimdall

Operating rules for AI coding agents (Claude Code, Codex, Cursor,
Aider, …) working in this repo. Humans should also follow these — the
file just happens to be the standardized place agents look first.

## Project at a glance

- **What**: per-cgroup transparent egress proxy + TLS observability
  for Kubernetes pods and CLI processes, written in Rust + aya eBPF.
- **Where to start reading**: [`README.md`](README.md) for the
  90-second pitch, [`docs/architecture.md`](docs/architecture.md) for
  the data flow + control loops.
- **Where to start coding**: pick a doc that mentions the file you
  want to change. Most non-trivial changes touch one of `heimdall/`
  (userspace daemon), `heimdall-ebpf/` (kernel programs),
  `heimdall-config/` (schema), `heimdall-ui/` (React UI). The four are
  built independently — see `docs/runbook.md` for build order.

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
("loop over pods", "handle error case"). The eBPF programs in
`heimdall-ebpf/src/main.rs` and the cgroup/iptables glue in
`heimdall/src/{policy,bypass}.rs` are the reference style — every
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
( cd heimdall-ebpf && cargo +nightly build -Z build-std=core \
                                          --target bpfel-unknown-none --release )
( cd heimdall-ui && bun install && bun run build )    # only when UI changed
cargo build --release                                  # daemon
cargo test --release --workspace                       # gate before commit
```

### Schema changes mirror in three places

`heimdall-config/src/lib.rs` is the source of truth for the config
schema, but two derived files **must stay in sync**:

- `heimdall/src/cli/init_templates/lib.ncl` — Nickel contracts
- `heimdall/src/cli/init_templates/README.md` — AI-readable reference

The PR template has a checklist for this. CI doesn't enforce it yet.

### Commit messages

- Subject in imperative voice (`add X`, not `added X`).
- Optional `<scope>: ` prefix when touching one area (`tap: …`,
  `dns: …`, `runbook: …`, `ui: …`).
- Body explains WHY when non-obvious; reference incidents/links.
- Don't add `Co-Authored-By: Claude / Codex / …` lines. The agent
  isn't a coauthor in the legal sense and the noise piles up over
  time. Attribution belongs in the PR description if anywhere.

### Testing UI changes

`bun run typecheck` + `bun run build` are the lower-bar checks. For
anything touching components or hooks, also run the dev server and
exercise the changed surface in a browser before declaring done. Type
checks verify code correctness, not feature correctness.

### Don't touch what you don't need to

Bug fixes shouldn't drag in surrounding cleanup. One-shot operations
shouldn't grow helpers "for next time". Three near-duplicate lines
beat a premature abstraction. Keep PRs tight; the reviewer will
remember to ask for more if needed.

## Pitfalls (specific to this codebase)

- `parking_lot::MutexGuard` is **not Send across `.await`**. Take
  what you need out of the lock into a local before any await point.
  This caused mysterious axum Handler trait failures historically.
- **Help discovery is split for two audiences.** Don't collapse them.
  - `heimdall --help` / `-h` — concise per-command help (clap default).
    What a human at a terminal expects.
  - `heimdall help` — recursive dump of every subcommand and every
    option in one read. **The canonical surface-discovery path for
    AI agents.** Drill in with `heimdall help flows`, `heimdall help
    flows list`, etc.
  - `--help-all` — same content as `help`, available as a global flag
    so it composes anywhere (`heimdall flows --help-all`, etc.).
  The concise help has a footer line (`Tip: heimdall help …`) that
  points AI agents at the recursive form. Don't strip the footer.
- `heimdall init` always rewrites `lib.ncl` and `README.md`, but
  preserves `heimdall.<ext>` unless `--force`. Don't change this:
  losing live config to a doc refresh has bitten the user already.
- The daemon uses a **dual-stack** TCP listener (`[::]:12345`) but
  the config defaults to `0.0.0.0:12345`. The bind path rewrites the
  v4 form to `[::]:` so v6 pods reach the relay. Don't "fix" the
  rewrite; don't change the default.
- IPv6 ULA range `fc00::/7` is **not** in the default bypass list,
  because the fake-IP v6 pool (`fc00:198:19::/96`) lives inside it.
  Bypassing fc00::/7 would break v6 pod redirect.
- v2raya (or any other transparent-host-proxy) on the same node will
  TPROXY-trap heimdall's relay traffic unless you whitelist
  `dst=relay_ip:12345` in the host's iptables/ip6tables. Document
  this in the deploy notes for any environment that runs both.

## When the agent doesn't know what to do

Read the doc in `docs/` whose name matches the area, or grep for the
function name. If still stuck, leave a `TODO:` with a question
phrased for the human reviewer rather than guessing. Guessing in eBPF
land tends to produce silent breakage.
