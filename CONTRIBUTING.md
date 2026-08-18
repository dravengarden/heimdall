# Contributing to heimdall

Thanks for considering a contribution. Heimdall is a small project
right now; the bar for accepted changes is high (kernel-side eBPF +
userspace systemd integration is hard to roll back), but the velocity
target on accepted ideas is fast.

## Before you write code

- **File an issue first** for anything bigger than a typo or
  one-line bugfix. We'd rather discuss the design than have you
  rewrite a chunk twice.
- Read [ROADMAP.md](ROADMAP.md) to see whether the proposal belongs to an
  active development track, a planned area, or an explicit non-goal.
- Skim [docs/architecture.md](docs/architecture.md) to know which
  control loop your change lands in.
- For changes touching `heimdall-config/src/lib.rs`, update the four embedded
  init templates, `docs/config.md`, and the bundled skill reference together.

## Dev setup

```bash
nix develop
```

## Building

eBPF must be built **before** the userspace binary — `heimdall/src/main.rs`
embeds the eBPF object via `include_bytes!`.

```bash
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'
nix develop -c just verify
```

Tests:

```bash
nix develop -c cargo test --workspace --all-features --locked
```

## Code style

- **Rust 2024** edition, default `cargo fmt` + `cargo clippy --all-targets`
  before opening a PR.
- Keep changes minimal and focused. A bug fix doesn't need surrounding
  cleanup; a one-shot operation doesn't need a helper.
- **Comments explain WHY, not WHAT.** Examples to imitate live in
  `heimdall-ebpf/src/main.rs` (every non-obvious BPF choice has a
  "why" block) and `heimdall/src/cli/run.rs` (the unshare + bind-mount
  shim explains the failure modes it sidesteps).
- No emoji in code or commit messages.
- English only — code comments, doc strings, commit messages.

## Commit messages

Imperative subject ≤ 72 chars (`fix relay accept loop on EAGAIN`,
`docs: clarify --dns fake mechanics`). Body explains *why* the change
was needed and any non-obvious tradeoffs. Reference issues with
`Fixes #N` / `Refs #N`.

`<scope>: <subject>` is encouraged when the scope is one crate or
file (`gc:`, `dns:`, `policy:`, `docs:`, `ebpf:`).

## PR checklist

- [ ] `nix develop -c just verify` passes
- [ ] `nix develop -c just test-vm` passes for proxy, lifecycle, or TLS changes
- [ ] eBPF rebuild not skipped if the BPF source changed
- [ ] Schema changes propagated to all init formats, docs, and the Heimdall skill
- [ ] User-visible behaviour change documented in `CHANGELOG.md`
      under the `## [Unreleased]` heading
- [ ] README or `ROADMAP.md` status updated when the public capability boundary changes
- [ ] No new private info / hostnames / paths committed (run
      `git diff origin/main --stat | grep -v '^ '`)

## Reporting bugs

Use the GitHub issue template when available. Security vulnerabilities belong
in the private process described by [SECURITY.md](SECURITY.md), not in a
public issue. Include:
- Kernel version (`uname -r`)
- `heimdall agent` output
- The run manifest and relevant JSONL events from `heimdall logs query`
- A minimal wrapped-command reproduction

## Licensing

By submitting a PR you agree your contribution is licensed under
[Apache License 2.0](LICENSE), the project's chosen license. No
contributor license agreement is required.
