# Contributing to heimdall

Thanks for considering a contribution. Heimdall is a small project
right now; the bar for accepted changes is high (kernel-side eBPF +
userspace systemd integration is hard to roll back), but the velocity
target on accepted ideas is fast.

## Before you write code

- **File an issue first** for anything bigger than a typo or
  one-line bugfix. We'd rather discuss the design than have you
  rewrite a chunk twice.
- Skim [docs/architecture.md](docs/architecture.md) to know which
  control loop your change lands in.
- For changes touching `heimdall-config/src/lib.rs`: the schema is
  also mirrored in `heimdall/src/cli/init_templates/lib.ncl` (Nickel
  contracts) and `init_templates/README.md` (the AI-readable
  reference). Update all three in lockstep.

## Dev setup

```bash
# Toolchain prerequisites
rustup toolchain install stable
rustup toolchain install nightly        # eBPF needs nightly + build-std
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly

# Bun for the UI
curl -fsSL https://bun.sh/install | bash

# (NixOS) define a flake/devShell that pins nightly + bpfel target
# + bun to get the same toolchain reproducibly.
```

## Building

eBPF must be built **before** the userspace daemon — `heimdall/src/main.rs`
embeds the eBPF object via `include_bytes!`.

```bash
( cd heimdall-ebpf && cargo +nightly build -Z build-std=core \
                                          --target bpfel-unknown-none --release )
( cd heimdall-ui && bun install && bun run build )
cargo build --release
```

Tests:

```bash
cargo test                          # workspace (heimdall + heimdall-config + heimdall-common)
cd heimdall-ui && bun run typecheck
```

## Code style

- **Rust 2021** edition, default `cargo fmt` + `cargo clippy --all-targets`
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

- [ ] Tests pass: `cargo test` + `cd heimdall-ui && bun run typecheck`
- [ ] eBPF rebuild not skipped if the BPF source changed
- [ ] Schema changes propagated to `lib.ncl` + `init_templates/README.md`
- [ ] User-visible behaviour change documented in `CHANGELOG.md`
      under the `## [Unreleased]` heading
- [ ] No new private info / hostnames / paths committed (run
      `git diff origin/master --stat | grep -v '^ '`)

## Reporting bugs

Use the GitHub issue template. Include:
- Kernel version (`uname -r`)
- `heimdall status` output (config path + connection / pod-rule counts)
- Relevant journal entries (`journalctl -u heimdall --since "5min ago"`)
- For routing problems: a flow log row from
  `curl http://127.0.0.1:9999/api/flows?limit=20`

## Licensing

By submitting a PR you agree your contribution is licensed under
[Apache License 2.0](LICENSE), the project's chosen license. No
contributor license agreement is required.
