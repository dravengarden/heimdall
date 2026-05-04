<!--
Heimdall PR template. Filled-in PRs get reviewed faster than blank
ones. Delete sections that don't apply.
-->

## Summary

<!-- One-paragraph description of what changes and why. -->

## Linked issue

<!-- Fixes #N / Refs #N. If no issue, explain why this is small enough
     to skip the design conversation. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (config schema, on-wire shape, BPF map layout, …)
- [ ] Documentation only

## Test plan

<!-- What did you run? `cargo test`, `bun run typecheck`, end-to-end
     smoke against a real cluster, manual verification of a failure
     mode, etc. -->

- [ ] `cargo test` (workspace)
- [ ] `cargo +nightly build -Zbuild-std=core --target bpfel-unknown-none --release` (if BPF source changed)
- [ ] `cd heimdall-ui && bun run typecheck` (if UI changed)
- [ ] Manual smoke test described above

## Schema / config changes

<!-- If your change touches `heimdall-config/src/lib.rs`, the schema is
     mirrored in TWO other places that must stay in sync:
     - `heimdall/src/cli/init_templates/lib.ncl` (Nickel contracts)
     - `heimdall/src/cli/init_templates/README.md` (AI-readable reference)
     Tick the boxes when both are updated. Skip if your change isn't
     schema-touching. -->

- [ ] `lib.ncl` updated
- [ ] `init_templates/README.md` updated
- [ ] N/A — no schema changes

## CHANGELOG

- [ ] Added an entry under `## [Unreleased]` in `CHANGELOG.md`
- [ ] N/A — no user-visible behaviour change

## Privacy / security

- [ ] No new private hostnames, IPs, paths, or emails committed
      (`git diff origin/master | grep -iE 'gmail|corp|host|192.168'`
      should be empty unless this PR is specifically about scrubbing)
- [ ] Doesn't open a network listener on a public address by default
- [ ] Doesn't grant new ambient capabilities

<!--
Reviewer note: this template hasn't been linted; if you spot anything
that should be enforced rather than asked-for, say so.
-->
