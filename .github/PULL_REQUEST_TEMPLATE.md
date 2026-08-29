## Summary

<!-- Explain the user-visible change and why it belongs in Heimdall. -->

## Scope

- [ ] Runtime code
- [ ] eBPF code
- [ ] Configuration or machine-readable contract
- [ ] Documentation or skill
- [ ] Tests / acceptance coverage

## Evidence

<!-- Include the repository-owned commands and the relevant output. -->

- [ ] `nix develop -c just verify`
- [ ] `nix develop -c just test-vm` (when proxy, lifecycle, or TLS behavior changed)
- [ ] `just test-vm-ubuntu && just test-vm-debian` (when distro, resolver, lifecycle, or TLS behavior changed)

## Contract and documentation review

- [ ] User-visible changes are recorded in `CHANGELOG.md`.
- [ ] README or `ROADMAP.md` status is updated when the public boundary changed.
- [ ] Config changes are synchronized across TOML, YAML, JSON, docs, and skills.
- [ ] Agent or health contract changes have an intentional version decision.
- [ ] No credentials, private hostnames, internal addresses, or environment-specific paths are included.
