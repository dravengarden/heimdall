# Release standard

Heimdall releases are curated product records, not raw commit dumps. Local
verification is authoritative; GitHub stores the immutable tag, release notes,
archives, and checksums after every gate passes.

## Required changelog entry

Before publishing `VERSION`, replace `Unreleased` with a dated
`## [VERSION] - YYYY-MM-DD` section. It must contain:

- `### Highlights` with two to five user-facing bullets explaining the release;
- the applicable `### Added`, `### Changed`, `### Fixed`, `### Removed`, or
  `### Security` sections;
- `### Known limitations`, even when its only bullet is `None known`.

Describe behavior, compatibility, and operator impact. Do not paste commit
subjects, internal implementation chronology, private environment details, or
claims that exceed the tested platform contract.

## Required GitHub Release body

`scripts/render-release-notes` turns the versioned changelog entry into the
release body and rejects missing required headings. The generated body contains:

1. curated highlights and the complete version changelog;
2. the versioned installation guide;
3. every expected platform archive and checksum;
4. the authoritative local verification statement;
5. a full Git comparison link from the previous version.

Do not hand-write a GitHub-only summary that can drift from `CHANGELOG.md`.
Preview the exact body during release preparation:

```bash
version=$(nix eval --raw .#packages.x86_64-linux.release.version)
scripts/render-release-notes "$version" \
  "$(gh repo view --json url --jq .url)"
```

When a new platform becomes supported, update the renderer, packaging checks,
installation guide, compatibility section, and artifact list in the same
release-preparation change. In particular, native macOS support must add its
actual macOS artifacts rather than describing Linux aarch64 as macOS support.

Every Linux archive must pass `tests/package/check-artifact-hygiene.sh`. The
gate rejects private and build paths, Nix store paths, ELF debug sections,
dynamic interpreters, and dynamic dependencies. It checks the embedded eBPF
object separately because stripping the outer userspace ELF cannot prove that
the object is clean; the object must retain `.BTF`, `.BTF.ext`, and their
relocation sections after DWARF removal.

The npm, PyPI, and Cargo acceptance scripts must apply the same hygiene policy
to the native bytes recovered from each final registry package. A clean source
archive is not evidence that a later package assembly step preserved those
bytes or the release boundary.

The flake overrides the legacy crates.io index key to the registry's canonical
static download root for Nix vendoring. Keep Cargo.lock checksums authoritative;
do not replace a failed registry fetch with an unchecked mirror or a local
cache dependency.

Before release notes claim native aarch64 data-path coverage, run the following
on an aarch64 Linux execution host at the exact release commit:

```bash
nix develop .#acceptance -c just test-vm-native-aarch64
```

This is separate from the x86_64 release host's qemu-user CLI check. Until the
native current and Linux 6.6 LTS guests both pass, the version changelog must
retain native aarch64 real-eBPF acceptance as a known limitation.

## Publication transaction

From a clean `main` checkout that exactly matches `origin/main`, run only:

```bash
just release-github
```

The command validates release notes before expensive gates, runs source, the
current/LTS NixOS real-eBPF matrix, the pinned Ubuntu 24.04 archive,
lifecycle, runtime/relay TLS, and data-path gate, and package acceptance
locally, builds archives, verifies checksums, creates the annotated tag, pushes
it, and publishes the generated notes and local artifacts. An existing Release
or a tag pointing elsewhere is a hard failure.

After publication, independently verify the peeled remote tag, asset inventory,
downloaded checksums, extracted file set, and `heimdall --version`. A failed
attempt may remove an unpublished tag after proving no Release exists. Never
move or replace a published release tag.

## npm publication

GitHub Release publication precedes npm. The npm package is a distribution
wrapper for the exact released native binaries, not an independent product
build. `just release-github` builds the tarball with npm 12.0.2 and uploads
`heimdall-egress-VERSION.tgz` plus its SHA-256 file beside the native archives.
No product build runs in GitHub Actions.

Publishing the GitHub Release is also the npm publication authorization. The
`release: published` event starts the project-owned `publish-npm.yml` on a
GitHub-hosted runner. It checks out the immutable tag, downloads the existing
tarball and checksum, and calls the native `npm publish` command. npm detects
the GitHub OIDC identity itself. The workflow has no npm token,
`NODE_AUTH_TOKEN`, product build, GitHub Environment, Lasso command, or second
manual dispatch.

One-time account setup may use Columbus Lasso to fill the native npm command:

```bash
lasso npm setup heimdall-egress \
  --repo dravengarden/heimdall \
  --workflow publish-npm.yml
```

Lasso does not participate in routine releases. npm owns browser
authentication, 2FA, and the trusted-publisher relationship; the project owns
all packing, publication, and acceptance behavior.

The npm tarball must expose both `heimdall` and `heimdall-egress`, contain no
lifecycle scripts, and carry only the launcher, LICENSE, README, package
metadata, and supported native binaries. `packaging/npm/README.md` is the
project-owned npm landing page. Keep its supported npm, pnpm, Yarn, Bun, and
Deno commands, stable-path caveats, shortest setup, architecture, modes, and
security boundaries aligned with the actual archive; package acceptance checks
that content. Lasso templates may help draft a page but never own, generate,
check, or publish Heimdall's copy.

After the workflow succeeds, use native `npm view` and fresh-cache `npm exec`
commands for independent acceptance. npm versions are immutable; never
unpublish and replace a version to repair its contents.

## PyPI publication

PyPI follows the same immutable-asset boundary as npm. Before creating the
GitHub Release, `just release-github` builds separate x86_64 and aarch64 Linux
wheels with compressed manylinux/musllinux platform tags, verifies each bundled
static binary, and uploads each wheel with its SHA-256 file. No source
distribution is published because an sdist cannot reproduce the release binary
without rebuilding the product.

Publishing the GitHub Release starts the project-owned `publish-pypi.yml`. The
workflow checks out the immutable tag, downloads exactly two wheels and their
checksums, and uses pinned `uv publish --trusted-publishing always` to exchange
the GitHub OIDC identity for a short-lived PyPI credential. It has no PyPI
token, product build, Lasso command, GitHub Environment, or manual dispatch.

The one-time PyPI pending publisher must use these exact values:

```text
PyPI project: heimdall-egress
GitHub owner: dravengarden
Repository: heimdall
Workflow: publish-pypi.yml
Environment: (blank)
```

Leaving the environment blank intentionally preserves the one-command release
transaction without a per-version approval click. Repository write access and
changes to the publishing workflow therefore remain release-authority
boundaries. Once the first OIDC upload succeeds, PyPI converts the pending
publisher to the normal project publisher automatically.

`packaging/pypi/README.md` is the project-owned PyPI landing page. Keep its
`uv`, `pip`, `pipx`, and ephemeral-run commands, wheel/platform claims, stable
native-path caveat, architecture, modes, and security boundaries aligned with
the actual package. The Lasso template is an optional disposable starting
point; Lasso never owns, synchronizes, checks, builds, or publishes Heimdall's
page.

After publication, independently inspect the PyPI JSON API and install the
exact version into fresh `uv tool` and `pip` environments. Verify
`heimdall --version`, `heimdall-egress --print-native-path`, the rendered
project description, wheel inventory, and release-file digests. PyPI versions
are immutable; repair a bad package with a new version.

## crates.io publication

The Cargo distribution is a source build, not a prebuilt-binary wrapper. The
public package is `heimdall-egress`, its only installed executable is
`heimdall`. The eBPF wire types and strict configuration schema remain internal
workspace crates for repository builds, while their canonical source is bundled
directly into the CLI package. They are not separate crates.io products. The
CLI crate also includes the release's locally built eBPF ELF, so installation
needs stable Rust but no nightly compiler, `bpf-linker`, lifecycle script, or
remote binary download.

Before the GitHub Release is created, `just release-github` packages the CLI
crate locally with pinned Cargo, proves that the embedded ELF equals the Nix
eBPF derivation, runs package acceptance, and uploads the `.crate` with its
SHA-256 file. Standard `cargo publish` does not accept an existing `.crate`
path, so the thin `publish-cargo.yml` workflow makes the narrowest necessary
exception to the immutable-asset upload model: it recreates the package from
the immutable tag and refuses publication unless every byte matches the local
GitHub Release asset. It does not compile or test the product.

crates.io requires each new crate to be published once with a regular API
token before Trusted Publishing can be configured. For that one bootstrap
release only, keep `CARGO_TRUSTED_PUBLISHING_ENABLED` absent, run `cargo login`
locally, and publish the CLI:

```bash
cargo publish --package heimdall-egress --locked --no-verify
```

Then configure the CLI crate with this publisher identity:

```text
GitHub owner: dravengarden
Repository: heimdall
Workflow: publish-cargo.yml
Environment: (blank)
```

Columbus Lasso may validate and open the native settings page, but it
does not store a Cargo token or participate in publication. After the bindings
are verified, remove the bootstrap token with `cargo logout` and set the
repository variable `CARGO_TRUSTED_PUBLISHING_ENABLED=true`. Future Release
publication obtains one short-lived token through the pinned official
crates.io auth action, reproduces the local package, publishes it, and revokes
the token automatically. Leaving the environment blank avoids a
per-version approval click while keeping repository and workflow changes as
release-authority boundaries.

`packaging/cargo/README.md` is the project-owned crates.io landing page. Keep
its installation, Rust/platform requirements, architecture, modes, daemonless
lifecycle, and setup-authorization guidance aligned with the package. Lasso's
template is only an optional disposable starting point.

After publication, inspect the exact version with `cargo info`, compare its
registry checksum with the GitHub Release asset, and run
`cargo install heimdall-egress --version VERSION --locked` with fresh Cargo
home, target, and install roots. Verify `heimdall --version`, the regular
installed path, and the absence of any second executable. crates.io versions
cannot be overwritten; repair a bad package with a new version.
