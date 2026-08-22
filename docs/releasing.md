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

## Publication transaction

From a clean `main` checkout that exactly matches `origin/main`, run only:

```bash
just release-github
```

The command validates release notes before expensive gates, runs source,
current/LTS real-eBPF, and package acceptance locally, builds archives, verifies
checksums, creates the annotated tag, pushes it, and publishes the generated
notes and local artifacts. An existing Release or a tag pointing elsewhere is
a hard failure.

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

Columbus Lasso owns the external publication transaction:

```bash
lasso check
lasso npm publish "v$(nix eval --raw .#packages.x86_64-linux.release.version)" --yes
```

The thin `publish-npm.yml` workflow runs only on a GitHub-hosted runner. It
checks out the immutable tag, installs the pinned npm 12.0.2 client, downloads
the existing GitHub Release tarball and checksum, validates package identity,
and calls `npm publish` through OIDC trusted publishing. It has no npm token,
`NODE_AUTH_TOKEN`, build step, GitHub Environment, or separate web approval.
The explicit Lasso command is the publication authorization.

One-time package setup uses `lasso npm trust --apply` to bind
`heimdall-egress` to repository `dravengarden/heimdall`, workflow
`publish-npm.yml`, no environment, and direct `npm publish` permission. This
account-level change may require interactive npm authentication; routine
releases do not.

The npm tarball must expose both `heimdall` and `heimdall-egress`, contain no
lifecycle scripts, and carry only the launcher, LICENSE, README, package
metadata, and supported native binaries. Lasso accepts completion only after
registry identity/integrity and fresh-cache execution of both commands pass.
npm versions are immutable; never unpublish and replace a version to repair its
contents. Re-running Lasso for an existing matching version performs acceptance
without dispatching another publication.
