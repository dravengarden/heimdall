#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

notes=$(CHANGELOG_FILE=tests/release/CHANGELOG.md PREVIOUS_TAG_OVERRIDE=v0.1.0 \
  scripts/render-release-notes 0.2.0 https://github.com/example/heimdall)

grep -Fq '## Changes' <<<"$notes"
grep -Fq '### Highlights' <<<"$notes"
grep -Fq '### Known limitations' <<<"$notes"
grep -Fq 'heimdall-egress-0.2.0-aarch64-linux-musl.tar.gz' <<<"$notes"
grep -Fq 'heimdall-egress-0.2.0.tgz' <<<"$notes"
grep -Fq 'heimdall_egress-0.2.0-*.whl' <<<"$notes"
grep -Fq 'https://github.com/example/heimdall/compare/v0.1.0...v0.2.0' <<<"$notes"

if CHANGELOG_FILE=tests/release/CHANGELOG.md \
  scripts/render-release-notes 0.1.0 https://github.com/example/heimdall \
  >/dev/null 2>&1; then
  echo 'renderer accepted a release without known limitations' >&2
  exit 1
fi

echo 'release notes renderer acceptance OK'
