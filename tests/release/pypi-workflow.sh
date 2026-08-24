#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/publish-pypi.yml

grep -Fq 'release:' "$workflow"
grep -Fq 'types: [published]' "$workflow"
grep -Fq 'id-token: write' "$workflow"
grep -Fq 'version: "0.11.21"' "$workflow"
grep -Fq 'uv publish --trusted-publishing always dist/*.whl' "$workflow"
grep -Fq 'github.event.release.prerelease == false' "$workflow"

for forbidden in workflow_dispatch 'python -m build' 'lasso ' UV_PUBLISH_TOKEN; do
  if grep -Fq "$forbidden" "$workflow"; then
    printf 'PyPI workflow contains forbidden build or release wrapper: %s\n' \
      "$forbidden" >&2
    exit 1
  fi
done

printf 'native PyPI release workflow acceptance OK\n'
