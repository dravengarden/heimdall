#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/publish-npm.yml

grep -Fq 'release:' "$workflow"
grep -Fq 'types: [published]' "$workflow"
grep -Fq 'id-token: write' "$workflow"
grep -Fq "npm publish \"\$archive\" --access public" "$workflow"
grep -Fq 'github.event.release.prerelease == false' "$workflow"

for forbidden in workflow_dispatch 'npm install --global' 'lasso ' NODE_AUTH_TOKEN; do
    if grep -Fq "$forbidden" "$workflow"; then
        printf 'npm workflow contains forbidden release wrapper: %s\n' "$forbidden" >&2
        exit 1
    fi
done

printf 'native npm release workflow acceptance OK\n'
