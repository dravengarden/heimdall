---
name: heimdall-init
description: |
  Bootstrap or refresh the /etc/heimdall/ config directory — drops a
  starter `heimdall.<ext>`, the auto-generated `lib.ncl` schema
  contracts (Nickel only), and the AI-readable `README.md` reference.
  Use on a fresh host or after `heimdall` upgrade to refresh the
  reference files. User-owned `heimdall.<ext>` is preserved unless
  --force is passed.
license: MIT
metadata:
  author: heimdall
  version: '0.1.0'
---

# heimdall init — bootstrap the config dir

Two situations:

1. **Fresh host** — no `/etc/heimdall/` yet. Generate the starter.
2. **Post-upgrade** — refresh `lib.ncl` + `README.md` so the schema
   contract and AI reference match the new daemon binary. The
   user-owned `heimdall.<ext>` stays put.

## Command

```bash
sudo heimdall init [OPTIONS]
```

Run `heimdall init --help` (concise) or `heimdall init --help-all`
(verbose / AI-friendly) for the complete option matrix; this skill
covers the common flow.

### Options summary

| Flag | Meaning | Default |
|---|---|---|
| `--dir <PATH>` | Target directory; created if missing | `/etc/heimdall` |
| `--format <yaml\|json\|toml\|nickel>` | Output format for the main config | `yaml` |
| `--force` | Overwrite the user-owned `heimdall.<ext>` if it exists | false |

`lib.ncl` and `README.md` are **always refreshed** regardless of
`--force` — they're auto-generated reference material that mirrors
the daemon binary, not user-edited.

## What gets written

For `--format nickel` (recommended, validates at evaluation time):

| File | Owner | Purpose |
|---|---|---|
| `heimdall.ncl` | user-edited | Main config (connections + podRouting + cli defaults) |
| `lib.ncl` | auto-generated | Nickel contracts mirroring the Rust schema |
| `README.md` | auto-generated | AI-readable schema reference (this is your in-system doc) |

For `--format {yaml,json,toml}`: only `heimdall.<ext>` + `README.md`
(no `lib.ncl` since contracts are Nickel-specific).

The `secrets/` subdirectory is **not** created or touched. Add
credentials manually:

```bash
sudo install -d -m 0700 -o root -g root /etc/heimdall/secrets
printf '%s' 'PASSWORD' | sudo tee /etc/heimdall/secrets/<name>.pw > /dev/null
sudo chmod 0400 /etc/heimdall/secrets/<name>.pw
```

## Common patterns

### Fresh setup (Nickel — recommended)

```bash
sudo heimdall init --format nickel
sudoedit /etc/heimdall/heimdall.ncl     # add your connections + rules
nix-shell -p nickel --run "cd /etc/heimdall && nickel export -f json heimdall.ncl > /dev/null"
sudo systemctl restart heimdall
heimdall status                          # verify
```

### Post-upgrade refresh (preserve heimdall.ncl)

```bash
sudo heimdall init --format nickel
# Output: README.md + lib.ncl refreshed; heimdall.ncl preserved.
sudo systemctl restart heimdall
```

### Re-set to starter (destructive)

```bash
sudo heimdall init --format nickel --force
# WARNING: overwrites your live heimdall.ncl. Back up first.
```

### Try a different format on a non-default path

```bash
sudo heimdall init --dir /tmp/heimdall-test --format toml
```

## Idempotence

Running `heimdall init` twice without `--force`:
- First run: writes all files.
- Second run: refreshes `lib.ncl` + `README.md`; reports
  `heimdall.<ext>` as preserved.

This makes it safe to call from a Nix activation script or a
post-install hook.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied` | Not running as root, target dir not writable | `sudo` |
| `... already exists; pass --force` | You asked to overwrite a user-owned file | Add `--force`, or back up the old file and rename |

## Related skills

- `heimdall-config` — edit `heimdall.<ext>` after init
- `heimdall-status` — confirm daemon picked up the new config
