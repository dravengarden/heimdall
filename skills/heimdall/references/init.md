# `heimdall init` — bootstrap or refresh `/etc/heimdall/`

Two situations:

1. **Fresh host** — no `/etc/heimdall/` yet. Drop the starter.
2. **Post-upgrade** — refresh `lib.ncl` + `README.md` so the schema
   contract and AI reference match the new daemon binary. The
   user-owned `heimdall.<ext>` stays put.

## Command

```bash
sudo heimdall init [OPTIONS]
```

`heimdall help init -v` for the complete option matrix. Common flags:

| Flag | Meaning | Default |
|---|---|---|
| `--dir <PATH>` | Target directory; created if missing | `/etc/heimdall` |
| `--format <yaml\|json\|toml\|nickel>` | Output format for the main config | `yaml` |
| `--force` | Overwrite the user-owned `heimdall.<ext>` if it exists | false |

`lib.ncl` and `README.md` are **always refreshed** regardless of
`--force` — they're auto-generated reference material that mirrors
the daemon binary, not user-edited.

## What gets written

For `--format nickel` (recommended; validates at evaluation time):

| File | Owner | Purpose |
|---|---|---|
| `heimdall.ncl` | user-edited | Main config (connections + podRouting + cli defaults) |
| `lib.ncl` | auto-generated | Nickel contracts mirroring the Rust schema |
| `README.md` | auto-generated | AI-readable schema reference (the in-system doc) |

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
sudoedit /etc/heimdall/heimdall.ncl     # add connections + rules
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

Safe to call from a Nix activation script or a post-install hook.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied` | Not running as root, or target dir not writable | `sudo` |
| `... already exists; pass --force` | Asked to overwrite a user-owned file | Add `--force`, or back up + rename the old file |
