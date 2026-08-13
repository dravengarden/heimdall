# Command workflows

## Inspect without mutation

```bash
heimdall agent
heimdall config path
heimdall config show
heimdall config validate --json
heimdall config explain --policy default --domain example.com --port 443 --json
heimdall status --json
```

`agent` is the primary machine contract: one versioned JSON object, stable
error categories, and next actions represented as argv arrays. Exit 0 means
ready, 1 means not ready, and 2 means CLI usage error. It never mutates state.

`config show` prints source text, not a normalized form. `config validate`
evaluates Nickel when applicable, decodes the selected syntax, rejects unknown
fields and types, then runs semantic validation.

`config explain` evaluates one TCP destination against the selected policy and
returns the first matching rule plus its structured action. Use `--ip` instead
of `--domain` for IP/CIDR rules; omit both to test port-only and final actions.

## Run through a proxy

```bash
heimdall agent
heimdall run -- curl https://example.com
heimdall agent --policy corp
heimdall run --policy corp -- curl https://internal.example.com
```

The selected policy owns DNS, ordered rules, and final TCP/UDP actions. The
wrapped process may be re-executed through `systemd-run --user --scope` to
obtain an isolated cgroup.

## Diagnose failures

1. Run `heimdall agent` and preserve its JSON even when it exits 1.
2. Follow its `actions.validate` or `actions.status` argv array.
3. If the daemon is unavailable, inspect recent logs:

   ```bash
   journalctl -u heimdall --since "10 min ago" --no-pager
   ```

4. Preview a destination with `heimdall config explain --policy NAME ... --json`.
5. Preview daemon readiness with `heimdall agent --policy NAME`.
6. Reproduce with a small command such as `curl`, preserving the same policy.

Do not equate config validity with connectivity. A real acceptance check must
exercise the selected policy through `heimdall run`.
