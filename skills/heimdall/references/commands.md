# Command workflows

## Inspect without mutation

```bash
heimdall agent
heimdall config path
heimdall config show
heimdall config validate --json
heimdall status --json
```

`agent` is the primary machine contract: one versioned JSON object, stable
error categories, and next actions represented as argv arrays. Exit 0 means
ready, 1 means not ready, and 2 means CLI usage error. It never mutates state.

`config show` prints source text, not a normalized form. `config validate`
evaluates Nickel when applicable, decodes the selected syntax, rejects unknown
fields and types, then runs semantic validation.

## Run through a proxy

```bash
heimdall agent
heimdall run -- curl https://example.com
heimdall run -p corp --dns fake -- curl https://internal.example.com
```

`fake` DNS is for names the upstream proxy can resolve. Use `system` when the
host resolver should resolve names normally. The wrapped process may be
re-executed through `systemd-run --user --scope` to obtain an isolated cgroup.

## Diagnose failures

1. Run `heimdall agent` and preserve its JSON even when it exits 1.
2. Follow its `actions.validate` or `actions.status` argv array.
3. If the daemon is unavailable, inspect recent logs:

   ```bash
   journalctl -u heimdall --since "10 min ago" --no-pager
   ```

4. Preview the exact run decision with `heimdall agent -p NAME --dns MODE`.
5. Reproduce with a small command such as `curl`, preserving the same proxy and
   DNS flags.

Do not equate config validity with connectivity. A real acceptance check must
exercise the named upstream through `heimdall run`.
