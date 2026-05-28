# heimdall tap test fixture

Two stand-alone scripts that exercise the TLS implementations heimdall's
plaintext tap covers. Used to validate new tap modules (BoringSSL static,
rustls, …) and to smoke-test the existing ones after a heimdall bump.

| Script | TLS implementation it exercises |
|---|---|
| [`scripts/boringssl-bun.js`](scripts/boringssl-bun.js) | statically-linked BoringSSL (Bun ships its own copy) |
| [`scripts/rustls-deno.ts`](scripts/rustls-deno.ts) | rustls (Deno's `deno_tls` crate) |

Both scripts fetch `https://httpbin.org/json` every 5 seconds. No
external state, no images, no build step — just `bun` or `deno` on PATH.

## Run

heimdall must be serving (`systemctl is-active heimdall` returns `active`,
or `heimdall serve` running in a terminal). Then drive the script through
the daemon via `heimdall run` — this puts the wrapped process in a
transient cgroup that the daemon routes through whatever `cli.run`
profile resolves to:

```bash
# BoringSSL-static (Bun)
heimdall run -- bun tests/tap/scripts/boringssl-bun.js

# rustls (Deno)
heimdall run -- deno run --allow-net tests/tap/scripts/rustls-deno.ts
```

To force a specific connection / observe setting per-invocation:

```bash
heimdall run --connection default --observe -- \
  bun tests/tap/scripts/boringssl-bun.js
```

## Verify capture

Traffic should show up in two places:

1. `heimdall flows list --limit 5` — one row per `fetch()`, with
   `connection_name` matching whatever `heimdall run` resolved to.
2. `heimdall flows show <id>` (or the Web UI `/messages` panel) — the
   `messages` rows attached to each flow contain the plaintext HTTP
   request / response captured at the libssl / rustls boundary.

If a script's fetches show up under `flows` but `messages` is empty,
the relevant uprobe attach probably failed — check `heimdall status`
(the `tap.attached_libs` count) and `journalctl -u heimdall | grep tap`.
