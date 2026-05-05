# Heimdall tap test fixture

A single-pod, multi-container Kubernetes workload that exercises the
TLS implementations heimdall's plaintext tap covers. Used to validate
new tap modules (e.g. BoringSSL static, rustls) and to smoke-test the
existing modules after a heimdall version bump.

| Container | TLS implementation | Source script |
|---|---|---|
| `bun` | statically-linked BoringSSL (Bun ships its own copy) | [`timoni/templates/scripts/boringssl-bun.js`](timoni/templates/scripts/boringssl-bun.js) |
| `deno` | rustls (Deno's `deno_tls` crate) | [`timoni/templates/scripts/rustls-deno.ts`](timoni/templates/scripts/rustls-deno.ts) |

Both containers fetch `https://httpbin.org/json` every 5 seconds. The
fixture is intentionally minimal — no custom images, no Dockerfile, no
external state. Each TLS-implementation case lives in its own runtime
(Bun / Deno) so the corresponding heimdall scanner has a clean target
to attach uprobes to.

## Layout

```
tests/tap/
├── README.md                         # this file
└── timoni/                           # Timoni module (CUE-based)
    ├── cue.mod/module.cue            # module declaration
    ├── timoni.cue                    # entry: ties values + resources
    ├── values.cue                    # user-overridable values (empty default)
    └── templates/
        ├── config.cue                # #Config schema + #Instance
        ├── resources.cue             # Namespace + ConfigMap + Pod
        └── scripts/
            ├── boringssl-bun.js      # BoringSSL test (canonical source)
            └── rustls-deno.ts        # rustls test (canonical source)
```

The `.js` / `.ts` files are the canonical source — `templates/resources.cue`
embeds them via CUE 0.11's `@embed(... type=text)` so the ConfigMap
always matches the file on disk; no manual sync step.

## Apply

Prerequisites: `timoni` on `$PATH` (or run via `nix run nixpkgs#timoni`)
and a `kubectl` context / `KUBECONFIG` that points at your cluster.
Some k8s distros (e.g. k0s) keep the admin kubeconfig under
`/var/lib/<distro>/...` with root-only permissions; in that case
`sudo -E env KUBECONFIG=<path> …` works without copying the file.

From the repo root:

```bash
timoni apply tap-fixture ./tests/tap/timoni --namespace tap-test
```

`timoni` creates the namespace, ConfigMap, and Pod, then waits for the
Pod to become Ready before returning.

## Verify

Both containers should be `Running` and emitting `OK 200 bytes=...` lines:

```bash
kubectl -n tap-test get pod tap-fixture
kubectl -n tap-test logs tap-fixture -c bun  --tail=5
kubectl -n tap-test logs tap-fixture -c deno --tail=5
```

### Sanity-check the runtimes use the expected TLS stack

```bash
# Bun should ship BoringSSL — strings in the binary should contain "BoringSSL".
BUN_PID=$(sudo pgrep -f "bun run /scripts")
sudo strings /proc/$BUN_PID/exe | grep -c BoringSSL    # > 0

# Deno should ship rustls — strings should reference rustls source paths.
DENO_PID=$(sudo pgrep -f "deno run --allow-net /scripts")
sudo strings /proc/$DENO_PID/exe | grep -c rustls      # > 0
```

### Verify heimdall attached to each binary

The startup scan and the live-rescan ticks both log every uprobe
attach. Either run the fixture against an existing daemon (the next
30 s rescan tick picks up the new pod) or restart the daemon:

```bash
# rustls scanner — should report 1 binary at the deno path.
sudo journalctl -u heimdall --since "5 min ago" | \
    grep -E "rustls binaries discovered|rustls uprobes attached|rescan rustls"

# BoringSSL static scanner — should report 1 binary at the bun path.
sudo journalctl -u heimdall --since "5 min ago" | \
    grep -E "BoringSSL static binaries discovered|BoringSSL static uprobes attached|rescan BoringSSL"
```

Or query `/api/status` for a JSON snapshot of all attached scanners:

```bash
curl -s http://127.0.0.1:9999/api/status | jq .tap
```

### Verify plaintext capture

```bash
# Live tail — expect `tap[SEND ...]` and `tap[RECV ...]` lines with
# HTTP request / response bodies in plaintext.
sudo journalctl -u heimdall -f | grep "tap\["

# Persisted rows in the flow store, scoped to this fixture's pod:
sudo sqlite3 /var/lib/heimdall/flows.db <<'SQL'
SELECT
  CASE m.dir WHEN 0 THEN 'SEND' ELSE 'RECV' END AS dir,
  m.tgid,
  m.total_len,
  substr(m.body, 1, 60) AS preview
FROM messages m
LEFT JOIN flows f ON m.flow_id = f.id
WHERE f.namespace = 'tap-test'
  AND f.pod_name  = 'tap-fixture'
  AND m.ts_us > strftime('%s','now')*1000000 - 60000000
ORDER BY m.ts_us DESC
LIMIT 20;
SQL
```

You should see SEND rows beginning `GET /json HTTP/1.1` and RECV rows
beginning `HTTP/1.1 200 OK`. The `tgid` column distinguishes the two
containers (different host PIDs).

## Teardown

The fixture is meant to be ephemeral — leaving it running just burns
upstream bandwidth. Remove it when you're done:

```bash
timoni delete tap-fixture --namespace tap-test
kubectl delete namespace tap-test
```

## Why these specific runtimes

`docs/observability.md` lists the TLS implementations supported by the
Phase B tap. Most are validated in production by real cluster workloads
(libssl: Kong / postgres clients; Go: rancher / kubelet / cilium).
BoringSSL static and rustls historically lacked guaranteed in-cluster
consumers, which is why this fixture exists.

| Runtime | Why we picked it |
|---|---|
| Bun (`oven/bun:1`) | Statically-linked BoringSSL with stable symbol names; one-line invocation via `bun run`; small image. |
| Deno (`denoland/deno:alpine`) | rustls via `deno_tls`; runs TypeScript inline; small Alpine image. |

If a future TLS implementation needs a new test runtime (e.g.
BoringSSL via Envoy data plane, or a JVM SSL test for the eventual
JVMTI path), add another container to the same Pod with its own script
under `templates/scripts/`.
