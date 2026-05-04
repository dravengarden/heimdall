# heimdall config — directory layout & setup

Authoritative reference for **how heimdall reads configuration** on
the the host. Schema details live in `heimdall-config/src/lib.rs`;
this doc covers files-on-disk + the bootstrap workflow.

> Single source of truth: this file is at
> `~/heimdall/docs/config.md` and is symlinked into
> `/etc/<host-config>/docs/services/heimdall-config.md` and
> `~/corp/docs/heimdall.md`. Edit here.

## Directory layout

```
/etc/heimdall/
├── heimdall.ncl          ← main config (loaded by daemon)
├── lib.ncl               ← Nickel schema contracts (imported by heimdall.ncl)
└── secrets/              ← 0700 root:root, NOT in git
    └── corp.pw        ← 0400 root:root, no trailing newline
```

That's it. There is no `routing/` subdir, no `config.yaml`, no
per-pod policy files. One main config + one schema lib + a secrets
dir. The daemon supports YAML / JSON / TOML / Nickel via extension
dispatch — **on the host we use Nickel** because `lib.ncl` validates the
whole record at evaluation time (typos and wrong types are caught
before the daemon ever sees the file).

The systemd unit (`services/heimdall/default.nix`) hard-codes:

```
ExecStart=/usr/local/bin/heimdall serve --config /etc/heimdall/heimdall.ncl
```

If you want a different format, change `--format` on `heimdall init`,
update the ExecStart path, `nixos-rebuild switch`.

## Setup / bootstrap

First-time setup (or reset):

```bash
# 1. Generate starter config + schema lib
sudo /usr/local/bin/heimdall init --dir /etc/heimdall --format nickel

# 2. Edit /etc/heimdall/heimdall.ncl — declare connections + rules

# 3. Validate locally before restart (recommended)
nix-shell -p nickel --run "cd /etc/heimdall && nickel export -f json heimdall.ncl > /dev/null"

# 4. Apply
sudo systemctl restart heimdall
sudo journalctl -u heimdall -n 5 --no-pager | grep "config loaded"
# expected: config loaded path=... connections=N pod_rules=M default_use=... default_observe=...
```

`heimdall init` writes:
- `heimdall.<ext>` — main starter config
- `lib.ncl` — schema contracts (Nickel format only)

It does **not** touch `secrets/`. Add credentials by hand:

```bash
sudo install -d -m 0700 -o root -g root /etc/heimdall/secrets
printf '%s' 'PASSWORD' | sudo tee /etc/heimdall/secrets/<name>.pw > /dev/null
sudo chmod 0400 /etc/heimdall/secrets/<name>.pw
```

`--force` overwrites existing files. Without it, `init` refuses to
clobber.

## Schema (top-level)

```nickel
let h = import "lib.ncl" in
{
  apiVersion = "heimdall.io/v1alpha1",
  kind       = "HeimdallConfig",

  runtime     = { ... },             # eBPF + listener + retention knobs
  connections = { name = { ... } },  # named SOCKS5 / direct upstreams
  podRouting  = {                    # pod-selector → connection name
    routingKey = "heimdall.io/routing",
    observeKey = "heimdall.io/observe",
    rules      = [ ... ],
    "default"  = { use = "...", observe = ... },
  },
} | h.HeimdallConfig
```

### `runtime`

| Key | Default | Meaning |
|---|---|---|
| `cgroup` | `/sys/fs/cgroup` | Cgroup root to attach `connect4` + `skb_egress`. Use `/sys/fs/cgroup/kubepods` for k8s scope. |
| `listen` | `0.0.0.0:12345` | Relay TCP listener. |
| `relayIp` | `127.0.0.1` | IPv4 the relay listens on as seen from pods. On k0s use `cilium_host` (`10.244.0.41`). |
| `bypassCidrs` | `[]` | Reserved; not yet wired. |
| `dnsListen` | `0.0.0.0:5358` | Fake-IP DNS UDP listener. |
| `fakeIpCidr` | `198.19.0.0/16` | Fake-IP pool (RFC 2544 benchmark range). |
| `apiListen` | `127.0.0.1:9999` | HTTP API + Web UI. Use `0.0.0.0:9999` for LAN. |
| `stateDir` | `/var/lib/heimdall` | sqlite + future blob storage. |
| `flowRetentionSecs` | `259200` (3d) | Cleanup task drops rows older than this. |
| `tap.enabled` | `false` | Master switch for Phase B uprobe tap. |
| `tap.persist` | `false` | Within tap, write captured plaintext to `messages` table. |

### `connections`

```nickel
connections = {
  default = {
    description = "Local v2raya — public internet",
    type = "socks5",
    addr = "127.0.0.1:20170",
  },
  corp = {
    description = "Mac SOCKS5 → AnyConnect VPN",
    owner       = "colleague@corp.ai",
    type        = "socks5",
    addr        = "<UPSTREAM_IP>:1080",
    auth = {
      username     = "draven",
      passwordFile = "/etc/heimdall/secrets/corp.pw",
    },
  },
  direct = { type = "direct" },
}
```

| Field | Notes |
|---|---|
| `type` | `"socks5"` or `"direct"`. |
| `addr` | Required for `socks5`. |
| `auth` | Optional (RFC 1929 user/pass). `passwordFile` is read at daemon startup. |
| `description`, `owner` | Free-form; surfaced in API + UI. |
| `mitm` | Reserved for M5; parsed but ignored. |

The reserved name `system` is **not** a connection — it means "no
relay, eBPF lets the connection through untouched." Do not declare a
`connections.system` entry.

### `podRouting`

Resolution order, top-down:

```
1. pod.annotations[routingKey]   ← annotation override (e.g. "system" / "corp")
2. pod.labels     [routingKey]   ← label override
3. first matching rule in podRouting.rules
4. podRouting.default
```

`observe` resolves the same way through `observeKey` (default
`heimdall.io/observe`); the two axes are independent.

A rule has:

```nickel
{
  name    = "string",        # optional, for logs
  "match" = { ... },         # MatchCond; omit for catchall
  use     = "default",       # connection name, or reserved "system"
  observe = true,            # optional override of podRouting.default.observe
}
```

### `MatchCond` (K8s LabelSelector + boolean ops)

```nickel
{
  namespaces       = ["a", "b"],                # match on pod namespace
  matchLabels      = { key = "value" },         # AND of equality
  matchExpressions = [
    { key = "app", operator = "In", values = ["x", "y"] },
    { key = "env", operator = "NotIn", values = ["prod"] },
    { key = "feature.flag", operator = "Exists" },
    { key = "deprecated", operator = "DoesNotExist" },
  ],

  # Boolean composition — every leaf is itself a MatchCond
  all = [ ... ],   # AND
  any = [ ... ],   # OR
  "not" = { ... }, # NOT  (`not` is reserved in Nickel; quote it)
}
```

All present fields **AND** together. Boolean ops let you build
arbitrary trees. Empty `MatchCond` (or `all = []`) matches everything.

## The host's current rules (live config)

```
podRouting.rules:
  cluster-infra        ns ∈ {kube-system, local-path-storage}            → use=system
  corp-workloads    label app.k8s.io/part-of=corp  ∨  ns corp*  → use=corp, observe=true
  observed-workloads   rancher / fleet / cert-manager / ingress / opik   → use=default, observe=true
podRouting.default:    use=default, observe=false
```

The annotation/label override path (`heimdall.io/routing: <name>` on
a pod) always wins over rules. So a Helm chart can opt into
`corp` egress without touching this file:

```yaml
# values.yaml
podLabels:
  heimdall.io/routing: corp
```

## Smoke test

After any rule change, verify routing decisions via the flows API:

```bash
# Generate traffic from a pod that should match the rule under test:
sudo KUBECONFIG=/var/lib/k0s/pki/admin.conf kubectl exec -n <ns> <pod> -- \
  curl -ksSm 5 -o /dev/null https://www.cloudflare.com/

# Inspect the resulting flow:
curl -sS "http://127.0.0.1:9999/api/flows?limit=20" \
  | python3 -c "import json,sys; [print(f[\"namespace\"], f[\"connection_name\"], f[\"dst_host\"] or f[\"dst_ip\"]) for f in json.load(sys.stdin)]"
```

Expected:
- `connection_name` = the `use:` your rule resolved to
- `dst_host` = hostname (atyp=domain) when fake-IP DNS round-tripped;
  IP literal (atyp=ip) means the pod connected by raw IP

For pods with `use: system`, **no flow record appears** (eBPF lets
the connection skip the relay).

For traffic where `dst_ip` is in the cluster CIDR or in the bypass
list, you'll see `connection_name: bypass` — that's the synthetic
log the eBPF bypass path emits, not a real relay flow.

## Common edits

| What | Where |
|---|---|
| Add a new SOCKS5 upstream | `connections.<name>` + `secrets/<name>.pw` (if auth) |
| Route a namespace to it | new entry in `podRouting.rules` with `use = "<name>"` |
| Per-pod override | label/annotation `heimdall.io/routing: <name>` (no config edit) |
| Skip relay for some pods | `use = "system"` |
| Capture plaintext | `observe = true` (rule or default) + `runtime.tap.enabled = true` |

## Where things break

- Misspelled `use:` — caught at startup: `unknown use 'foo' in pod rule`.
- Misspelled MatchCond field — caught at Nickel evaluation:
  `unknown field 'namespace', expected one of 'namespaces', 'matchLabels', ...`.
- Forgotten `secrets/<name>.pw` — daemon refuses to start; create the file then restart.
- `nickel` not in PATH — systemd unit bundles it via `path = [ pkgs.nickel ]`.
  Hand-validating from a fish shell needs `nix-shell -p nickel --run ...`.
- Editing CoreDNS forward target by hand — k0s overwrites it. The
  fix lives in `services/k0s/default.nix:k0s-coredns-patch`.

## Related

- Service module (NixOS): `/etc/<host-config>/services/heimdall/default.nix`
- Architecture / data flow: `/etc/<host-config>/docs/services/heimdall.md`
- Corp networking context: `~/corp/docs/networking.md`
