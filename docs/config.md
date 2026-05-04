# Configuration reference

Path: `/etc/heimdall/config.yaml`. Loaded once at startup; restart
the unit to pick up changes (`sudo systemctl restart heimdall`).

## Two orthogonal axes

```
                  ┌────────────────── observe ──────────────────┐
                  │                                              │
                  │              true              false         │
        ┌─────────┼──────────────────────┬──────────────────────┤
        │         │                      │                      │
        │ default │ proxy via v2raya     │ proxy via v2raya     │
        │         │ + capture plaintext  │ + no plaintext       │
        │         │                      │                      │
        │  proxy  │                      │                      │
        │ corp │ proxy via Mac        │ proxy via Mac        │
        │         │ + capture plaintext  │ + no plaintext       │
        │         │                      │                      │
        │ system  │ no relay redirect    │ no relay redirect    │
        │         │ + capture plaintext  │ + nothing            │
        └─────────┴──────────────────────┴──────────────────────┘
                                              ┌─── least heimdall
                                              │    involvement
```

The two axes are fully independent:

- A pod can pick `use: system` and still be observed (uprobes don't
  depend on the relay path).
- A pod can use the proxy but suppress observability (e.g. high-volume
  database protocols where plaintext is uninteresting).

## Top-level structure

```yaml
apiVersion: heimdall.io/v1alpha1
kind: HeimdallConfig

runtime:        # eBPF + listener + retention knobs
connections:    # named SOCKS5 / Direct upstreams
routing:        # how each pod's (use, observe) is decided
```

## `runtime`

| Key | Default | Meaning |
|---|---|---|
| `cgroup` | `/sys/fs/cgroup` | Path to attach `connect4` and `skb_egress` to. Use `/sys/fs/cgroup/kubepods` to scope to k8s only. |
| `listen` | `0.0.0.0:12345` | Relay TCP listener (target of connect4 rewrite). |
| `relayIp` | `127.0.0.1` | IPv4 the relay listens on as seen from pods. On k0s this is typically `cilium_host` (`10.244.0.41`). |
| `bypassCidrs` | `[]` | Reserved; not yet wired into eBPF. |
| `dnsListen` | `0.0.0.0:5358` | UDP listener for the fake-IP DNS server. CoreDNS forwards non-cluster zones here. |
| `fakeIpCidr` | `198.19.0.0/16` | Pool to draw fake IPs from (RFC 2544 benchmark range). |
| `stateDir` | `/var/lib/heimdall` | sqlite + future blob storage. |
| `flowRetentionSecs` | `259200` (3d) | Cleanup task drops flows + messages older than this. |
| `apiListen` | `127.0.0.1:9999` | HTTP API + UI. Set `0.0.0.0:9999` for LAN access. |
| `tap.enabled` | `false` | Master switch for the Phase B uprobe tap. When false, no /proc scan, no uprobes, no perf consumer. |
| `tap.persist` | `false` | Within the tap, controls whether captured plaintext is written to the `messages` table. When false, events only show up in the journal logs. |

## `connections`

A registry of named upstream targets. Connection names are used in
`routing` to pick where redirected traffic goes.

```yaml
connections:
  default:
    description: Local v2raya — default egress.
    type: socks5
    addr: 127.0.0.1:20170

  corp:
    description: SOCKS5 server on Mac (LAN). hev-socks5-server.
    owner: colleague@corp.ai
    type: socks5
    addr: <UPSTREAM_IP>:1080
    auth:
      username: draven
      passwordFile: /etc/heimdall/secrets/corp.pw
```

Two connection types:

- `type: socks5` — relay opens a SOCKS5 client to `addr`, optionally
  with `auth.{username, passwordFile}`.
- `type: direct` — relay direct-connects to the original destination
  with no proxy layer. Useful for "see traffic but don't tunnel".

The reserved name `system` is **NOT** declared here — it's a
keyword in `routing` that means "skip eBPF redirect entirely". The
validator rejects a connection literally named `system`.

`connections.default` is required: validation fails without it.

## `routing`

The decision pipeline for each pod. Two annotation keys are checked
independently — set both, neither, or just one.

```yaml
routing:
  connectionKey: heimdall.io/connection   # picks `use`
  observeKey:    heimdall.io/observe      # picks `observe`

  rules:
    - name: cluster-infra
      match:
        namespaces: [kube-system, local-path-storage]
      use: system
      observe: false

  default:
    use: default
    observe: true
```

### Resolution order (each axis independently)

1. **Pod annotation** at the relevant key.
2. **Pod label** at the same key.
3. **`routing.rules`** — first rule that matches (rule's `use` and
   `observe` are taken together).
4. **`routing.default`**.

So a pod with just `heimdall.io/observe: false` flips observe off
while inheriting `use` from the default. Conversely a pod with
`heimdall.io/connection: corp` keeps `observe` from whatever rule
or default applies.

### Annotation values

- `heimdall.io/connection` — any name in `connections:` or the literal
  string `system`.
- `heimdall.io/observe` — `true | false | yes | no | on | off | 1 | 0`
  (case-insensitive). Anything unparseable falls through to the next
  layer of resolution.

### Match block

K8s LabelSelector-compatible plus an optional namespace filter.

```yaml
match:
  matchLabels:                       # all-of
    family: corp
  matchExpressions:                  # all-of
    - { key: env, operator: In,         values: [prod, stg] }
    - { key: tier, operator: NotIn,     values: [data] }
    - { key: legacy, operator: Exists }
    - { key: external, operator: DoesNotExist }
  namespaces: [corp-prod, corp-stg]
```

`deny_unknown_fields` is on for the schema. `matchLables` (typo) and
similar are rejected at load.

## Reference: cluster cases

Concrete rules from the deployed config on this k0s cluster, with
the labels each rule actually matches. Maintained when the cluster
inventory changes — see [runbook.md](runbook.md).

| Rule | Targets | `use` | `observe` |
|---|---|---|---|
| `cluster-infra` | `kube-system`, `local-path-storage` namespaces | `system` | `false` |
| `cert-manager-noisy` | `cert-manager` ns + `app.kubernetes.io/name in [cainjector, webhook]` | `default` | `false` |
| `rancher-webhook` | `cattle-system` + `app: rancher-webhook` | `default` | `false` |
| `cattle-controllers` | `cattle-capi-system`, `cattle-turtles-system` namespaces | `default` | `false` |
| `fleet-controller` | `cattle-fleet-system` + `app: fleet-controller` | `default` | `false` |
| `data-stores` | `app.kubernetes.io/name in [mysql, minio, redis, zookeeper-opik, postgresql, postgres]` | `default` | `false` |
| (default) | everything else (rancher, cert-manager leaf, ingress-nginx, fleet-agent / gitjob / helmops, opik backend pods, etc.) | `default` | `true` |

Pods picked up by `cluster-infra` do **both**: skip the eBPF redirect
**and** suppress tap events. Pods picked up by `cattle-controllers`
still go through the proxy (so external API calls work), they just
don't pollute the messages table with their leader-election leases.

## Per-pod overrides

```yaml
metadata:
  annotations:
    heimdall.io/connection: corp     # route this pod via Mac
    heimdall.io/observe:    "true"      # force observe even if a rule says false
```

Annotations win over rules. Use sparingly — usually it's better to
add a rule so the policy is grep-able from one place.

## All six (`use` × `observe`) combinations as YAML

```yaml
# 1. Default for most user workloads — proxy via v2raya, capture plaintext.
default:
  use: default
  observe: true

# 2. Noisy controller — proxy as normal, but silence the tap.
- name: cattle-controllers
  match: { namespaces: [cattle-capi-system, cattle-turtles-system] }
  use: default
  observe: false

# 3. Pod that needs corporate VPN routing AND observation (the dev case).
metadata:
  annotations:
    heimdall.io/connection: corp
    heimdall.io/observe: "true"

# 4. Same routing as #3, plaintext suppressed (e.g. own credentials in flight).
metadata:
  annotations:
    heimdall.io/connection: corp
    heimdall.io/observe: "false"

# 5. Cluster infrastructure — bypass the relay entirely AND silence tap.
- name: cluster-infra
  match: { namespaces: [kube-system, local-path-storage] }
  use: system
  observe: false

# 6. Pod that should bypass the relay (host-network style) but you DO
#    want to see its TLS plaintext. No example currently in this
#    cluster, but configurable:
metadata:
  annotations:
    heimdall.io/connection: system
    heimdall.io/observe: "true"
```

## `RoutingDecision` flag encoding

For reference, `policy.rs::encode` maps a `RoutingDecision` to the
byte stored in `CGROUP_POLICY`:

```
flags = 0x00
if use == "system":  flags |= POLICY_REDIRECT_OFF   (0x01)
if !observe:         flags |= POLICY_OBSERVE_OFF |
                              POLICY_NO_BYPASS_LOG  (0x06)
```

So in the BPF map:

| Value | Meaning | Cluster pods |
|---|---|---|
| `0x00` | observe + redirect (the default) | rancher, ingress-nginx, opik backends, cert-manager leaf, fleet-agent / gitjob / helmops |
| `0x06` | observe off, redirect on | webhooks, cainjector, capi/turtles, fleet-controller, mysql/redis/minio |
| `0x07` | observe off, redirect off | kube-system, local-path-storage |

`bpftool map dump name CGROUP_POLICY` will show this directly.
