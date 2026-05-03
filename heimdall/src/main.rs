//! heimdall — transparent SOCKS5 egress proxy driven by eBPF.
//!
//! Works as a standalone CLI tool or as a Kubernetes DaemonSet.
//!
//! ## How it works
//!
//!   Pod connect(external_ip:port)
//!       │
//!       │  [eBPF BPF_CGROUP_INET4_CONNECT]
//!       │  Rewrites dst → relay_ip:12345
//!       │  Saves (orig, cgroup_id) in COOKIE_MAP[socket_cookie]
//!       │
//!       │  [eBPF BPF_CGROUP_INET_EGRESS on first SYN]
//!       │  Moves COOKIE_MAP[cookie] → PORT_MAP[src_port]
//!       │
//!       ▼
//!   heimdall daemon
//!     1. accept() → src_port → PORT_MAP → (orig_ip, orig_port, cgroup_id)
//!     2. cgroup_id → pod_uid → PodInfo (labels + annotations)
//!     3. PodInfo → connection name (annotation > rules > default)
//!     4. SOCKS5 CONNECT orig_ip:orig_port via chosen connection's upstream
//!
//! ## Configuration
//!
//! Driven by `/etc/heimdall/config.yaml`. See heimdall-config crate
//! for schema, /etc/<host-config>/docs/heimdall.md for the operator's view.

mod api;
mod cli;
mod dns;
mod pod;
mod router;
mod store;

use std::{
    collections::HashMap as StdHashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
    Ebpf,
};
use clap::Parser;
use heimdall_common::OrigDst;
use heimdall_config::{Connection, HeimdallConfig, Socks5Auth, Socks5Connection};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tracing::{debug, info, warn};

use crate::dns::DnsResolver;
use crate::pod::{CgroupResolver, PodInformer};

// eBPF object compiled from heimdall-ebpf, embedded at build time.
//
// The wrapper ensures 8-byte alignment, which the ELF parser requires when
// parsing 64-bit ELF from a static byte slice.
#[repr(C, align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

static EBPF_OBJ: AlignedBytes<{ include_bytes!(
    "../../heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf"
).len() }> = AlignedBytes(*include_bytes!(
    "../../heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf"
));

const EBPF_BYTES: &[u8] = &EBPF_OBJ.0;

type PortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;

// ---------------------------------------------------------------------------
// CLI — top level
// ---------------------------------------------------------------------------

/// heimdall — transparent SOCKS5 egress proxy + observability for k8s pods.
#[derive(Parser, Debug)]
#[command(name = "heimdall", version, about, long_about = None)]
struct Cli {
    /// Path to YAML config.
    #[arg(long, default_value = heimdall_config::DEFAULT_PATH, env = "HEIMDALL_CONFIG", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Run the heimdall daemon (used by systemd).
    Serve(ServeArgs),

    /// List, search, and inspect recorded flows.
    #[command(subcommand)]
    Flows(cli::flows::FlowsCmd),

    /// Daemon health and counts.
    Status,
}

#[derive(clap::Args, Debug)]
struct ServeArgs {
    /// Disable Kubernetes API integration entirely.
    /// All connections will use `routing.default`.
    #[arg(long, env = "HEIMDALL_NO_K8S")]
    no_k8s: bool,
}

// ---------------------------------------------------------------------------
// Resolved upstream — produced from a Connection at startup
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Upstream {
    Socks5 { addr: String, auth: Option<ResolvedAuth> },
    Direct,
}

#[derive(Clone, Debug)]
struct ResolvedAuth {
    username: String,
    password: String,
}

impl Upstream {
    fn from_connection(conn: &Connection) -> Result<Self> {
        match conn {
            Connection::Socks5(Socks5Connection { addr, auth, .. }) => {
                let resolved = auth.as_ref().map(resolve_auth).transpose()?;
                Ok(Upstream::Socks5 { addr: addr.clone(), auth: resolved })
            }
            Connection::Direct(_) => Ok(Upstream::Direct),
        }
    }
}

fn resolve_auth(a: &Socks5Auth) -> Result<ResolvedAuth> {
    let password = a
        .read_password()
        .with_context(|| format!("read password file {}", a.password_file.display()))?;
    Ok(ResolvedAuth { username: a.username.clone(), password })
}

/// Pre-resolve every connection in the config so the relay path doesn't
/// re-read password files per connection.
fn resolve_all(cfg: &HeimdallConfig) -> Result<StdHashMap<String, Arc<Upstream>>> {
    let mut out = StdHashMap::with_capacity(cfg.connections.len());
    for (name, conn) in &cfg.connections {
        let up = Upstream::from_connection(conn)
            .with_context(|| format!("resolving connection `{name}`"))?;
        out.insert(name.clone(), Arc::new(up));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct Shared {
    cfg: HeimdallConfig,
    upstreams: StdHashMap<String, Arc<Upstream>>,
    /// None when --no-k8s or informer init failed.
    informer: Option<PodInformer>,
    /// None when running outside k8s.
    cgroup_resolver: Option<CgroupResolver>,
    /// Fake-IP DNS resolver. None when DNS server failed to bind
    /// (relay degrades to plain IP-mode SOCKS5 in that case).
    dns: Option<Arc<DnsResolver>>,
    /// Flow store (sqlite). None when init failed (relay still runs).
    store: Option<Arc<store::Store>>,
    /// Live flow event bus — relay publishes finish events,
    /// API WebSocket subscribers consume.
    events: api::EventBus,
}

/// SOCKS5 destination — either an IP literal (ATYP=0x01) or a hostname
/// recovered via fake-IP lookup (ATYP=0x03, RFC 1928).
#[derive(Debug, Clone)]
enum Dst {
    Ip(Ipv4Addr),
    Domain(String),
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Only the daemon prints structured logs by default. CLI subcommands
    // stay quiet unless `RUST_LOG` overrides — they're meant to feed
    // stdout into pipes / `jq` / human eyes.
    let default_level = match &cli.cmd {
        Cmd::Serve(_) => "heimdall=info",
        _ => "heimdall=warn",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(default_level.parse()?),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.cmd {
        Cmd::Serve(args) => daemon_run(&cli.config, args).await,
        Cmd::Flows(sub) => cli::flows::run(&cli.config, sub).await,
        Cmd::Status => cli::status::run(&cli.config).await,
    }
}

async fn daemon_run(config_path: &PathBuf, args: ServeArgs) -> Result<()> {
    // ─── Load config ──────────────────────────────────────────────────────
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    info!(
        path = %config_path.display(),
        connections = cfg.connections.len(),
        rules = cfg.routing.rules.len(),
        default = %cfg.routing.default,
        "config loaded"
    );

    let upstreams = resolve_all(&cfg)?;
    info!(connections = upstreams.len(), "all connections resolved");

    // ─── Flow store (sqlite) ──────────────────────────────────────────────
    let store_path = cfg.runtime.state_dir.join("flows.db");
    let store = match store::Store::open(&store_path).await {
        Ok(s) => {
            info!(
                path = %store_path.display(),
                retention_secs = cfg.runtime.flow_retention_secs,
                "flow store ready"
            );
            let s = Arc::new(s);
            store::spawn_cleanup(s.clone(), cfg.runtime.flow_retention_secs);
            Some(s)
        }
        Err(e) => {
            warn!(error = %e, path = %store_path.display(), "flow store failed; continuing without recording");
            None
        }
    };

    // ─── Pod identity (cgroup → uid → labels) ─────────────────────────────
    let cgroup_resolver = if args.no_k8s {
        None
    } else {
        Some(CgroupResolver::new(&cfg.runtime.cgroup))
    };
    let informer = if args.no_k8s {
        None
    } else {
        match PodInformer::spawn().await {
            Ok(i) => {
                info!("pod informer started");
                Some(i)
            }
            Err(e) => {
                warn!(error = %e, "pod informer failed to start; routing falls back to default");
                None
            }
        }
    };

    // ─── Fake-IP DNS server ──────────────────────────────────────────────
    let dns = match DnsResolver::new(&cfg.runtime.fake_ip_cidr) {
        Ok(r) => {
            let r = Arc::new(r);
            let listen: SocketAddr = cfg
                .runtime
                .dns_listen
                .parse()
                .with_context(|| format!("parse runtime.dnsListen `{}`", cfg.runtime.dns_listen))?;
            let r_for_task = r.clone();
            tokio::spawn(async move {
                if let Err(e) = r_for_task.serve(listen).await {
                    warn!(error = %e, "DNS server exited");
                }
            });
            Some(r)
        }
        Err(e) => {
            warn!(error = %e, "DNS resolver init failed; relay will run in IP-only mode");
            None
        }
    };

    // ─── HTTP API (REST + WebSocket) ──────────────────────────────────────
    let events = api::EventBus::new(1024);

    if let Some(s) = store.as_ref() {
        let api_listen: SocketAddr = cfg
            .runtime
            .api_listen
            .parse()
            .with_context(|| format!("parse runtime.apiListen `{}`", cfg.runtime.api_listen))?;
        let app_state = api::AppState {
            store: s.clone(),
            events: events.clone(),
            cfg_path: config_path.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = api::serve(app_state, api_listen).await {
                warn!(error = %e, "HTTP API exited");
            }
        });
    } else {
        warn!("flow store unavailable; HTTP API not started");
    }

    let shared = Arc::new(Shared {
        cfg,
        upstreams,
        informer,
        cgroup_resolver,
        dns,
        store,
        events,
    });

    // ─── Load eBPF object and attach programs ─────────────────────────────
    let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF object")?;

    {
        let relay_ip_be = u32::from(shared.cfg.runtime.relay_ip).to_be();
        let mut relay_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(bpf.map_mut("RELAY_ADDR").context("RELAY_ADDR not found")?)?;
        relay_map.set(0, relay_ip_be, 0).context("failed to set relay IP in BPF map")?;
        info!(relay_ip = %shared.cfg.runtime.relay_ip, "relay IP written to BPF map");
    }

    let cgroup = std::fs::File::open(&shared.cfg.runtime.cgroup)
        .with_context(|| format!("failed to open cgroup path: {}", shared.cfg.runtime.cgroup))?;

    let connect4: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .context("connect4 eBPF program not found")?
        .try_into()?;
    connect4.load().context("failed to load connect4")?;
    connect4
        .attach(&cgroup, CgroupAttachMode::default())
        .context("failed to attach connect4")?;
    info!(cgroup = %shared.cfg.runtime.cgroup, "eBPF connect4 attached");

    let skb_egress: &mut CgroupSkb = bpf
        .program_mut("skb_egress")
        .context("skb_egress eBPF program not found")?
        .try_into()?;
    skb_egress.load().context("failed to load skb_egress")?;
    skb_egress
        .attach(&cgroup, CgroupSkbAttachType::Egress, CgroupAttachMode::default())
        .context("failed to attach skb_egress")?;
    info!(cgroup = %shared.cfg.runtime.cgroup, "eBPF skb_egress attached");

    let port_map: PortMap = Arc::new(RwLock::new(
        HashMap::try_from(bpf.take_map("PORT_MAP").context("PORT_MAP not found")?)?,
    ));

    // ─── Relay listener ────────────────────────────────────────────────────
    let listener = TcpListener::bind(&shared.cfg.runtime.listen)
        .await
        .with_context(|| format!("failed to bind relay listener on {}", shared.cfg.runtime.listen))?;
    info!(listen = %shared.cfg.runtime.listen, "heimdall ready");

    loop {
        let (stream, peer) = listener.accept().await?;
        let map = port_map.clone();
        let shared = shared.clone();

        tokio::spawn(async move {
            let client_port = peer.port() as u32;
            debug!(client_port, "accepted redirected connection");
            if let Err(e) = relay(stream, client_port, map, shared).await {
                warn!(client_port, "relay error: {e:#}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection relay: pod identity → routing → upstream
// ---------------------------------------------------------------------------

async fn relay(
    mut client: TcpStream,
    client_port: u32,
    map: PortMap,
    shared: Arc<Shared>,
) -> Result<()> {
    // Pop the original destination (and cgroup_id) from the BPF map.
    let orig = {
        let m = map.read().await;
        m.get(&client_port, 0)
            .with_context(|| format!("BPF map miss for client port {client_port}"))?
    };
    map.write().await.remove(&client_port).ok();

    let dst_ip = Ipv4Addr::from(u32::from_be(orig.ip));
    let dst_port = u16::from_be(orig.port);

    // ─── Fake-IP reverse lookup ────────────────────────────────────────────
    // If the dst falls in heimdall's fake-IP pool we have a hostname for it
    // and prefer SOCKS5 ATYP=0x03 so the upstream proxy resolves it via
    // its own resolver (which knows internal / VPN-pushed DNS we don't).
    let dst = match shared.dns.as_ref().and_then(|d| d.lookup_be(orig.ip)) {
        Some(host) => {
            debug!(%dst_ip, %host, "fake-IP reverse lookup hit");
            Dst::Domain(host)
        }
        None => Dst::Ip(dst_ip),
    };

    // ─── Resolve pod identity ──────────────────────────────────────────────
    let pod_info = match (&shared.cgroup_resolver, &shared.informer) {
        (Some(cr), Some(inf)) => cr
            .resolve(orig.cgroup_id)
            .and_then(|uid| inf.lookup(&uid)),
        _ => None,
    };

    // ─── Pick connection ───────────────────────────────────────────────────
    let conn_name = router::resolve_connection(&shared.cfg, pod_info.as_ref());
    let upstream = shared
        .upstreams
        .get(&conn_name)
        .with_context(|| format!("resolved connection `{conn_name}` not in registry"))?
        .clone();

    let pod_label = pod_info
        .as_ref()
        .map(|p| format!("{}/{}", p.namespace, p.name))
        .unwrap_or_else(|| "unknown".to_string());

    let (dst_label, dst_host_for_store, atyp) = match &dst {
        Dst::Ip(ip) => (ip.to_string(), None, "ip"),
        Dst::Domain(d) => (d.clone(), Some(d.clone()), "domain"),
    };

    // ─── Record flow start to store (best-effort) ─────────────────────────
    let flow_id = if let Some(s) = shared.store.as_ref() {
        let upstream_addr = match upstream.as_ref() {
            Upstream::Socks5 { addr, .. } => Some(addr.clone()),
            Upstream::Direct => None,
        };
        match s
            .insert_flow_start(store::FlowStart {
                socket_cookie: None, // Phase B will plumb from eBPF
                cgroup_id: Some(orig.cgroup_id),
                pod_uid: pod_info.as_ref().map(|p| p.uid.clone()),
                namespace: pod_info.as_ref().map(|p| p.namespace.clone()),
                pod_name: pod_info.as_ref().map(|p| p.name.clone()),
                connection_name: conn_name.clone(),
                dst_host: dst_host_for_store,
                dst_ip: dst_ip.to_string(),
                dst_port,
                upstream_addr,
                atyp: Some(atyp),
            })
            .await
        {
            Ok(id) => Some(id),
            Err(e) => {
                warn!(error = %e, "store: insert_flow_start failed");
                None
            }
        }
    } else {
        None
    };

    // ─── Open the chosen upstream ──────────────────────────────────────────
    let result: Result<(u64, u64)> = async {
        match upstream.as_ref() {
            Upstream::Socks5 { addr, auth } => {
                let mut up = TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("connect to SOCKS5 {addr}"))?;
                socks5_connect(&mut up, &dst, dst_port, auth.as_ref())
                    .await
                    .with_context(|| format!("SOCKS5 CONNECT {dst_label}:{dst_port} via {addr}"))?;
                info!(
                    pod = %pod_label,
                    connection = %conn_name,
                    dst = %dst_label,
                    dst_port,
                    via = %addr,
                    "tunnel established"
                );
                let (u, d) = copy_bidirectional(&mut client, &mut up).await?;
                Ok((u, d))
            }
            Upstream::Direct => {
                let target = match &dst {
                    Dst::Ip(ip) => format!("{ip}:{dst_port}"),
                    Dst::Domain(d) => format!("{d}:{dst_port}"),
                };
                let mut up = TcpStream::connect(&target)
                    .await
                    .with_context(|| format!("direct connect to {target}"))?;
                info!(
                    pod = %pod_label,
                    connection = %conn_name,
                    dst = %dst_label,
                    dst_port,
                    "tunnel established (direct)"
                );
                let (u, d) = copy_bidirectional(&mut client, &mut up).await?;
                Ok((u, d))
            }
        }
    }
    .await;

    // ─── Record flow finish (best-effort) + publish to live bus ──────────
    if let (Some(s), Some(id)) = (shared.store.as_ref(), flow_id) {
        let finish = match &result {
            Ok((u, d)) => store::FlowFinish {
                bytes_up: *u as i64,
                bytes_down: *d as i64,
                error: None,
            },
            Err(e) => store::FlowFinish {
                bytes_up: 0,
                bytes_down: 0,
                error: Some(format!("{e:#}")),
            },
        };
        if let Err(e) = s.finish_flow(id, finish).await {
            warn!(error = %e, "store: finish_flow failed");
        } else {
            shared.events.publish(api::FlowEvent { flow_id: id });
        }
    }

    result.map(|_| ())
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake (RFC 1928 + RFC 1929 user/pass)
// ---------------------------------------------------------------------------

const M_NO_AUTH: u8 = 0x00;
const M_USER_PASS: u8 = 0x02;
const M_NO_ACCEPTABLE: u8 = 0xFF;

async fn socks5_connect(
    s: &mut TcpStream,
    dst: &Dst,
    port: u16,
    auth: Option<&ResolvedAuth>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ─── Method negotiation (RFC 1928 §3) ────────────────────────────────
    let methods: &[u8] = if auth.is_some() {
        &[M_NO_AUTH, M_USER_PASS]
    } else {
        &[M_NO_AUTH]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    s.write_all(&greeting).await?;

    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    anyhow::ensure!(sel[0] == 0x05, "SOCKS5: bad version in method reply: {sel:?}");

    match sel[1] {
        M_NO_AUTH => {}
        M_USER_PASS => {
            let auth = auth.context("server demands user/pass but no credentials configured")?;
            socks5_userpass(s, &auth.username, &auth.password).await?;
        }
        M_NO_ACCEPTABLE => anyhow::bail!("SOCKS5: server rejected all offered methods"),
        other => anyhow::bail!("SOCKS5: unsupported method 0x{other:02x}"),
    }

    // ─── CONNECT request (RFC 1928 §4) ───────────────────────────────────
    let port_be = port.to_be_bytes();
    let mut req = Vec::with_capacity(8 + 256);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CMD=CONNECT, RSV
    match dst {
        Dst::Ip(ip) => {
            req.push(0x01); // ATYP=IPv4
            req.extend_from_slice(&ip.octets());
        }
        Dst::Domain(host) => {
            anyhow::ensure!(
                host.len() <= 255,
                "SOCKS5: domain name too long ({} bytes)",
                host.len()
            );
            req.push(0x03); // ATYP=DOMAINNAME
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port_be);
    s.write_all(&req).await?;

    // ─── CONNECT reply (RFC 1928 §6) — variable length ───────────────────
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    anyhow::ensure!(hdr[0] == 0x05, "SOCKS5: bad version in CONNECT reply: {hdr:?}");
    anyhow::ensure!(
        hdr[1] == 0x00,
        "SOCKS5 CONNECT rejected by server: code=0x{:02x}",
        hdr[1]
    );
    // Drain BND.ADDR + BND.PORT based on the reply ATYP (independent of request).
    match hdr[3] {
        0x01 => {
            let mut tail = [0u8; 4 + 2];
            s.read_exact(&mut tail).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            s.read_exact(&mut len_buf).await?;
            let mut tail = vec![0u8; len_buf[0] as usize + 2];
            s.read_exact(&mut tail).await?;
        }
        0x04 => {
            let mut tail = [0u8; 16 + 2];
            s.read_exact(&mut tail).await?;
        }
        other => anyhow::bail!("SOCKS5: unknown reply ATYP 0x{other:02x}"),
    }
    Ok(())
}

async fn socks5_userpass(s: &mut TcpStream, user: &str, pass: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    anyhow::ensure!(user.len() <= 255, "SOCKS5 user/pass: username > 255 bytes");
    anyhow::ensure!(pass.len() <= 255, "SOCKS5 user/pass: password > 255 bytes");

    let mut req = Vec::with_capacity(3 + user.len() + pass.len());
    req.push(0x01);
    req.push(user.len() as u8);
    req.extend_from_slice(user.as_bytes());
    req.push(pass.len() as u8);
    req.extend_from_slice(pass.as_bytes());
    s.write_all(&req).await?;

    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    anyhow::ensure!(resp[0] == 0x01, "SOCKS5 user/pass: bad sub-version: {resp:?}");
    anyhow::ensure!(resp[1] == 0x00, "SOCKS5 user/pass: auth failed (status=0x{:02x})", resp[1]);
    Ok(())
}
