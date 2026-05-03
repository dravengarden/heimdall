//! heimdall — transparent SOCKS5 egress proxy driven by eBPF.
//!
//! Works as a standalone CLI tool or as a Kubernetes DaemonSet.
//!
//! ## How it works
//!
//!   Any process connect(external_ip:port)
//!       │
//!       │  [eBPF BPF_CGROUP_INET4_CONNECT hook]
//!       │  Rewrites dst → relay_ip:12345
//!       │  Saves original dst in COOKIE_MAP[socket_cookie]
//!       │
//!       │  [eBPF BPF_CGROUP_INET_EGRESS hook on first SYN]
//!       │  inet_hash_connect already ran → ephemeral src port is assigned.
//!       │  Moves COOKIE_MAP[cookie] → PORT_MAP[src_port]
//!       │
//!       ▼
//!   heimdall daemon (listens on runtime.listen, default 0.0.0.0:12345)
//!       │  accept() → getpeername().port → lookup PORT_MAP
//!       │  resolve which "connection" (upstream proxy) to use for this pod
//!       │
//!       ▼
//!   Upstream (SOCKS5 with optional auth, or direct splice)
//!       │  CONNECT original_ip:original_port
//!       │
//!       ▼
//!   External network
//!
//! ## Configuration
//!
//! Driven by `/etc/heimdall/config.yaml` (see `heimdall-config` crate). The
//! schema documents `runtime`, `connections`, and `routing`. Today only
//! `runtime` and `routing.default` are honored — per-pod selection (M3+M4)
//! lands later but the config is forward-compatible.

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};

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

// eBPF object compiled from heimdall-ebpf, embedded at build time.
// Build first: cargo +nightly build (from heimdall-ebpf dir)
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
// CLI
// ---------------------------------------------------------------------------

/// Transparent SOCKS5 egress proxy using eBPF cgroup hooks.
#[derive(Parser, Debug)]
#[command(name = "heimdall", version, about, long_about = None)]
struct Cli {
    /// Path to YAML config (see /etc/<host-config>/docs/heimdall.md for schema).
    #[arg(long, default_value = heimdall_config::DEFAULT_PATH, env = "HEIMDALL_CONFIG")]
    config: PathBuf,
}

// ---------------------------------------------------------------------------
// Resolved upstream — produced from the chosen Connection
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("heimdall=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // ─── Load config ──────────────────────────────────────────────────────
    let cfg = HeimdallConfig::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;
    info!(
        path = %cli.config.display(),
        connections = cfg.connections.len(),
        rules = cfg.routing.rules.len(),
        default = %cfg.routing.default,
        "config loaded"
    );

    // For M2/today: every connection uses the routing.default connection.
    // M3+M4 will replace this with per-pod resolution.
    let default_conn = cfg.default_connection();
    let upstream = Upstream::from_connection(default_conn)
        .with_context(|| format!("resolving default connection `{}`", cfg.routing.default))?;
    info!(
        connection = %cfg.routing.default,
        kind = default_conn.type_str(),
        "active upstream"
    );
    let upstream = Arc::new(upstream);

    // ─── Load eBPF object and attach programs ─────────────────────────────
    let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF object")?;

    // Write relay IP into the BPF map BEFORE attaching hooks.
    // The eBPF connect4 hook reads this to know where to redirect connections
    // and to avoid re-intercepting connections already going to the relay.
    {
        let relay_ip_be = u32::from(cfg.runtime.relay_ip).to_be();
        let mut relay_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(bpf.map_mut("RELAY_ADDR").context("RELAY_ADDR not found")?)?;
        relay_map.set(0, relay_ip_be, 0).context("failed to set relay IP in BPF map")?;
        info!(relay_ip = %cfg.runtime.relay_ip, "relay IP written to BPF map");
    }

    let cgroup = std::fs::File::open(&cfg.runtime.cgroup)
        .with_context(|| format!("failed to open cgroup path: {}", cfg.runtime.cgroup))?;

    // Hook 1: intercept connect() and rewrite destination
    let connect4: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .context("connect4 eBPF program not found")?
        .try_into()?;
    connect4.load().context("failed to load connect4")?;
    connect4
        .attach(&cgroup, CgroupAttachMode::default())
        .context("failed to attach connect4")?;
    info!(cgroup = %cfg.runtime.cgroup, relay_ip = %cfg.runtime.relay_ip, "eBPF connect4 hook attached");

    // Hook 2: on first SYN to relay, move cookie_map → port_map by src_port.
    // Runs at cgroup_skb egress time, after inet_hash_connect assigns src port.
    let skb_egress: &mut CgroupSkb = bpf
        .program_mut("skb_egress")
        .context("skb_egress eBPF program not found")?
        .try_into()?;
    skb_egress.load().context("failed to load skb_egress")?;
    skb_egress
        .attach(&cgroup, CgroupSkbAttachType::Egress, CgroupAttachMode::default())
        .context("failed to attach skb_egress")?;
    info!(cgroup = %cfg.runtime.cgroup, "eBPF skb_egress hook attached");

    // Shared BPF map: client ephemeral port → original destination
    let port_map: PortMap = Arc::new(RwLock::new(
        HashMap::try_from(
            bpf.take_map("PORT_MAP").context("PORT_MAP not found")?,
        )?,
    ));

    // ─── Start relay listener ─────────────────────────────────────────────
    let listener = TcpListener::bind(&cfg.runtime.listen)
        .await
        .with_context(|| format!("failed to bind relay listener on {}", cfg.runtime.listen))?;

    info!(listen = %cfg.runtime.listen, "heimdall ready");

    loop {
        let (stream, peer) = listener.accept().await?;
        let map = port_map.clone();
        let upstream = upstream.clone();

        tokio::spawn(async move {
            let client_port = peer.port() as u32;
            debug!(client_port, "accepted redirected connection");

            if let Err(e) = relay(stream, client_port, map, upstream).await {
                warn!(client_port, "relay error: {e:#}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection relay
// ---------------------------------------------------------------------------

async fn relay(
    mut client: TcpStream,
    client_port: u32,
    map: PortMap,
    upstream: Arc<Upstream>,
) -> Result<()> {
    // Retrieve and immediately remove the original destination from the BPF map.
    let orig = {
        let m = map.read().await;
        m.get(&client_port, 0)
            .with_context(|| format!("BPF map miss for client port {client_port}"))?
    };
    map.write().await.remove(&client_port).ok();

    let dst_ip = Ipv4Addr::from(u32::from_be(orig.ip));
    let dst_port = u16::from_be(orig.port);
    debug!(%dst_ip, dst_port, "original destination resolved");

    match upstream.as_ref() {
        Upstream::Socks5 { addr, auth } => {
            let mut up = TcpStream::connect(addr)
                .await
                .with_context(|| format!("failed to connect to SOCKS5 {addr}"))?;
            socks5_connect(&mut up, dst_ip, dst_port, auth.as_ref())
                .await
                .with_context(|| format!("SOCKS5 CONNECT {dst_ip}:{dst_port} via {addr}"))?;
            info!(%dst_ip, dst_port, via = %addr, "tunnel established");
            copy_bidirectional(&mut client, &mut up).await?;
        }
        Upstream::Direct => {
            let dst = format!("{dst_ip}:{dst_port}");
            let mut up = TcpStream::connect(&dst)
                .await
                .with_context(|| format!("direct connect to {dst}"))?;
            info!(%dst_ip, dst_port, "tunnel established (direct)");
            copy_bidirectional(&mut client, &mut up).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake (RFC 1928 + RFC 1929 user/pass auth)
// ---------------------------------------------------------------------------

const M_NO_AUTH: u8 = 0x00;
const M_USER_PASS: u8 = 0x02;
const M_NO_ACCEPTABLE: u8 = 0xFF;

async fn socks5_connect(
    s: &mut TcpStream,
    ip: Ipv4Addr,
    port: u16,
    auth: Option<&ResolvedAuth>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Method negotiation. Offer methods we support.
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
        M_NO_AUTH => { /* proceed without auth */ }
        M_USER_PASS => {
            let auth = auth.context("server demands user/pass but no credentials configured")?;
            socks5_userpass(s, &auth.username, &auth.password).await?;
        }
        M_NO_ACCEPTABLE => anyhow::bail!("SOCKS5: server rejected all offered methods"),
        other => anyhow::bail!("SOCKS5: unsupported method 0x{other:02x}"),
    }

    // CONNECT request with IPv4 address
    let ip = ip.octets();
    let port_be = port.to_be_bytes();
    s.write_all(&[
        0x05, 0x01, 0x00, 0x01, // VER, CMD=CONNECT, RSV, ATYP=IPv4
        ip[0], ip[1], ip[2], ip[3],
        port_be[0], port_be[1],
    ])
    .await?;

    // Read reply (fixed 10 bytes for IPv4 BND.ADDR)
    let mut resp = [0u8; 10];
    s.read_exact(&mut resp).await?;
    anyhow::ensure!(
        resp[1] == 0x00,
        "SOCKS5 CONNECT rejected by server: code=0x{:02x}",
        resp[1]
    );

    Ok(())
}

/// RFC 1929 username/password sub-negotiation.
async fn socks5_userpass(s: &mut TcpStream, user: &str, pass: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    anyhow::ensure!(user.len() <= 255, "SOCKS5 user/pass: username > 255 bytes");
    anyhow::ensure!(pass.len() <= 255, "SOCKS5 user/pass: password > 255 bytes");

    let mut req = Vec::with_capacity(3 + user.len() + pass.len());
    req.push(0x01); // sub-version
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
