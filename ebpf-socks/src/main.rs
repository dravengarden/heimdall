//! ebpf-socks — transparent SOCKS5 egress proxy driven by eBPF.
//!
//! Works as a standalone CLI tool or as a Kubernetes DaemonSet.
//!
//! ## How it works
//!
//!   Any process connect(external_ip:port)
//!       │
//!       │  [eBPF BPF_CGROUP_INET4_CONNECT hook]
//!       │  Rewrites dst → 127.0.0.1:<listen-port>
//!       │  Saves original dst in COOKIE_MAP[socket_cookie]
//!       │
//!       │  [eBPF BPF_CGROUP_SOCK_OPS / ACTIVE_ESTABLISHED_CB]
//!       │  After TCP handshake the kernel knows the ephemeral src port.
//!       │  Moves COOKIE_MAP[cookie] → PORT_MAP[src_port]
//!       │
//!       ▼
//!   ebpf-socks daemon (listens on --listen)
//!       │  accept() → getpeername().port → lookup PORT_MAP
//!       │
//!       ▼
//!   SOCKS5 server (--socks5)
//!       │  CONNECT original_ip:original_port
//!       │
//!       ▼
//!   External network
//!
//! ## Kubernetes deployment
//!
//! Run as a privileged DaemonSet with hostPID and access to /sys/fs/cgroup.
//! Set SOCKS5_ADDR env var (or --socks5) to your cluster's SOCKS5 endpoint.
//! The eBPF hooks attach to the root cgroup and cover every pod on the node.

use std::{net::Ipv4Addr, sync::Arc};

use anyhow::{Context, Result};
use aya::{
    maps::HashMap,
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
    Bpf,
};
use clap::Parser;
use ebpf_socks_common::OrigDst;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tracing::{debug, info, warn};

// eBPF object compiled from ebpf-socks-ebpf, embedded at build time.
// Build first: cargo build -p ebpf-socks-ebpf --target bpfel-unknown-none -Z build-std=core
const EBPF_BYTES: &[u8] = include_bytes!(
    "../../target/bpfel-unknown-none/release/ebpf-socks-ebpf"
);

type PortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Transparent SOCKS5 egress proxy using eBPF cgroup hooks.
///
/// Intercepts all outbound TCP connections from processes in the attached
/// cgroup and tunnels them through a SOCKS5 server — no per-app config needed.
#[derive(Parser, Debug)]
#[command(name = "ebpf-socks", version, about, long_about = None)]
struct Cli {
    /// SOCKS5 server address.
    ///
    /// The upstream proxy that all intercepted connections are forwarded to.
    /// Supports env var SOCKS5_ADDR.
    ///
    /// Examples: 127.0.0.1:1080  socks5-proxy.default.svc:1080
    #[arg(long, env = "SOCKS5_ADDR")]
    socks5: String,

    /// Local address for the relay listener.
    ///
    /// The eBPF hook rewrites connect() targets to this address.
    /// Change only if port 12345 is already in use on the host.
    #[arg(long, default_value = "127.0.0.1:12345", env = "LISTEN_ADDR")]
    listen: String,

    /// cgroup v2 mount point to attach the eBPF programs to.
    ///
    /// Attaching to the root cgroup covers all processes on the host/node.
    /// Narrow this to a specific pod cgroup for finer-grained control.
    #[arg(long, default_value = "/sys/fs/cgroup", env = "CGROUP_PATH")]
    cgroup: String,

    /// Additional CIDR ranges that bypass the proxy (comma-separated).
    ///
    /// Default bypass list already includes RFC-1918, loopback, and link-local.
    /// Use this to add cluster-specific ranges, e.g. 100.64.0.0/10.
    #[arg(long, value_delimiter = ',', env = "BYPASS_CIDRS")]
    bypass: Vec<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ebpf_socks=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Load eBPF object and attach programs ------------------------------------
    let mut bpf = Bpf::load(EBPF_BYTES).context("failed to load eBPF object")?;

    let cgroup = std::fs::File::open(&cli.cgroup)
        .with_context(|| format!("failed to open cgroup path: {}", cli.cgroup))?;

    // Hook 1: intercept connect() and rewrite destination
    let connect4: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .context("connect4 eBPF program not found")?
        .try_into()?;
    connect4.load().context("failed to load connect4")?;
    connect4
        .attach(&cgroup, CgroupAttachMode::default())
        .context("failed to attach connect4")?;
    info!(cgroup = %cli.cgroup, "eBPF connect4 hook attached");

    // Hook 2: after TCP handshake, move cookie_map → port_map
    let sock_ops: &mut SockOps = bpf
        .program_mut("sock_ops_handler")
        .context("sock_ops_handler eBPF program not found")?
        .try_into()?;
    sock_ops.load().context("failed to load sock_ops_handler")?;
    sock_ops
        .attach(&cgroup, CgroupAttachMode::default())
        .context("failed to attach sock_ops_handler")?;
    info!(cgroup = %cli.cgroup, "eBPF sock_ops hook attached");

    // Shared BPF map: client ephemeral port → original destination ------------
    let port_map: PortMap = Arc::new(RwLock::new(
        HashMap::try_from(bpf.map_mut("PORT_MAP").context("PORT_MAP not found")?)?,
    ));

    // Start relay listener ----------------------------------------------------
    let listener = TcpListener::bind(&cli.listen)
        .await
        .with_context(|| format!("failed to bind relay listener on {}", cli.listen))?;

    info!(
        listen = %cli.listen,
        socks5 = %cli.socks5,
        "ebpf-socks ready"
    );

    let socks5_addr = Arc::new(cli.socks5);

    loop {
        let (stream, peer) = listener.accept().await?;
        let map = port_map.clone();
        let socks5 = socks5_addr.clone();

        tokio::spawn(async move {
            let client_port = peer.port() as u32;
            debug!(client_port, "accepted redirected connection");

            if let Err(e) = relay(stream, client_port, map, &socks5).await {
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
    socks5_addr: &str,
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

    // Open a connection to the SOCKS5 server and request a tunnel.
    let mut upstream = TcpStream::connect(socks5_addr)
        .await
        .with_context(|| format!("failed to connect to SOCKS5 server {socks5_addr}"))?;

    socks5_connect(&mut upstream, dst_ip, dst_port)
        .await
        .with_context(|| format!("SOCKS5 CONNECT {dst_ip}:{dst_port} failed"))?;

    info!(%dst_ip, dst_port, "tunnel established");

    // Transparent bidirectional relay.
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake (RFC 1928, no-auth, IPv4 CONNECT)
// ---------------------------------------------------------------------------

async fn socks5_connect(s: &mut TcpStream, ip: Ipv4Addr, port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Method negotiation: offer "no authentication"
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).await?;
    anyhow::ensure!(buf == [0x05, 0x00], "SOCKS5 method negotiation failed: {buf:?}");

    // CONNECT request with IPv4 address
    let ip = ip.octets();
    let port = port.to_be_bytes();
    s.write_all(&[
        0x05, 0x01, 0x00, 0x01, // VER, CMD=CONNECT, RSV, ATYP=IPv4
        ip[0], ip[1], ip[2], ip[3],
        port[0], port[1],
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
