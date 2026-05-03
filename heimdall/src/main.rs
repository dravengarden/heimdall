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
//!   heimdall daemon (listens on --listen, defaults to 0.0.0.0:12345)
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
//! The eBPF hooks attach to the kubepods cgroup and cover every pod on the node.
//! Use --relay-ip to set the host IP reachable from pods (e.g., cilium_host 10.244.0.41),
//! so the eBPF hook redirects pods to the right address.

use std::{net::Ipv4Addr, sync::Arc};

use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
    Ebpf,
};
use clap::Parser;
use heimdall_common::OrigDst;
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
///
/// Intercepts all outbound TCP connections from processes in the attached
/// cgroup and tunnels them through a SOCKS5 server — no per-app config needed.
#[derive(Parser, Debug)]
#[command(name = "heimdall", version, about, long_about = None)]
struct Cli {
    /// SOCKS5 server address.
    #[arg(long, env = "SOCKS5_ADDR")]
    socks5: String,

    /// Local address for the relay listener.
    ///
    /// Use 0.0.0.0:12345 when serving Kubernetes pods (pods cannot reach
    /// the host's 127.0.0.1 from a different network namespace).
    #[arg(long, default_value = "0.0.0.0:12345", env = "LISTEN_ADDR")]
    listen: String,

    /// IPv4 address to redirect intercepted connections to.
    ///
    /// Written into the RELAY_ADDR BPF map so the eBPF hook knows where to
    /// redirect connect() calls. Must be reachable by cgroup processes.
    ///
    /// For host-only: 127.0.0.1 (default).
    /// For Kubernetes pods: use the host's cilium_host IP (e.g., 10.244.0.41)
    /// or node IP reachable from pods.
    #[arg(long, default_value = "127.0.0.1", env = "RELAY_IP")]
    relay_ip: Ipv4Addr,

    /// cgroup v2 mount point to attach the eBPF programs to.
    #[arg(long, default_value = "/sys/fs/cgroup", env = "CGROUP_PATH")]
    cgroup: String,

    /// Additional CIDR ranges that bypass the proxy (comma-separated).
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
                .add_directive("heimdall=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Load eBPF object and attach programs ------------------------------------
    let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF object")?;

    // Write relay IP into the BPF map BEFORE attaching hooks.
    // The eBPF connect4 hook reads this to know where to redirect connections
    // and to avoid re-intercepting connections already going to the relay.
    {
        let relay_ip_be = u32::from(cli.relay_ip).to_be();
        let mut relay_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(bpf.map_mut("RELAY_ADDR").context("RELAY_ADDR not found")?)?;
        relay_map.set(0, relay_ip_be, 0).context("failed to set relay IP in BPF map")?;
        info!(relay_ip = %cli.relay_ip, "relay IP written to BPF map");
    }

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
    info!(cgroup = %cli.cgroup, relay_ip = %cli.relay_ip, "eBPF connect4 hook attached");

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
    info!(cgroup = %cli.cgroup, "eBPF skb_egress hook attached");

    // Shared BPF map: client ephemeral port → original destination ------------
    let port_map: PortMap = Arc::new(RwLock::new(
        HashMap::try_from(
            bpf.take_map("PORT_MAP").context("PORT_MAP not found")?,
        )?,
    ));

    // Start relay listener ----------------------------------------------------
    let listener = TcpListener::bind(&cli.listen)
        .await
        .with_context(|| format!("failed to bind relay listener on {}", cli.listen))?;

    info!(
        listen = %cli.listen,
        socks5 = %cli.socks5,
        "heimdall ready"
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
