//! kube-tproxy — transparent SOCKS5 egress proxy for Kubernetes pods.
//!
//! Architecture:
//!
//!   Pod connect(external_ip:port)
//!       │
//!       │  [eBPF connect4 hook]
//!       │  Rewrites dst → 127.0.0.1:PROXY_PORT
//!       │  Saves original dst in COOKIE_MAP[socket_cookie]
//!       │
//!       │  [eBPF sock_ops hook — after TCP handshake]
//!       │  Moves COOKIE_MAP[cookie] → PORT_MAP[client_ephemeral_port]
//!       │
//!       ▼
//!   kube-tproxy (this program, listens on PROXY_PORT)
//!       │  accept() → getpeername() → client_ephemeral_port
//!       │  lookup PORT_MAP[client_port] → original (ip, port)
//!       │
//!       ▼
//!   v2raya SOCKS5 (SOCKS5_ADDR)
//!       │  SOCKS5 CONNECT original_ip:original_port
//!       │
//!       ▼
//!   External internet (via configured proxy / VPN)

use std::{net::Ipv4Addr, sync::Arc};

use anyhow::{Context, Result};
use aya::{
    maps::HashMap,
    programs::{CgroupSockAddr, SockOps},
    Bpf,
};
use kube_tproxy_common::OrigDst;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tracing::{debug, error, info, warn};

// Where this daemon listens; must match PROXY_PORT in the eBPF program.
const PROXY_LISTEN: &str = "127.0.0.1:12345";

// v2raya SOCKS5 endpoint on the host.
const SOCKS5_ADDR: &str = "127.0.0.1:20170";

// cgroup v2 root — attach eBPF programs here to cover all pods on the node.
const CGROUP_PATH: &str = "/sys/fs/cgroup";

// Compiled eBPF object, embedded at build time.
// Build with: cargo build -p kube-tproxy-ebpf --target bpfel-unknown-none -Z build-std=core
const EBPF_BYTES: &[u8] = include_bytes!(
    "../../target/bpfel-unknown-none/release/kube-tproxy-ebpf"
);

// Shared handle to PORT_MAP, read by every accepted connection handler.
type PortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("kube_tproxy=info".parse()?),
        )
        .init();

    // Load and attach eBPF programs -------------------------------------------
    let mut bpf = Bpf::load(EBPF_BYTES).context("failed to load eBPF object")?;

    let cgroup = std::fs::File::open(CGROUP_PATH)
        .with_context(|| format!("failed to open cgroup {CGROUP_PATH}"))?;

    let connect4: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .context("connect4 program not found")?
        .try_into()?;
    connect4.load().context("failed to load connect4")?;
    connect4
        .attach(&cgroup, aya::programs::CgroupAttachMode::default())
        .context("failed to attach connect4")?;
    info!("eBPF connect4 hook attached to {CGROUP_PATH}");

    let sock_ops: &mut SockOps = bpf
        .program_mut("sock_ops_handler")
        .context("sock_ops_handler program not found")?
        .try_into()?;
    sock_ops.load().context("failed to load sock_ops_handler")?;
    sock_ops
        .attach(&cgroup, aya::programs::CgroupAttachMode::default())
        .context("failed to attach sock_ops_handler")?;
    info!("eBPF sock_ops hook attached to {CGROUP_PATH}");

    // Shared reference to the BPF port→orig_dst map ---------------------------
    let port_map: PortMap = Arc::new(RwLock::new(
        HashMap::try_from(bpf.map_mut("PORT_MAP").context("PORT_MAP not found")?)?,
    ));

    // Start accepting connections ----------------------------------------------
    let listener = TcpListener::bind(PROXY_LISTEN)
        .await
        .with_context(|| format!("failed to bind {PROXY_LISTEN}"))?;
    info!("Listening on {PROXY_LISTEN}, upstream SOCKS5 at {SOCKS5_ADDR}");

    loop {
        let (client, peer) = listener.accept().await?;
        let map = port_map.clone();

        tokio::spawn(async move {
            let client_port = peer.port() as u32;
            debug!(client_port, "accepted connection");

            if let Err(e) = proxy(client, client_port, map).await {
                warn!(client_port, "connection error: {e:#}");
            }
        });
    }
}

/// Handle one proxied connection.
async fn proxy(mut client: TcpStream, client_port: u32, map: PortMap) -> Result<()> {
    // Look up the original destination that eBPF saved for this client port.
    let orig = {
        let m = map.read().await;
        m.get(&client_port, 0)
            .with_context(|| format!("no BPF entry for client port {client_port}"))?
    };
    // Remove the entry immediately to avoid map exhaustion.
    map.write().await.remove(&client_port).ok();

    let dst_ip = Ipv4Addr::from(u32::from_be(orig.ip));
    let dst_port = u16::from_be(orig.port);
    debug!(%dst_ip, dst_port, "original destination resolved");

    // Connect to v2raya SOCKS5 and send a CONNECT request.
    let mut upstream = TcpStream::connect(SOCKS5_ADDR)
        .await
        .context("failed to connect to SOCKS5 upstream")?;

    socks5_connect(&mut upstream, dst_ip, dst_port)
        .await
        .with_context(|| format!("SOCKS5 CONNECT {dst_ip}:{dst_port} failed"))?;

    info!(%dst_ip, dst_port, "tunnel established");

    // Bidirectional transparent relay.
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Perform a SOCKS5 no-auth CONNECT handshake.
///
/// Protocol (RFC 1928):
///   C→S  \x05 \x01 \x00              (ver=5, nmethods=1, no-auth)
///   S→C  \x05 \x00                   (ver=5, method=no-auth)
///   C→S  \x05 \x01 \x00 \x01 <ip4> <port>  (CONNECT IPv4)
///   S→C  \x05 \x00 \x00 \x01 <ip4> <port>  (success)
async fn socks5_connect(s: &mut TcpStream, ip: Ipv4Addr, port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Method negotiation
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).await?;
    anyhow::ensure!(
        buf == [0x05, 0x00],
        "unexpected SOCKS5 method response: {buf:?}"
    );

    // CONNECT request — IPv4 address type (0x01)
    let ip = ip.octets();
    let port = port.to_be_bytes();
    s.write_all(&[
        0x05, 0x01, 0x00, 0x01,
        ip[0], ip[1], ip[2], ip[3],
        port[0], port[1],
    ])
    .await?;

    // Read response (10 bytes for IPv4 BND.ADDR)
    let mut resp = [0u8; 10];
    s.read_exact(&mut resp).await?;
    anyhow::ensure!(
        resp[1] == 0x00,
        "SOCKS5 server rejected CONNECT: code=0x{:02x}",
        resp[1]
    );

    Ok(())
}
