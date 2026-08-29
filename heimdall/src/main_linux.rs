// Linux foreground implementation. This file is included at the crate root so
// the established module paths and embedded eBPF data path remain unchanged.

mod capture;
mod dns;
mod ebpf;
mod heimdall_common;
mod http;
mod resolver;
mod setup;
mod tls_relay;
mod tls_runtime;

use std::{
    collections::HashMap as StdHashMap,
    ffi::OsString,
    io::{IoSlice, IoSliceMut, Read},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::heimdall_common::{FAMILY_V4, FAMILY_V6, OrigDst, relay_key};
use crate::heimdall_config::{Action, HeimdallConfig};
use crate::relay_transport::{
    Dst, SOCKS5_HANDSHAKE_TIMEOUT, Upstream, decode_socks5_udp_payload,
    destination_socket_addr, encode_socks5_udp_frame, open_socks5_tunnel_with_timeouts,
    open_socks5_udp_association, resolve_all,
};
use anyhow::{Context, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap},
    programs::{
        CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr, links::FdLink,
    },
};
use clap::Parser;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn,
    SockaddrStorage, bind, recvmsg, sendmsg, setsockopt, socket, sockopt,
};
use tokio::{
    io::unix::AsyncFd,
    io::{AsyncReadExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, RwLock, mpsc},
};
use tracing::{debug, info, warn};

use crate::dns::DnsResolver;

// eBPF object compiled from heimdall-ebpf, embedded at build time.
//
// The wrapper ensures 8-byte alignment, which the ELF parser requires when
// parsing 64-bit ELF from a static byte slice.
#[repr(C, align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

static EBPF_OBJ: AlignedBytes<{ include_bytes!("../embedded/heimdall-ebpf").len() }> =
    AlignedBytes(*include_bytes!("../embedded/heimdall-ebpf"));

const EBPF_BYTES: &[u8] = &EBPF_OBJ.0;

type PortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;
type UdpPortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;
type UdpTokenMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;
type UdpCookieMap = Arc<RwLock<HashMap<aya::maps::MapData, u64, OrigDst>>>;
pub(crate) type UdpSessions = Arc<Mutex<StdHashMap<UdpSessionKey, UdpSessionHandle>>>;

const UDP_SESSION_QUEUE: usize = 128;
const UDP_MAX_SESSIONS: usize = 4096;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
static NEXT_UDP_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct UdpSessionHandle {
    id: u64,
    cgroup_id: u64,
    tx: mpsc::Sender<UdpRequest>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum UdpSessionKey {
    Token(u32),
    Cookie(u64),
}

struct UdpRequest {
    payload: Vec<u8>,
}

#[derive(Clone)]
struct UdpRelayContext {
    relay: UdpResponseRelay,
    ports: UdpPortMap,
    tokens: UdpTokenMap,
    cookies: UdpCookieMap,
    sessions: UdpSessions,
    shared: Arc<Shared>,
}

struct UdpSessionRuntime {
    peer: SocketAddr,
    token: Option<u32>,
    relay: UdpResponseRelay,
    cookies: UdpCookieMap,
    shared: Arc<Shared>,
}

#[derive(Clone)]
enum UdpResponseRelay {
    Token(Arc<UdpRelaySocket>),
    Ipv6(Arc<UdpSocket>),
}

impl UdpResponseRelay {
    async fn send(&self, payload: &[u8], peer: SocketAddr, token: Option<u32>) -> Result<()> {
        match (self, token) {
            (Self::Token(relay), Some(token)) => relay.send(payload, peer, token).await,
            (Self::Ipv6(relay), None) => {
                relay
                    .send_to(payload, peer)
                    .await
                    .with_context(|| format!("return IPv6 UDP response to {peer}"))?;
                Ok(())
            }
            _ => anyhow::bail!("UDP relay correlation mode mismatch"),
        }
    }
}

enum UdpCorrelation {
    Token(u32),
    Port(u32),
}

struct UdpRelaySocket {
    fd: AsyncFd<OwnedFd>,
}

struct RelayRuntime {
    tcp_v4: TcpListener,
    tcp_v6: TcpListener,
    udp_v4: Arc<UdpRelaySocket>,
    udp_v6: Arc<UdpSocket>,
    port: u16,
}

struct SessionRuntime {
    relay: RelayRuntime,
    dns: Arc<DnsResolver>,
    dns_task: tokio::task::JoinHandle<()>,
    dns_port: u16,
    kernel: Option<KernelRuntime>,
}

struct InstalledSetupRuntime {
    buffers: Vec<(u32, OwnedFd)>,
    report: Option<tls_runtime::StartReport>,
    worker: Option<setup::SetupWorker>,
}

struct KernelRuntime {
    port_map: PortMap,
    udp_port_map: UdpPortMap,
    udp_token_map: UdpTokenMap,
    udp_cookie_map: UdpCookieMap,
    _links: KernelLinks,
}

enum KernelLinks {
    Raw { _fds: Vec<OwnedFd> },
}

impl SessionRuntime {
    async fn bind_foreground(_cfg: &HeimdallConfig, state_path: PathBuf) -> Result<Self> {
        let relay = RelayRuntime::bind().await?;
        let dns = Arc::new(
            DnsResolver::with_state(dns::FAKE_IPV4_CIDR, dns::FAKE_IPV6_CIDR, &state_path)
                .context("initialize fake-IP DNS resolver")?,
        );
        let dns_server = dns.clone().bind(0).await?;
        let dns_port = dns_server.port();
        let dns_task = tokio::spawn(async move {
            if let Err(error) = dns_server.serve().await {
                warn!(%error, "DNS server exited");
            }
        });

        Ok(Self {
            relay,
            dns,
            dns_task,
            dns_port,
            kernel: None,
        })
    }

    fn install_kernel(&mut self, kernel: KernelRuntime) -> Result<()> {
        anyhow::ensure!(
            self.kernel.is_none(),
            "session kernel runtime was already installed"
        );
        self.kernel = Some(kernel);
        Ok(())
    }

    fn kernel(&self) -> Result<&KernelRuntime> {
        self.kernel
            .as_ref()
            .context("session kernel runtime is not installed")
    }

    fn install_setup_bundle(
        &mut self,
        bundle: setup::SetupBundle,
    ) -> Result<InstalledSetupRuntime> {
        let runtime = bundle.into_runtime_fds()?;
        let runtime_buffers = runtime.runtime_buffers;
        let runtime_report = runtime.runtime;
        self.install_kernel(KernelRuntime {
            port_map: Arc::new(RwLock::new(runtime.port_map)),
            udp_port_map: Arc::new(RwLock::new(runtime.udp_port_map)),
            udp_token_map: Arc::new(RwLock::new(runtime.udp_token_map)),
            udp_cookie_map: Arc::new(RwLock::new(runtime.udp_cookie_map)),
            _links: KernelLinks::Raw {
                _fds: runtime.links,
            },
        })?;
        Ok(InstalledSetupRuntime {
            buffers: runtime_buffers,
            report: runtime_report,
            worker: runtime.worker,
        })
    }

    fn relay_port(&self) -> u16 {
        self.relay.port()
    }

    fn dns_port(&self) -> u16 {
        self.dns_port
    }

    async fn serve(&self, udp_sessions: UdpSessions, shared: Arc<Shared>) -> Result<()> {
        let kernel = self.kernel()?;
        self.relay
            .serve(
                kernel.port_map.clone(),
                kernel.udp_port_map.clone(),
                kernel.udp_token_map.clone(),
                kernel.udp_cookie_map.clone(),
                udp_sessions,
                shared,
            )
            .await
    }
}

pub(crate) struct ForegroundSession {
    cgroup_id: u64,
    runtime: Arc<SessionRuntime>,
    relay_task: tokio::task::JoinHandle<Result<()>>,
    udp_sessions: UdpSessions,
    event_client: event_log::EventClient,
    _runtime_tls: Option<tls_runtime::RuntimeCapture>,
    setup_worker: Option<setup::SetupWorker>,
}

impl ForegroundSession {
    pub(crate) async fn start(
        cfg: &HeimdallConfig,
        policy_name: &str,
        cgroup_path: PathBuf,
        cgroup_id: u64,
        event_socket: PathBuf,
        dns_state_path: PathBuf,
    ) -> Result<Self> {
        let selected = cfg
            .policy(policy_name)
            .with_context(|| format!("selected policy `{policy_name}` disappeared"))?;
        let mut policy_flags = 0;
        if selected.dns_hijack() {
            policy_flags |= crate::heimdall_common::POLICY_DNS_HIJACK;
        } else {
            policy_flags |= crate::heimdall_common::POLICY_DNS_SYSTEM;
        }
        if selected.rejects_all_udp() {
            policy_flags |= crate::heimdall_common::POLICY_UDP_REJECT;
        }

        let upstreams = resolve_all(cfg)?;
        let relay_tls = (cfg.decrypt.mode == crate::heimdall_config::DecryptMode::Relay)
            .then(|| {
                let ca_cert = cfg
                    .decrypt
                    .ca_cert
                    .as_deref()
                    .context("strict config accepted relay decrypt without ca_cert")?;
                let ca_key = cfg
                    .decrypt
                    .ca_key
                    .as_deref()
                    .context("strict config accepted relay decrypt without ca_key")?;
                Ok::<_, anyhow::Error>(Arc::new(
                    tls_relay::RelayTls::load(ca_cert, ca_key)
                        .context("initialize foreground relay TLS decryption")?,
                ))
            })
            .transpose()?;

        let mut runtime = SessionRuntime::bind_foreground(cfg, dns_state_path).await?;
        let request = setup::SetupRequest::new(
            cgroup_path,
            cgroup_id,
            runtime.relay_port(),
            runtime.dns_port(),
            policy_flags,
            cfg.decrypt.mode == crate::heimdall_config::DecryptMode::Runtime,
        )?;
        let bundle = tokio::task::spawn_blocking(move || setup::launch_worker(&request))
            .await
            .context("join setup worker launcher")??;
        let installed = runtime.install_setup_bundle(bundle)?;
        let event_client = event_log::EventClient::connect(event_socket)?;
        runtime
            .dns
            .configure_events(event_client.clone(), policy_name)
            .context("configure foreground DNS event evidence")?;
        let capture =
            capture::CaptureManager::from_config(&cfg.capture, Some(event_client.clone()))
                .await
                .context("initialize foreground payload capture")?;
        let runtime_tls = match installed.report {
            Some(report) => {
                anyhow::ensure!(
                    report.attached_images > 0,
                    "runtime TLS found no attachable OpenSSL images in active mappings or system loader directories; install a supported OpenSSL shared library in a standard loader path, or use decrypt.mode = relay"
                );
                anyhow::ensure!(
                    installed.buffers.len() == report.perf_cpus.len(),
                    "setup worker returned an incomplete runtime TLS perf bundle"
                );
                let capture = capture
                    .clone()
                    .context("strict config enabled runtime decrypt without capture")?;
                Some(
                    tls_runtime::start_from_fds(installed.buffers, capture)
                        .context("start foreground runtime TLS capture")?,
                )
            }
            None => {
                anyhow::ensure!(
                    installed.buffers.is_empty(),
                    "setup worker returned runtime TLS buffers without a report"
                );
                None
            }
        };

        let cli_overrides: CliOverrides = Arc::new(parking_lot::RwLock::new(StdHashMap::from([(
            cgroup_id,
            crate::heimdall_config::Decision {
                policy: policy_name.to_owned(),
            },
        )])));
        let event_clients: EventClients = Arc::new(parking_lot::RwLock::new(StdHashMap::from([(
            cgroup_id,
            event_client.clone(),
        )])));
        let udp_sessions: UdpSessions = Arc::new(Mutex::new(StdHashMap::new()));
        let shared = Arc::new(Shared {
            cfg: cfg.clone(),
            upstreams,
            capture,
            relay_tls,
            dns: Some(runtime.dns.clone()),
            cli_overrides,
            event_clients,
        });
        let runtime = Arc::new(runtime);
        let relay_runtime = Arc::clone(&runtime);
        let relay_sessions = Arc::clone(&udp_sessions);
        let relay_task =
            tokio::spawn(async move { relay_runtime.serve(relay_sessions, shared).await });

        Ok(Self {
            cgroup_id,
            runtime,
            relay_task,
            udp_sessions,
            event_client,
            _runtime_tls: runtime_tls,
            setup_worker: installed.worker,
        })
    }

    pub(crate) async fn shutdown(mut self) -> bool {
        close_udp_sessions_for_cgroup(&self.udp_sessions, self.cgroup_id).await;
        if let Some(runtime_tls) = self._runtime_tls.take() {
            runtime_tls.shutdown().await;
        }
        if let Some(worker) = self.setup_worker.take() {
            match tokio::task::spawn_blocking(move || worker.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "setup helper shutdown failed"),
                Err(error) => warn!(%error, "setup helper join failed"),
            }
        }
        let flows_drained = self.event_client.wait_for_flows(Duration::from_secs(2));
        self.relay_task.abort();
        let _ = self.relay_task.await;
        drop(self.runtime);
        flows_drained
    }
}

impl Drop for SessionRuntime {
    fn drop(&mut self) {
        // Why: a session is the lifetime boundary. Explicit cancellation keeps
        // the foreground owner from leaving a detached DNS task behind after
        // listeners are dropped.
        self.dns_task.abort();
    }
}

impl RelayRuntime {
    async fn bind() -> Result<Self> {
        // Why: all four listeners must be live before eBPF can redirect a
        // packet. Keeping them under one owner makes that readiness barrier
        // explicit and gives a foreground run session one value to drop.
        let tcp_v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind IPv4 relay loopback")?;
        let port = tcp_v4.local_addr()?.port();
        let tcp_v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port))
            .await
            .context("bind IPv6 relay loopback")?;
        let udp_v4 = Arc::new(UdpRelaySocket::bind(port)?);
        let udp_v6 = Arc::new(
            UdpSocket::bind((Ipv6Addr::LOCALHOST, port))
                .await
                .context("bind IPv6 UDP relay loopback")?,
        );

        Ok(Self {
            tcp_v4,
            tcp_v6,
            udp_v4,
            udp_v6,
            port,
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn serve(
        &self,
        port_map: PortMap,
        udp_port_map: UdpPortMap,
        udp_token_map: UdpTokenMap,
        udp_cookie_map: UdpCookieMap,
        udp_sessions: UdpSessions,
        shared: Arc<Shared>,
    ) -> Result<()> {
        let mut udp_buf = vec![0u8; 65_535];
        let mut udp6_buf = vec![0u8; 65_535];
        let udp4_context = UdpRelayContext {
            relay: UdpResponseRelay::Token(self.udp_v4.clone()),
            ports: udp_port_map.clone(),
            tokens: udp_token_map.clone(),
            cookies: udp_cookie_map.clone(),
            sessions: udp_sessions.clone(),
            shared: shared.clone(),
        };
        let udp6_context = UdpRelayContext {
            relay: UdpResponseRelay::Ipv6(self.udp_v6.clone()),
            ports: udp_port_map,
            tokens: udp_token_map,
            cookies: udp_cookie_map,
            sessions: udp_sessions,
            shared: shared.clone(),
        };

        loop {
            tokio::select! {
                accepted = self.tcp_v4.accept() => {
                    let (stream, peer) = accepted?;
                    spawn_tcp_relay(stream, peer, port_map.clone(), shared.clone());
                }
                accepted = self.tcp_v6.accept() => {
                    let (stream, peer) = accepted?;
                    spawn_tcp_relay(stream, peer, port_map.clone(), shared.clone());
                }
                received = self.udp_v4.recv(&mut udp_buf) => {
                    let (len, peer, token) = received?;
                    spawn_udp_relay(
                        udp_buf[..len].to_vec(),
                        peer,
                        UdpCorrelation::Token(token),
                        udp4_context.clone(),
                    );
                }
                received = self.udp_v6.recv_from(&mut udp6_buf) => {
                    let (len, peer) = received?;
                    spawn_udp_relay(
                        udp6_buf[..len].to_vec(),
                        peer,
                        UdpCorrelation::Port(relay_key_for_peer(peer)),
                        udp6_context.clone(),
                    );
                }
            }
        }
    }
}

impl UdpRelaySocket {
    fn bind(port: u16) -> Result<Self> {
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )
        .context("create UDP relay socket")?;
        setsockopt(&fd, sockopt::ReuseAddr, &true).context("set UDP relay SO_REUSEADDR")?;
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).context("enable UDP relay IP_PKTINFO")?;
        // Why: token destinations span 127/8, so one wildcard bind is needed
        // to receive every address. SO_BINDTODEVICE keeps that wildcard from
        // exposing the privileged relay on non-loopback interfaces.
        setsockopt(&fd, sockopt::BindToDevice, &OsString::from("lo"))
            .context("bind UDP relay to loopback device")?;
        bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        )
        .context("bind UDP relay on IPv4 loopback range")?;
        Ok(Self {
            fd: AsyncFd::new(fd).context("register UDP relay with async runtime")?,
        })
    }

    async fn recv(&self, payload: &mut [u8]) -> Result<(usize, SocketAddr, u32)> {
        loop {
            let mut ready = self
                .fd
                .readable()
                .await
                .context("wait for UDP relay datagram")?;
            let result = ready.try_io(|inner| {
                let mut iov = [IoSliceMut::new(payload)];
                let mut control = nix::cmsg_space!(libc::in_pktinfo);
                let message = recvmsg::<SockaddrStorage>(
                    inner.as_raw_fd(),
                    &mut iov,
                    Some(&mut control),
                    MsgFlags::MSG_DONTWAIT,
                )
                .map_err(nix_io_error)?;
                let peer = message
                    .address
                    .and_then(|address| address.as_sockaddr_in().copied())
                    .map(std::net::SocketAddrV4::from)
                    .map(SocketAddr::V4)
                    .ok_or_else(|| std::io::Error::other("UDP relay peer is not IPv4"))?;
                let token = message
                    .cmsgs()
                    .map_err(nix_io_error)?
                    .find_map(|item| match item {
                        ControlMessageOwned::Ipv4PacketInfo(info) => {
                            token_from_relay_ip(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()))
                        }
                        _ => None,
                    })
                    .ok_or_else(|| std::io::Error::other("UDP relay datagram has no token"))?;
                Ok((message.bytes, peer, token))
            });
            match result {
                Ok(value) => return value.context("receive UDP relay datagram"),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, payload: &[u8], peer: SocketAddr, token: u32) -> Result<()> {
        let SocketAddr::V4(peer) = peer else {
            anyhow::bail!("UDP relay response peer is not IPv4");
        };
        let source = relay_ip_from_token(token);
        let packet_info = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes(source.octets()),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let address = SockaddrIn::from(peer);
        loop {
            let mut ready = self
                .fd
                .writable()
                .await
                .context("wait for UDP relay writable")?;
            let result = ready.try_io(|inner| {
                sendmsg(
                    inner.as_raw_fd(),
                    &[IoSlice::new(payload)],
                    &[ControlMessage::Ipv4PacketInfo(&packet_info)],
                    MsgFlags::MSG_DONTWAIT,
                    Some(&address),
                )
                .map_err(nix_io_error)
            });
            match result {
                Ok(sent) => {
                    let sent = sent.context("send UDP relay response")?;
                    anyhow::ensure!(sent == payload.len(), "short UDP relay response");
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

fn nix_io_error(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

fn relay_ip_from_token(token: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        127,
        ((token >> 16) & 0xff) as u8,
        ((token >> 8) & 0xff) as u8,
        (token & 0xff) as u8,
    )
}

fn token_from_relay_ip(ip: Ipv4Addr) -> Option<u32> {
    let octets = ip.octets();
    (octets[0] == 127).then_some(
        (u32::from(octets[1]) << 16) | (u32::from(octets[2]) << 8) | u32::from(octets[3]),
    )
}

// ---------------------------------------------------------------------------
// CLI — top level
// ---------------------------------------------------------------------------

/// Run commands through a SOCKS5 proxy without modifying the command.
///
/// Help has one entry point — `heimdall help [subcommand…] [-v]`:
///
///   `heimdall help`              concise top-level (same as `--help`)
///   `heimdall help -v`           verbose: every subcommand + option in one read
///   `heimdall help run`          concise help for the run command
///
/// `--help` / `-h` remain available everywhere (standard clap output).
#[derive(Parser, Debug)]
#[command(name = "heimdall", version, about, long_about = None,
          arg_required_else_help = true,
          // Replace clap's auto-generated `help` subcommand with our
          // own variant (Cmd::Help) so we can add the `-v` toggle.
          disable_help_subcommand = true,
          after_help = "Tip: `heimdall help -v` prints every subcommand and \
                        option in one shot.")]
struct Cli {
    /// Config path (.toml, .yaml/.yml, or .json). By default,
    /// discover exactly one /etc/heimdall/config.<format> file.
    #[arg(long, env = "HEIMDALL_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Emit a stable, side-effect-free JSON preflight for AI agents.
    /// Includes config validity, the resolved run decision, error codes,
    /// capabilities, and shell-safe argv arrays.
    Agent(cli::agent::AgentArgs),

    /// Internal privileged half of one foreground run.
    #[command(name = "__setup-worker", hide = true)]
    SetupWorker,

    /// Validate, explain a policy decision, show source, or print its path.
    #[command(subcommand)]
    Config(cli::config::ConfigCmd),

    /// Generate and inspect TLS trust material used by relay decryption.
    #[command(subcommand)]
    Tls(cli::tls::TlsCmd),

    /// Inspect, follow, rotate, verify, recover, or prune per-run event logs.
    #[command(subcommand)]
    Logs(cli::logs::LogsCmd),

    /// Write a minimal starter config in the selected format.
    Init(cli::init::InitArgs),

    /// Wrap a CLI command so its egress goes through a heimdall
    /// selected policy (proxychains-style). Non-root: re-execs itself
    /// under `systemd-run --user --scope` to land in a writable
    /// cgroup. The policy defaults to `proxy.default_policy`.
    Run(cli::run::RunArgs),

    /// Print help. By default, concise per-command help (same as
    /// `--help` on the resolved subcommand). With `-v`, recurse into
    /// every subcommand beneath it and dump options too — useful for
    /// AI agents discovering the full CLI surface in one read.
    ///
    ///     heimdall help              # concise top-level
    ///     heimdall help -v           # full tree, every option inlined
    ///     heimdall help run          # concise run help
    Help {
        /// Recurse through descendants and print every option.
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Subcommand path to scope the help to (e.g. `config validate`).
        #[arg(num_args = 0..)]
        path: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct Shared {
    cfg: HeimdallConfig,
    upstreams: StdHashMap<String, Arc<Upstream>>,
    capture: Option<capture::CaptureManager>,
    relay_tls: Option<Arc<tls_relay::RelayTls>>,
    /// Fake-IP DNS resolver. None when DNS server failed to bind
    /// (relay degrades to plain IP-mode SOCKS5 in that case).
    dns: Option<Arc<DnsResolver>>,
    /// `heimdall run` registers a (cgroup_id → Decision) entry here
    /// before exec'ing the wrapped command. Relay checks this map
    /// on every redirected connection. Empty when no wrapped command is
    /// running and cleared when the matching CLI exits.
    ///
    cli_overrides: CliOverrides,
    event_clients: EventClients,
}

pub(crate) async fn close_udp_sessions_for_cgroup(sessions: &UdpSessions, cgroup_id: u64) {
    sessions
        .lock()
        .await
        .retain(|_, handle| handle.cgroup_id != cgroup_id);
}

/// Shared (cgroup_id → Decision) override map for `heimdall run`
/// CLI processes. See `Shared.cli_overrides` for semantics.
pub type CliOverrides = Arc<parking_lot::RwLock<StdHashMap<u64, crate::heimdall_config::Decision>>>;
pub type EventClients = Arc<parking_lot::RwLock<StdHashMap<u64, crate::event_log::EventClient>>>;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Commands stay quiet unless RUST_LOG overrides; stdout belongs to their
    // machine contract or wrapped process.
    let default_level = "heimdall=warn";
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(default_level.parse()?),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.cmd.unwrap() {
        Cmd::Help { path, verbose } => {
            // Validate the path against the known subcommand tree so
            // `heimdall help bogus` errors clearly instead of silently
            // printing the root help.
            let strs: Vec<&str> = path.iter().map(String::as_str).collect();
            if let Err(err) = validate_help_path(&strs) {
                eprintln!("error: {err}");
                eprintln!("\nUsage: heimdall help [<subcommand> ...] [-v]");
                eprintln!("Try `heimdall --help` for the list of subcommands.");
                std::process::exit(2);
            }
            print_help_at(&strs, verbose);
            Ok(())
        }
        Cmd::Agent(args) => {
            let ready = cli::agent::run(cli.config.as_deref(), args).await?;
            if !ready {
                std::process::exit(1);
            }
            Ok(())
        }
        Cmd::SetupWorker => setup_worker_entry(),
        Cmd::Config(sub) => {
            let config_path = if sub.reads_config() {
                resolve_config_path(cli.config.as_deref())?
            } else {
                cli.config.unwrap_or_else(|| {
                    PathBuf::from(crate::heimdall_config::DEFAULT_DIR).join("config.toml")
                })
            };
            cli::config::run(&config_path, sub)
        }
        Cmd::Tls(sub) => cli::tls::run(sub),
        Cmd::Logs(sub) => cli::logs::run(sub),
        Cmd::Init(args) => cli::init::run(args),
        Cmd::Run(args) => {
            let config_path = resolve_config_path(cli.config.as_deref())?;
            cli::run::run(&config_path, args).await
        }
    }
}

/// Resolve `--config` / `HEIMDALL_CONFIG`, otherwise discover one config.
fn resolve_config_path(explicit: Option<&std::path::Path>) -> Result<PathBuf> {
    explicit.map(PathBuf::from).map_or_else(
        || {
            crate::heimdall_config::discover_config_path(crate::heimdall_config::DEFAULT_DIR)
                .map_err(Into::into)
        },
        Ok,
    )
}

/// Walk the clap command tree and confirm every name in `path` resolves
/// to a real subcommand. Returns a human-readable error pointing at the
/// first unknown segment if not.
fn validate_help_path(path: &[&str]) -> Result<(), String> {
    use clap::CommandFactory;
    // Important: build() propagates globals such as `--config`
    // into every subcommand. Without it, walking the tree manually
    // misses the global args that clap injects at runtime.
    let mut root = Cli::command().clone();
    root.build();
    let mut node: &mut clap::Command = &mut root;
    for (i, name) in path.iter().enumerate() {
        match node.find_subcommand_mut(*name) {
            Some(next) => node = next,
            None => {
                let prefix = if i == 0 {
                    "heimdall".to_string()
                } else {
                    format!("heimdall {}", path[..i].join(" "))
                };
                return Err(format!("`{name}` is not a subcommand of `{prefix}`"));
            }
        }
    }
    Ok(())
}

/// Print help for the resolved subcommand. With `verbose=false`,
/// behaves like `<sub> --help` (clap's standard long-help). With
/// `verbose=true`, recurse: dump this node's long-help plus every
/// descendant's, with separators. Empty path = root.
fn print_help_at(path: &[&str], verbose: bool) {
    use clap::CommandFactory;
    let mut root = Cli::command();
    // Propagate globals (`--config`) into every subcommand so
    // Nested help lists global flags just like direct subcommand help.
    root.build();
    let mut node: &mut clap::Command = &mut root;
    for name in path {
        node = node
            .find_subcommand_mut(*name)
            .expect("validate_help_path ran first");
    }
    if verbose {
        let prefix: Vec<&str> = if path.is_empty() {
            vec![]
        } else {
            path[..path.len() - 1].to_vec()
        };
        print_command_recursive(node, &prefix);
    } else {
        let _ = node.print_long_help();
        println!();
    }
}

fn print_command_recursive(cmd: &mut clap::Command, path: &[&str]) {
    let title = if path.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{} {}", path.join(" "), cmd.get_name())
    };
    println!();
    println!("==============================================================");
    println!(" {title}");
    println!("==============================================================");
    let _ = cmd.print_long_help();
    println!();

    // Recurse into subcommands. Skip the auto-generated `help` to keep
    // the output noise-free.
    let names: Vec<String> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .map(|s| s.get_name().to_string())
        .collect();
    let mut new_path: Vec<&str> = path.to_vec();
    if !path.iter().any(|s| *s == cmd.get_name()) || path.is_empty() {
        new_path.push(cmd.get_name());
    }
    let owned_path: Vec<String> = new_path.iter().map(|s| s.to_string()).collect();
    for name in names {
        if let Some(sub) = cmd.find_subcommand_mut(&name) {
            let path_refs: Vec<&str> = owned_path.iter().map(|s| s.as_str()).collect();
            print_command_recursive(sub, &path_refs);
        }
    }
}

struct CgroupAttachTarget<'a> {
    path: &'a str,
    file: &'a std::fs::File,
    required: bool,
}

fn attach_cgroup_programs(
    bpf: &mut Ebpf,
    transaction: &mut ebpf::LinkTransaction,
    targets: &[CgroupAttachTarget<'_>],
) -> Result<()> {
    for name in [
        "connect4",
        "connect6",
        "getpeername4",
        "getpeername6",
        "udp4_sendmsg",
        "udp6_sendmsg",
        "udp6_bind",
        "udp4_recvmsg",
        "udp6_recvmsg",
    ] {
        let program: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .with_context(|| format!("{name} eBPF program not found"))?
            .try_into()?;
        program
            .load()
            .with_context(|| format!("failed to load {name}"))?;
        for target in targets {
            match program.attach(target.file, CgroupAttachMode::Single) {
                Ok(link_id) => {
                    let link: FdLink = program.take_link(link_id)?.try_into()?;
                    transaction.install_link(link);
                }
                Err(error) if !target.required => {
                    warn!(%error, cgroup = target.path, prog = name, "optional eBPF cgroup attach failed");
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("attach {name} to required cgroup {}", target.path)
                    });
                }
            }
            info!(
                cgroup = target.path,
                prog = name,
                "eBPF cgroup program attached"
            );
        }
    }

    let name = "sock_release";
    let program: &mut CgroupSock = bpf
        .program_mut(name)
        .context("sock_release eBPF program not found")?
        .try_into()?;
    program.load().context("failed to load sock_release")?;
    for target in targets {
        match program.attach(target.file, CgroupAttachMode::Single) {
            Ok(link_id) => {
                let link: FdLink = program.take_link(link_id)?.try_into()?;
                transaction.install_link(link);
            }
            Err(error) if !target.required => {
                warn!(%error, cgroup = target.path, prog = name, "optional eBPF cgroup attach failed");
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("attach {name} to required cgroup {}", target.path));
            }
        }
        info!(
            cgroup = target.path,
            prog = name,
            "eBPF cgroup program attached"
        );
    }

    let name = "skb_egress";
    let program: &mut CgroupSkb = bpf
        .program_mut(name)
        .context("skb_egress eBPF program not found")?
        .try_into()?;
    program.load().context("failed to load skb_egress")?;
    for target in targets {
        match program.attach(
            target.file,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::Single,
        ) {
            Ok(link_id) => {
                let link: FdLink = program.take_link(link_id)?.try_into()?;
                transaction.install_link(link);
            }
            Err(error) if !target.required => {
                warn!(%error, cgroup = target.path, prog = name, "optional eBPF cgroup attach failed");
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("attach {name} to required cgroup {}", target.path));
            }
        }
        info!(
            cgroup = target.path,
            prog = name,
            "eBPF cgroup program attached"
        );
    }

    Ok(())
}

fn load_kernel_object() -> Result<Ebpf> {
    EbpfLoader::new()
        .load(EBPF_BYTES)
        .context("load eBPF object with process-owned maps")
}

fn configure_kernel_maps(bpf: &mut Ebpf, relay_port: u16, dns_port: u16) -> Result<()> {
    let relay_ip_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let mut relay_map: Array<&mut aya::maps::MapData, u32> =
        Array::try_from(bpf.map_mut("RELAY_ADDR").context("RELAY_ADDR not found")?)?;
    relay_map
        .set(0, relay_ip_be, 0)
        .context("failed to set relay IP in BPF map")?;

    let mut relay6_map: Array<&mut aya::maps::MapData, [u8; 16]> = Array::try_from(
        bpf.map_mut("RELAY_ADDR6")
            .context("RELAY_ADDR6 not found")?,
    )?;
    relay6_map
        .set(0, Ipv6Addr::LOCALHOST.octets(), 0)
        .context("failed to set relay IPv6 in BPF map")?;

    let mut relay_port_map: Array<&mut aya::maps::MapData, u32> = Array::try_from(
        bpf.map_mut("RELAY_PORT_MAP")
            .context("RELAY_PORT_MAP not found")?,
    )?;
    relay_port_map
        .set(0, u32::from(relay_port.to_be()), 0)
        .context("failed to set relay port in BPF map")?;

    let dns_v4_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let dns_port_be = dns_port.to_be() as u32;
    let mut dns_map: Array<&mut aya::maps::MapData, u32> = Array::try_from(
        bpf.map_mut("DNS_ADDR_V4")
            .context("DNS_ADDR_V4 not found")?,
    )?;
    dns_map.set(0, dns_v4_be, 0).context("DNS_ADDR_V4 set ip")?;
    dns_map
        .set(1, dns_port_be, 0)
        .context("DNS_ADDR_V4 set port")?;

    let mut dns6_map: Array<&mut aya::maps::MapData, [u8; 16]> = Array::try_from(
        bpf.map_mut("DNS_ADDR_V6")
            .context("DNS_ADDR_V6 not found")?,
    )?;
    dns6_map
        .set(0, Ipv6Addr::LOCALHOST.octets(), 0)
        .context("DNS_ADDR_V6 set addr")?;
    let mut dns6_port_map: Array<&mut aya::maps::MapData, u32> = Array::try_from(
        bpf.map_mut("DNS_PORT_V6")
            .context("DNS_PORT_V6 not found")?,
    )?;
    dns6_port_map
        .set(0, dns_port_be, 0)
        .context("DNS_PORT_V6 set")?;

    info!(
        relay_ip = %Ipv4Addr::LOCALHOST,
        relay_ip6 = %Ipv6Addr::LOCALHOST,
        relay_port,
        dns_port,
        "kernel relay and DNS targets configured"
    );
    Ok(())
}

fn setup_worker_entry() -> Result<()> {
    let socket_fd = rustix::io::dup(std::io::stdin()).context("duplicate setup socket stdin")?;
    let mut socket = std::os::unix::net::UnixStream::from(socket_fd);
    if let Err(error) = setup_worker_run(&mut socket) {
        let _ = setup::send_error(&mut socket, "setup_failed", &error.to_string());
        return Err(error);
    }
    Ok(())
}

fn setup_worker_run(socket: &mut std::os::unix::net::UnixStream) -> Result<()> {
    anyhow::ensure!(
        rustix::process::geteuid().is_root(),
        "setup worker must run as root"
    );
    let peer = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::PeerCredentials)
        .context("read setup socket peer credentials")?;
    if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
        let sudo_uid = sudo_uid.parse::<u32>().context("parse SUDO_UID")?;
        anyhow::ensure!(
            peer.uid() == sudo_uid,
            "setup socket peer does not match the sudo caller"
        );
    }

    let request = setup::receive_request(socket)?;
    let canonical =
        std::fs::canonicalize(request.cgroup_path()).context("canonicalize setup cgroup path")?;
    anyhow::ensure!(
        canonical == request.cgroup_path(),
        "setup cgroup path must already be canonical"
    );
    anyhow::ensure!(
        canonical != std::path::Path::new("/sys/fs/cgroup"),
        "setup worker cannot attach to the cgroup root"
    );
    if peer.uid() != 0 {
        let user_root = PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{}.slice",
            peer.uid()
        ));
        anyhow::ensure!(
            canonical.starts_with(&user_root),
            "setup cgroup is outside the caller's user slice"
        );
    }
    let cgroup = std::fs::File::open(&canonical).context("open setup cgroup")?;
    anyhow::ensure!(
        cgroup.metadata()?.ino() == request.cgroup_id(),
        "setup cgroup ID does not match its inode"
    );

    let mut bpf = load_kernel_object()?;
    configure_kernel_maps(&mut bpf, request.relay_port(), request.dns_port())?;
    let mut policy_map: HashMap<aya::maps::MapData, u64, u8> = HashMap::try_from(
        bpf.take_map("CGROUP_POLICY")
            .context("CGROUP_POLICY not found")?,
    )?;
    policy_map
        .insert(request.cgroup_id(), request.policy_flags(), 0)
        .context("write foreground cgroup policy")?;

    let mut transaction = ebpf::LinkTransaction::new();
    attach_cgroup_programs(
        &mut bpf,
        &mut transaction,
        &[CgroupAttachTarget {
            path: canonical
                .to_str()
                .context("setup cgroup path is not UTF-8")?,
            file: &cgroup,
            required: true,
        }],
    )?;
    let links = transaction.commit();
    let link_fds = links.duplicate_fds()?;
    anyhow::ensure!(
        link_fds.len() == setup::FD_MANIFEST.len() - 4,
        "setup worker attached an unexpected number of links"
    );

    let runtime_tls = request
        .runtime_tls()
        .then(|| {
            let runtime = tls_runtime::prepare_setup(&mut bpf)
                .context("prepare daemonless runtime TLS probes")?;
            anyhow::ensure!(
                runtime.report.attached_images > 0,
                "runtime TLS found no attachable OpenSSL images in active mappings or system loader directories; install a supported OpenSSL shared library in a standard loader path, or use decrypt.mode = relay"
            );
            Ok::<_, anyhow::Error>(runtime)
        })
        .transpose()?;
    let runtime_link_fds = runtime_tls
        .as_ref()
        .map(|runtime| {
            runtime
                .links
                .iter()
                .map(ebpf::duplicate_link_fd)
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    let maps = [
        take_setup_hash_map(&mut bpf, "PORT_MAP")?,
        take_setup_hash_map(&mut bpf, "UDP_PORT_MAP")?,
        take_setup_hash_map(&mut bpf, "UDP_TOKEN_MAP")?,
        take_setup_hash_map(&mut bpf, "UDP_COOKIE_MAP")?,
    ];
    let mut manifest = setup::FD_MANIFEST.to_vec();
    let mut transferred: Vec<_> = maps
        .iter()
        .map(|map| map.fd().as_fd())
        .chain(link_fds.iter().map(AsFd::as_fd))
        .collect();
    if let Some(runtime) = runtime_tls.as_ref() {
        manifest.extend(std::iter::repeat_n(
            setup::SetupFd::RuntimeTlsLink,
            runtime_link_fds.len(),
        ));
        transferred.extend(runtime_link_fds.iter().map(AsFd::as_fd));
        manifest.extend(std::iter::repeat_n(
            setup::SetupFd::RuntimePerfBuffer,
            runtime.buffers.len(),
        ));
        transferred.extend(runtime.buffers.iter().map(AsFd::as_fd));
    }
    setup::send_ready(
        socket,
        manifest,
        runtime_tls.as_ref().map(|runtime| runtime.report.clone()),
        &transferred,
    )?;
    drop_setup_worker_privileges(peer.uid(), peer.gid())?;
    let mut marker = [0_u8; 1];
    let mut graceful = false;
    while socket
        .read(&mut marker)
        .context("wait for setup helper shutdown")?
        != 0
    {
        graceful |= marker == *b"G";
    }
    if !graceful {
        kill_abandoned_cgroup(&canonical)?;
    }
    Ok(())
}

fn kill_abandoned_cgroup(cgroup: &std::path::Path) -> Result<()> {
    // Why: if the foreground owner is SIGKILLed, its eBPF FDs close before
    // the workload does. Kill the delegated command cgroup on unmarked EOF so
    // surviving descendants cannot silently continue with direct egress.
    std::fs::write(cgroup.join("cgroup.kill"), b"1")
        .context("kill command cgroup after foreground owner exit")?;
    for _ in 0..500 {
        let events = std::fs::read_to_string(cgroup.join("cgroup.events"))
            .context("read abandoned command cgroup state")?;
        if events.lines().any(|line| line == "populated 0") {
            std::fs::remove_dir(cgroup).context("remove abandoned command cgroup")?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    anyhow::bail!("abandoned command cgroup remained populated after cgroup.kill")
}

#[allow(
    unsafe_code,
    reason = "the privileged setup process must irrevocably become its socket peer before waiting"
)]
fn drop_setup_worker_privileges(uid: u32, gid: u32) -> Result<()> {
    if uid == 0 {
        return Ok(());
    }
    let result = unsafe { libc::setgroups(0, std::ptr::null()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("clear setup helper groups");
    }
    let result = unsafe { libc::setresgid(gid, gid, gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("drop setup helper group privileges");
    }
    let result = unsafe { libc::setresuid(uid, uid, uid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("drop setup helper user privileges");
    }
    Ok(())
}

fn take_setup_hash_map(bpf: &mut Ebpf, name: &str) -> Result<aya::maps::MapData> {
    match bpf
        .take_map(name)
        .with_context(|| format!("{name} not found"))?
    {
        aya::maps::Map::HashMap(map) | aya::maps::Map::LruHashMap(map) => Ok(map),
        _ => anyhow::bail!("{name} has an unexpected map type"),
    }
}

fn spawn_tcp_relay(stream: TcpStream, peer: SocketAddr, map: PortMap, shared: Arc<Shared>) {
    tokio::spawn(async move {
        let key = relay_key_for_peer(peer);
        debug!(key, %peer, "accepted redirected connection");
        if let Err(e) = relay(stream, key, map, shared).await {
            warn!(key, "relay error: {e:#}");
        }
    });
}

fn spawn_udp_relay(
    payload: Vec<u8>,
    peer: SocketAddr,
    correlation: UdpCorrelation,
    context: UdpRelayContext,
) {
    tokio::spawn(async move {
        if let Err(e) = dispatch_udp(payload, peer, correlation, context).await {
            warn!("UDP relay error: {e:#}");
        }
    });
}

// ---------------------------------------------------------------------------
// Per-connection relay: registered CLI cgroup → upstream
// ---------------------------------------------------------------------------

fn relay_key_for_peer(peer: SocketAddr) -> u32 {
    let family = if peer.is_ipv4() { FAMILY_V4 } else { FAMILY_V6 };
    relay_key(family, peer.port())
}

fn destination_from_orig(orig: &OrigDst, shared: &Shared) -> Dst {
    match orig.family {
        FAMILY_V6 => {
            let ip = Ipv6Addr::from(orig.addr);
            shared
                .dns
                .as_ref()
                .and_then(|dns| dns.lookup6(&ip))
                .map_or(Dst::Ip6(ip), Dst::Domain)
        }
        _ => {
            let raw = u32::from_ne_bytes([orig.addr[0], orig.addr[1], orig.addr[2], orig.addr[3]]);
            let ip = Ipv4Addr::from(u32::from_be(raw));
            shared
                .dns
                .as_ref()
                .and_then(|dns| dns.lookup_be(raw))
                .map_or(Dst::Ip4(ip), Dst::Domain)
        }
    }
}

fn emit_policy_decision(
    shared: &Shared,
    owner: (u64, &str),
    network: &'static str,
    destination: &Dst,
    port: u16,
    rule: Option<&crate::heimdall_config::RouteRule>,
    action: &Action,
) -> Result<()> {
    let (cgroup_id, policy) = owner;
    let Some(events) = shared.event_clients.read().get(&cgroup_id).cloned() else {
        return Ok(());
    };
    let destination = match destination {
        Dst::Domain(host) => serde_json::json!({"host": host, "port": port}),
        Dst::Ip4(ip) => serde_json::json!({"ip": ip, "port": port}),
        Dst::Ip6(ip) => serde_json::json!({"ip": ip, "port": port}),
    };
    let rule = rule.map_or_else(
        || serde_json::json!({"name": null, "source": "final"}),
        |rule| serde_json::json!({"name": rule.name, "source": "ordered_rule"}),
    );
    events.emit_run(
        "policy.decision",
        serde_json::json!({
            "source": {"cgroup_id": cgroup_id},
            "policy": policy,
            "network": network,
            "destination": destination,
            "rule": rule,
            "action": serde_json::to_value(action).context("encode policy action")?
        }),
    )
}

async fn relay(mut client: TcpStream, key: u32, map: PortMap, shared: Arc<Shared>) -> Result<()> {
    // Pop the original destination (and cgroup_id) from the BPF map.
    let orig = {
        let m = map.read().await;
        m.get(&key, 0)
            .with_context(|| format!("BPF map miss for relay key {key:#010x}"))?
    };
    map.write().await.remove(&key).ok();

    let dst_port = u16::from_be(orig.port);

    let dst = destination_from_orig(&orig, &shared);

    // ─── Resolve decision → connection name directly ─────────────────────
    // `heimdall run` registers a per-cgroup override here before exec.
    // A redirected connection must belong to a registered `heimdall run`
    // cgroup. Map misses normally bypass in eBPF; reaching this branch means
    // registration raced with teardown, so fail this connection.
    let decision = if let Some(ovr) = shared.cli_overrides.read().get(&orig.cgroup_id).cloned() {
        ovr
    } else {
        anyhow::bail!("redirected cgroup {} is not registered", orig.cgroup_id)
    };
    let policy = shared
        .cfg
        .policy(&decision.policy)
        .with_context(|| format!("policy `{}` not in registry", decision.policy))?;

    let unit_label = format!("cgroup:{}", orig.cgroup_id);

    let dst_label = match &dst {
        Dst::Ip4(ip) => ip.to_string(),
        Dst::Ip6(ip) => ip.to_string(),
        Dst::Domain(domain) => domain.clone(),
    };

    let ip = match &dst {
        Dst::Ip4(ip) => Some(std::net::IpAddr::V4(*ip)),
        Dst::Ip6(ip) => Some(std::net::IpAddr::V6(*ip)),
        Dst::Domain(_) => None,
    };
    let domain = match &dst {
        Dst::Domain(domain) => Some(domain.as_str()),
        Dst::Ip4(_) | Dst::Ip6(_) => None,
    };
    let (rule, action) = policy.explain_tcp(domain, ip, dst_port);
    emit_policy_decision(
        &shared,
        (orig.cgroup_id, &decision.policy),
        "tcp",
        &dst,
        dst_port,
        rule,
        action,
    )?;

    // ─── Execute the selected terminal action ─────────────────────────────
    let result: Result<(u64, u64)> = async {
        match action {
            Action::Route { outbound } => {
                let upstream = shared
                    .upstreams
                    .get(outbound)
                    .with_context(|| format!("resolved outbound `{outbound}` not in registry"))?;
                let Upstream::Socks5 {
                    addr,
                    auth,
                    connect_timeout,
                } = upstream.as_ref();
                let mut up = open_socks5_tunnel_with_timeouts(
                    addr,
                    &dst,
                    dst_port,
                    auth.as_ref(),
                    *connect_timeout,
                    SOCKS5_HANDSHAKE_TIMEOUT,
                )
                    .await
                    .with_context(|| format!("SOCKS5 CONNECT {dst_label}:{dst_port} via {addr}"))?;
                info!(
                    unit = %unit_label,
                    policy = %decision.policy,
                    outbound = %outbound,
                    dst = %dst_label,
                    dst_port,
                    via = %addr,
                    "tunnel established"
                );
                let action = format!("route:{outbound}");
                let (u, d) = copy_tcp_transport(
                    &mut client,
                    &mut up,
                    &shared,
                    capture::FlowMeta {
                        flow_id: uuid::Uuid::now_v7(),
                        boundary: "transport",
                        network: "tcp",
                        cgroup_id: orig.cgroup_id,
                        policy: &decision.policy,
                        destination: &dst_label,
                        destination_port: dst_port,
                        action: &action,
                        payload: "opaque_transport",
                    },
                )
                .await?;
                Ok((u, d))
            }
            Action::Direct => {
                let mut direct = TcpStream::connect((dst_label.as_str(), dst_port))
                    .await
                    .with_context(|| format!("direct CONNECT {dst_label}:{dst_port}"))?;
                info!(unit = %unit_label, policy = %decision.policy, dst = %dst_label, dst_port, "direct connection established");
                let (u, d) = copy_tcp_transport(
                    &mut client,
                    &mut direct,
                    &shared,
                    capture::FlowMeta {
                        flow_id: uuid::Uuid::now_v7(),
                        boundary: "transport",
                        network: "tcp",
                        cgroup_id: orig.cgroup_id,
                        policy: &decision.policy,
                        destination: &dst_label,
                        destination_port: dst_port,
                        action: "direct",
                        payload: "opaque_transport",
                    },
                )
                .await?;
                Ok((u, d))
            }
            Action::Reject { method } => anyhow::bail!(
                "policy `{}` rejected {dst_label}:{dst_port} with {method:?}",
                decision.policy
            ),
        }
    }
    .await;

    result.map(|_| ())
}

async fn copy_tcp_transport(
    client: &mut TcpStream,
    remote: &mut TcpStream,
    shared: &Shared,
    mut meta: capture::FlowMeta<'_>,
) -> Result<(u64, u64)> {
    let relay_tls = if let Some(relay_tls) = &shared.relay_tls
        && tls_relay::looks_like_client_hello(client).await?
    {
        Some(relay_tls)
    } else {
        None
    };
    if relay_tls.is_some() {
        meta.payload = "tls_plaintext";
        meta.boundary = "tls_plaintext.relay";
    }

    // Start tracking while the registration map is read-locked. Deregistration
    // removes the map entry under the write lock, then waits for every guard
    // created here to emit its closing event before the run writer exits.
    let event_client = shared
        .event_clients
        .read()
        .get(&meta.cgroup_id)
        .map(event_log::EventClient::start_flow);
    let flow_id = meta.flow_id;
    let flow_started = std::time::Instant::now();
    if let Some(events) = &event_client {
        let destination = meta.destination.parse::<std::net::IpAddr>().map_or_else(
            |_| serde_json::json!({"host": meta.destination, "port": meta.destination_port}),
            |ip| serde_json::json!({"ip": ip, "port": meta.destination_port}),
        );
        let action = meta.action.strip_prefix("route:").map_or_else(
            || serde_json::json!({"type": meta.action}),
            |outbound| serde_json::json!({"type": "route", "outbound": outbound}),
        );
        events.emit(
            "flow.open",
            flow_id,
            serde_json::json!({
                "network": "tcp",
                "source": {"cgroup_id": meta.cgroup_id},
                "destination": destination,
                "action": action,
                "policy": meta.policy,
                "boundary": if meta.payload == "tls_plaintext" {
                    "tls_plaintext.relay"
                } else {
                    "transport"
                }
            }),
        )?;
    }

    let mut relay_error_code = None;
    let result = if let Some(relay_tls) = relay_tls {
        let manager = shared
            .capture
            .as_ref()
            .context("strict config enabled relay decrypt without capture")?;
        let fallback_name = meta.destination.to_owned();
        match relay_tls
            .copy(
                client,
                remote,
                &fallback_name,
                manager,
                event_client.as_ref(),
                meta,
            )
            .await
        {
            Ok(report) => {
                if let Some(events) = &event_client {
                    events.emit(
                        "tls.handshake",
                        flow_id,
                        serde_json::json!({
                            "mode": "relay",
                            "version": report.version,
                            "cipher": report.cipher,
                            "alpn": report.alpn,
                            "peer_identity": {
                                "server_name": report.server_name,
                                "verified": true
                            },
                            "trust": {
                                "upstream": "native_roots",
                                "downstream": "heimdall_ca"
                            },
                            "latency_us": report.latency_us
                        }),
                    )?;
                }
                Ok((report.client_to_remote_bytes, report.remote_to_client_bytes))
            }
            Err(error) => {
                relay_error_code = Some(error.code());
                if let Some(events) = &event_client {
                    let _ = events.emit(
                        "tls.error",
                        flow_id,
                        serde_json::json!({
                            "mode": "relay",
                            "code": error.code(),
                            "message": error.to_string(),
                            "phase": error.phase(),
                            "retryable": false,
                            "peer_identity": {
                                "server_name": fallback_name,
                                "verified": error.peer_verified()
                            }
                        }),
                    );
                }
                Err(anyhow::Error::new(error))
            }
        }
    } else {
        match &shared.capture {
            Some(manager) => match manager.open(meta).await {
                Ok(capture) => capture::copy_tcp(client, remote, capture).await,
                Err(error) => Err(error),
            },
            None => copy_bidirectional(client, remote).await.map_err(Into::into),
        }
    };

    if let Some(events) = event_client {
        let (client_to_remote_bytes, remote_to_client_bytes, status, error_code) = match &result {
            Ok((up, down)) => (*up, *down, "complete", None),
            Err(_) => (0, 0, "error", relay_error_code.or(Some("relay_failed"))),
        };
        let close_result = events.emit(
            "flow.close",
            flow_id,
            serde_json::json!({
                "network": "tcp",
                "status": status,
                "error_code": error_code,
                "client_to_remote_bytes": client_to_remote_bytes,
                "remote_to_client_bytes": remote_to_client_bytes,
                "duration_us": u64::try_from(flow_started.elapsed().as_micros())
                    .unwrap_or(u64::MAX)
            }),
        );
        if result.is_ok() {
            close_result?;
        } else if let Err(error) = close_result {
            warn!(%error, %flow_id, "cannot record failed TCP flow close");
        }
    }
    result
}

enum UdpSessionAction {
    Route {
        outbound: String,
        upstream: Arc<Upstream>,
    },
    Direct,
}

struct UdpSessionSpec {
    socket_cookie: u64,
    cgroup_id: u64,
    policy: String,
    dst: Dst,
    dst_port: u16,
    action: UdpSessionAction,
}

async fn dispatch_udp(
    payload: Vec<u8>,
    peer: SocketAddr,
    correlation: UdpCorrelation,
    context: UdpRelayContext,
) -> Result<()> {
    let (orig, token) = match correlation {
        UdpCorrelation::Token(token) => (
            context
                .tokens
                .read()
                .await
                .get(&token, 0)
                .with_context(|| format!("BPF map miss for UDP relay token {token:#08x}"))?,
            Some(token),
        ),
        UdpCorrelation::Port(key) => (
            context
                .ports
                .read()
                .await
                .get(&key, 0)
                .with_context(|| format!("BPF map miss for IPv6 UDP relay key {key:#010x}"))?,
            None,
        ),
    };
    anyhow::ensure!(orig.socket_cookie != 0, "UDP relay has no socket cookie");
    let session_key = token.map_or(
        UdpSessionKey::Cookie(orig.socket_cookie),
        UdpSessionKey::Token,
    );

    let request = UdpRequest { payload };
    let request = {
        let mut active = context.sessions.lock().await;
        if let Some(handle) = active.get(&session_key) {
            match handle.tx.try_send(request) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    anyhow::bail!("UDP session queue is full")
                }
                Err(mpsc::error::TrySendError::Closed(request)) => {
                    active.remove(&session_key);
                    request
                }
            }
        } else {
            request
        }
    };

    let spec = resolve_udp_session(&orig, &context.shared)?;
    let (tx, mut rx) = mpsc::channel(UDP_SESSION_QUEUE);
    tx.try_send(request)
        .map_err(|_| anyhow::anyhow!("new UDP session queue rejected its first datagram"))?;
    let id = NEXT_UDP_SESSION_ID.fetch_add(1, Ordering::Relaxed);

    {
        let mut active = context.sessions.lock().await;
        if let Some(handle) = active.get(&session_key) {
            let request = rx
                .try_recv()
                .map_err(|_| anyhow::anyhow!("new UDP session lost its first datagram"))?;
            handle
                .tx
                .try_send(request)
                .map_err(|error| anyhow::anyhow!("UDP session enqueue failed: {error}"))?;
            return Ok(());
        }
        anyhow::ensure!(
            active.len() < UDP_MAX_SESSIONS,
            "UDP session limit reached ({UDP_MAX_SESSIONS})"
        );
        active.insert(
            session_key,
            UdpSessionHandle {
                id,
                cgroup_id: orig.cgroup_id,
                tx,
            },
        );
    }

    let cleanup_sessions = context.sessions.clone();
    let socket_cookie = orig.socket_cookie;
    tokio::spawn(async move {
        let runtime = UdpSessionRuntime {
            peer,
            token,
            relay: context.relay,
            cookies: context.cookies,
            shared: context.shared,
        };
        if let Err(error) = run_udp_session(spec, rx, runtime).await {
            warn!(socket_cookie, "UDP session error: {error:#}");
        }
        let mut active = cleanup_sessions.lock().await;
        if active
            .get(&session_key)
            .is_some_and(|handle| handle.id == id)
        {
            active.remove(&session_key);
        }
    });
    Ok(())
}

fn resolve_udp_session(orig: &OrigDst, shared: &Shared) -> Result<UdpSessionSpec> {
    let decision = shared
        .cli_overrides
        .read()
        .get(&orig.cgroup_id)
        .cloned()
        .with_context(|| format!("redirected cgroup {} is not registered", orig.cgroup_id))?;
    let policy = shared
        .cfg
        .policy(&decision.policy)
        .with_context(|| format!("policy `{}` not in registry", decision.policy))?;
    let dst = destination_from_orig(orig, shared);
    let dst_port = u16::from_be(orig.port);
    let (domain, ip) = match &dst {
        Dst::Domain(domain) => (Some(domain.as_str()), None),
        Dst::Ip4(ip) => (None, Some(std::net::IpAddr::V4(*ip))),
        Dst::Ip6(ip) => (None, Some(std::net::IpAddr::V6(*ip))),
    };

    let (rule, selected_action) = policy.explain_udp(domain, ip, dst_port);
    emit_policy_decision(
        shared,
        (orig.cgroup_id, &decision.policy),
        "udp",
        &dst,
        dst_port,
        rule,
        selected_action,
    )?;
    let action = match selected_action.clone() {
        Action::Route { outbound } => {
            let upstream = shared
                .upstreams
                .get(&outbound)
                .cloned()
                .with_context(|| format!("resolved outbound `{outbound}` not in registry"))?;
            UdpSessionAction::Route { outbound, upstream }
        }
        Action::Direct => UdpSessionAction::Direct,
        Action::Reject { method } => anyhow::bail!(
            "policy `{}` rejected UDP destination port {dst_port} with {method:?}",
            decision.policy
        ),
    };
    Ok(UdpSessionSpec {
        socket_cookie: orig.socket_cookie,
        cgroup_id: orig.cgroup_id,
        policy: decision.policy,
        dst,
        dst_port,
        action,
    })
}

async fn run_udp_session(
    spec: UdpSessionSpec,
    rx: mpsc::Receiver<UdpRequest>,
    runtime: UdpSessionRuntime,
) -> Result<()> {
    match &spec.action {
        UdpSessionAction::Route { outbound, upstream } => {
            let (control, socket) = open_socks5_udp_association(upstream).await?;
            info!(
                socket_cookie = spec.socket_cookie,
                cgroup_id = spec.cgroup_id,
                policy = %spec.policy,
                outbound = %outbound,
                dst_port = spec.dst_port,
                "SOCKS5 UDP session established"
            );
            let action = format!("route:{outbound}");
            let capture = open_udp_capture(&spec, &runtime.shared, &action).await?;
            let result =
                run_socks5_udp_session(&spec, &runtime, rx, control, socket, capture.as_ref())
                    .await;
            close_udp_capture(capture, &result).await?;
            result
        }
        UdpSessionAction::Direct => {
            let target = destination_socket_addr(&spec.dst, spec.dst_port).await?;
            let bind = if target.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let socket = UdpSocket::bind(bind)
                .await
                .context("bind direct UDP socket")?;
            socket
                .connect(target)
                .await
                .context("connect direct UDP socket")?;
            info!(
                socket_cookie = spec.socket_cookie,
                cgroup_id = spec.cgroup_id,
                policy = %spec.policy,
                dst = %target,
                "direct UDP session established"
            );
            let capture = open_udp_capture(&spec, &runtime.shared, "direct").await?;
            let result =
                run_direct_udp_session(&spec, &runtime, rx, socket, capture.as_ref()).await;
            close_udp_capture(capture, &result).await?;
            result
        }
    }
}

async fn open_udp_capture(
    spec: &UdpSessionSpec,
    shared: &Shared,
    action: &str,
) -> Result<Option<UdpObservation>> {
    let event_client = shared
        .event_clients
        .read()
        .get(&spec.cgroup_id)
        .map(event_log::EventClient::start_flow);
    if shared.capture.is_none() && event_client.is_none() {
        return Ok(None);
    }
    let destination = match &spec.dst {
        Dst::Ip4(ip) => ip.to_string(),
        Dst::Ip6(ip) => ip.to_string(),
        Dst::Domain(domain) => domain.clone(),
    };
    let flow_id = uuid::Uuid::now_v7();
    let payload_capture = if let Some(manager) = &shared.capture {
        Some(
            manager
                .open(capture::FlowMeta {
                    flow_id,
                    boundary: "transport",
                    network: "udp",
                    cgroup_id: spec.cgroup_id,
                    policy: &spec.policy,
                    destination: &destination,
                    destination_port: spec.dst_port,
                    action,
                    payload: "opaque_transport",
                })
                .await?,
        )
    } else {
        None
    };
    if let Some(events) = &event_client {
        let destination = destination.parse::<std::net::IpAddr>().map_or_else(
            |_| serde_json::json!({"host": destination, "port": spec.dst_port}),
            |ip| serde_json::json!({"ip": ip, "port": spec.dst_port}),
        );
        let action = action.strip_prefix("route:").map_or_else(
            || serde_json::json!({"type": action}),
            |outbound| serde_json::json!({"type": "route", "outbound": outbound}),
        );
        events.emit(
            "flow.open",
            flow_id,
            serde_json::json!({
                "network": "udp",
                "source": {"cgroup_id": spec.cgroup_id},
                "destination": destination,
                "action": action,
                "policy": spec.policy,
                "boundary": "transport"
            }),
        )?;
    }
    Ok(Some(UdpObservation {
        payload_capture,
        events: event_client,
        flow_id,
        started: std::time::Instant::now(),
        client_to_remote_bytes: AtomicU64::new(0),
        remote_to_client_bytes: AtomicU64::new(0),
    }))
}

struct UdpObservation {
    payload_capture: Option<capture::CaptureFlow>,
    events: Option<event_log::FlowEventClient>,
    flow_id: uuid::Uuid,
    started: std::time::Instant,
    client_to_remote_bytes: AtomicU64,
    remote_to_client_bytes: AtomicU64,
}

impl UdpObservation {
    async fn data(&self, direction: capture::Direction, payload: &[u8]) -> Result<()> {
        match direction {
            capture::Direction::ClientToRemote => &self.client_to_remote_bytes,
            capture::Direction::RemoteToClient => &self.remote_to_client_bytes,
        }
        .fetch_add(payload.len() as u64, Ordering::Relaxed);
        if let Some(payload_capture) = &self.payload_capture {
            payload_capture.data(direction, payload).await?;
        }
        Ok(())
    }

    async fn close(self, result: &Result<()>) -> Result<()> {
        let capture_result = if let Some(payload_capture) = self.payload_capture {
            payload_capture
                .close(if result.is_ok() { "complete" } else { "error" })
                .await
        } else {
            Ok(())
        };
        let event_result = if let Some(events) = self.events {
            events.emit(
                "flow.close",
                self.flow_id,
                serde_json::json!({
                    "network": "udp",
                    "status": if result.is_ok() { "complete" } else { "error" },
                    "error_code": if result.is_ok() { None } else { Some("relay_failed") },
                    "client_to_remote_bytes": self.client_to_remote_bytes.load(Ordering::Relaxed),
                    "remote_to_client_bytes": self.remote_to_client_bytes.load(Ordering::Relaxed),
                    "duration_us": u64::try_from(self.started.elapsed().as_micros())
                        .unwrap_or(u64::MAX)
                }),
            )
        } else {
            Ok(())
        };
        capture_result?;
        event_result
    }
}

async fn close_udp_capture(capture: Option<UdpObservation>, result: &Result<()>) -> Result<()> {
    if let Some(capture) = capture {
        capture.close(result).await?;
    }
    Ok(())
}

async fn udp_session_active(
    spec: &UdpSessionSpec,
    cookies: &UdpCookieMap,
    shared: &Shared,
) -> bool {
    let registered = shared
        .cli_overrides
        .read()
        .get(&spec.cgroup_id)
        .is_some_and(|decision| decision.policy == spec.policy);
    if !registered {
        return false;
    }
    cookies.read().await.get(&spec.socket_cookie, 0).is_ok()
}

fn reset_udp_idle(idle: &mut std::pin::Pin<&mut tokio::time::Sleep>) {
    idle.as_mut()
        .reset(tokio::time::Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
}

async fn run_direct_udp_session(
    spec: &UdpSessionSpec,
    runtime: &UdpSessionRuntime,
    mut rx: mpsc::Receiver<UdpRequest>,
    socket: UdpSocket,
    capture: Option<&UdpObservation>,
) -> Result<()> {
    let idle = tokio::time::sleep(UDP_SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut liveness = tokio::time::interval(UDP_SESSION_LIVENESS_INTERVAL);
    liveness.tick().await;
    let mut response = vec![0u8; 65_535];

    loop {
        tokio::select! {
            request = rx.recv() => {
                let Some(request) = request else { return Ok(()) };
                if !udp_session_active(spec, &runtime.cookies, &runtime.shared).await {
                    return Ok(());
                }
                if let Some(capture) = capture {
                    capture.data(capture::Direction::ClientToRemote, &request.payload).await?;
                }
                socket.send(&request.payload).await.context("send direct UDP payload")?;
                reset_udp_idle(&mut idle);
            }
            received = socket.recv(&mut response) => {
                let len = received.context("receive direct UDP response")?;
                if !udp_session_active(spec, &runtime.cookies, &runtime.shared).await {
                    return Ok(());
                }
                if let Some(capture) = capture {
                    capture.data(capture::Direction::RemoteToClient, &response[..len]).await?;
                }
                runtime.relay.send(&response[..len], runtime.peer, runtime.token).await
                    .with_context(|| format!("return direct UDP response to {}", runtime.peer))?;
                reset_udp_idle(&mut idle);
            }
            _ = liveness.tick() => {
                if !udp_session_active(spec, &runtime.cookies, &runtime.shared).await {
                    return Ok(());
                }
            }
            () = &mut idle => return Ok(()),
        }
    }
}

async fn run_socks5_udp_session(
    spec: &UdpSessionSpec,
    runtime: &UdpSessionRuntime,
    mut rx: mpsc::Receiver<UdpRequest>,
    mut control: TcpStream,
    socket: UdpSocket,
    capture: Option<&UdpObservation>,
) -> Result<()> {
    let idle = tokio::time::sleep(UDP_SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut liveness = tokio::time::interval(UDP_SESSION_LIVENESS_INTERVAL);
    liveness.tick().await;
    let mut response = vec![0u8; 65_535];
    let mut control_byte = [0u8; 1];

    loop {
        tokio::select! {
            request = rx.recv() => {
                let Some(request) = request else { return Ok(()) };
                if !udp_session_active(spec, &runtime.cookies, &runtime.shared).await {
                    return Ok(());
                }
                if let Some(capture) = capture {
                    capture.data(capture::Direction::ClientToRemote, &request.payload).await?;
                }
                let frame = encode_socks5_udp_frame(&spec.dst, spec.dst_port, &request.payload)?;
                socket.send(&frame).await.context("send SOCKS5 UDP frame")?;
                reset_udp_idle(&mut idle);
            }
            received = socket.recv(&mut response) => {
                let len = received.context("receive SOCKS5 UDP response")?;
                let payload = decode_socks5_udp_payload(&response[..len])?;
                if !udp_session_active(spec, &runtime.cookies, &runtime.shared).await {
                    return Ok(());
                }
                if let Some(capture) = capture {
                    capture.data(capture::Direction::RemoteToClient, payload).await?;
                }
                runtime.relay.send(payload, runtime.peer, runtime.token).await
                    .with_context(|| format!("return SOCKS5 UDP response to {}", runtime.peer))?;
                reset_udp_idle(&mut idle);
            }
            control_read = control.read(&mut control_byte) => {
                match control_read {
                    Ok(0) => anyhow::bail!("SOCKS5 UDP control connection closed"),
                    Ok(_) => anyhow::bail!("SOCKS5 UDP control connection sent unexpected data"),
                    Err(error) => return Err(error).context("read SOCKS5 UDP control connection"),
                }
            }
            _ = liveness.tick() => {
                if !udp_session_active(spec, &runtime.cookies, &runtime.shared).await {
                    return Ok(());
                }
            }
            () = &mut idle => return Ok(()),
        }
    }
}

#[cfg(test)]
mod relay_correlation_tests {
    use super::*;

    #[test]
    fn relay_peer_key_separates_ipv4_and_ipv6() {
        let v4: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let v6: SocketAddr = "[::1]:40000".parse().unwrap();
        assert_ne!(relay_key_for_peer(v4), relay_key_for_peer(v6));
        assert_eq!(relay_key_for_peer(v4), relay_key(FAMILY_V4, 40_000));
        assert_eq!(relay_key_for_peer(v6), relay_key(FAMILY_V6, 40_000));
    }

    #[test]
    fn udp_session_keys_separate_tokens_from_socket_cookies() {
        assert_ne!(UdpSessionKey::Token(7), UdpSessionKey::Cookie(7));
    }

    #[test]
    fn udp_token_loopback_address_round_trips() {
        for token in [1, 0x12_3456, 0xff_ffff] {
            let address = relay_ip_from_token(token);
            assert!(address.is_loopback());
            assert_eq!(token_from_relay_ip(address), Some(token));
        }
    }
}
