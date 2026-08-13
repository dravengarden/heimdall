//! heimdall — transparent SOCKS5 egress proxy driven by eBPF.
//!
//! A small privileged daemon redirects only cgroups registered by
//! `heimdall run`; every other process bypasses it.
//!
//! ## How it works
//!
//!   process connect(external_ip:port)
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
//!     2. cgroup_id → proxy name from the active CLI registration
//!     3. SOCKS5 CONNECT orig_ip:orig_port via that proxy
//!
//! ## Configuration
//!
//! Driven by one `/etc/heimdall/config.{toml,yaml,json,ncl}` file.

mod api;
mod cli;
mod dns;
mod gc;
mod policy;
mod sni;

use std::{
    collections::HashMap as StdHashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::{Array, HashMap},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr},
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

// eBPF object compiled from heimdall-ebpf, embedded at build time.
//
// The wrapper ensures 8-byte alignment, which the ELF parser requires when
// parsing 64-bit ELF from a static byte slice.
#[repr(C, align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

static EBPF_OBJ: AlignedBytes<
    { include_bytes!("../../heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf").len() },
> = AlignedBytes(*include_bytes!(
    "../../heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf"
));

const EBPF_BYTES: &[u8] = &EBPF_OBJ.0;

type PortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;

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
    /// Config path (.toml, .yaml/.yml, .json, or .ncl). By default,
    /// discover exactly one /etc/heimdall/config.<format> file.
    #[arg(long, env = "HEIMDALL_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Emit a stable, side-effect-free JSON preflight for AI agents.
    /// Includes config validity, daemon reachability, the resolved run
    /// decision, error codes, and shell-safe argv arrays.
    Agent(cli::agent::AgentArgs),

    /// Run the small privileged eBPF relay (normally managed by systemd).
    Daemon(DaemonArgs),

    /// Inspect the resolved config: validate, show its content, or
    /// print the auto-discovered path.
    #[command(subcommand)]
    Config(cli::config::ConfigCmd),

    /// Show the selected config and local daemon health.
    Status(StatusArgs),

    /// Write a minimal starter config in the selected format.
    Init(cli::init::InitArgs),

    /// Wrap a CLI command so its egress goes through a heimdall
    /// proxy (proxychains-style). Non-root: re-execs itself
    /// under `systemd-run --user --scope` to land in a writable
    /// cgroup. Defaults come from the config's `run` section.
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

#[derive(clap::Args, Debug, Default)]
struct DaemonArgs {}

#[derive(clap::Args, Debug, Default)]
pub struct StatusArgs {
    /// Emit a single JSON object instead of the labeled-text view.
    /// Drops the "(daemon down)" warnings and uses null fields when
    /// the daemon HTTP API is unreachable. For the complete machine
    /// contract, prefer `heimdall agent`.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Resolved upstream — produced from a Connection at startup
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Upstream {
    Socks5 {
        addr: String,
        auth: Option<ResolvedAuth>,
    },
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
                Ok(Upstream::Socks5 {
                    addr: addr.clone(),
                    auth: resolved,
                })
            }
        }
    }
}

fn resolve_auth(a: &Socks5Auth) -> Result<ResolvedAuth> {
    let password = a
        .read_password()
        .with_context(|| format!("read password file {}", a.password_file.display()))?;
    Ok(ResolvedAuth {
        username: a.username.clone(),
        password,
    })
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
    /// Fake-IP DNS resolver. None when DNS server failed to bind
    /// (relay degrades to plain IP-mode SOCKS5 in that case).
    dns: Option<Arc<DnsResolver>>,
    /// `heimdall run` registers a (cgroup_id → Decision) entry here
    /// before exec'ing the wrapped command. Relay checks this map
    /// on every redirected connection. Empty when no wrapped command is
    /// running and cleared when the matching CLI exits.
    ///
    /// Shared by Arc::clone with `api::AppState.cli_overrides` so the
    /// HTTP register endpoints write here in lockstep with the
    /// PolicyEngine BPF map update.
    cli_overrides: CliOverrides,
}

/// Shared (cgroup_id → Decision) override map for `heimdall run`
/// CLI processes. See `Shared.cli_overrides` for semantics.
pub type CliOverrides = Arc<parking_lot::RwLock<StdHashMap<u64, heimdall_config::Decision>>>;

/// Late-bound policy engine slot. Constructed after eBPF attach
/// succeeds; the HTTP API holds an Arc clone of this slot so register
/// endpoints can call `engine.write_one()` once it's populated.
type PolicyEngineSlot = Arc<parking_lot::Mutex<Option<Arc<policy::PolicyEngine>>>>;

/// SOCKS5 destination — IPv4 literal (ATYP=0x01), IPv6 literal
/// (ATYP=0x04), or hostname recovered via fake-IP lookup (ATYP=0x03,
/// RFC 1928).
#[derive(Debug, Clone)]
enum Dst {
    Ip4(Ipv4Addr),
    Ip6(std::net::Ipv6Addr),
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
    let default_level = match cli.cmd.as_ref() {
        Some(Cmd::Daemon(_)) => "heimdall=info",
        _ => "heimdall=warn",
    };
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
        Cmd::Daemon(args) => {
            let config_path = resolve_config_path(cli.config.as_deref())?;
            daemon_run(&config_path, args).await
        }
        Cmd::Config(sub) => {
            let config_path = resolve_config_path(cli.config.as_deref())?;
            cli::config::run(&config_path, sub).await
        }
        Cmd::Status(args) => {
            let config_path = resolve_config_path(cli.config.as_deref())?;
            cli::status::run(&config_path, args).await
        }
        Cmd::Init(args) => cli::init::run(args),
        Cmd::Run(args) => {
            let config_path = resolve_config_path(cli.config.as_deref())?;
            cli::run::run(&config_path, args)
        }
    }
}

/// Resolve `--config` / `HEIMDALL_CONFIG`, otherwise discover one config.
fn resolve_config_path(explicit: Option<&std::path::Path>) -> Result<PathBuf> {
    explicit.map(PathBuf::from).map_or_else(
        || heimdall_config::discover_config_path(heimdall_config::DEFAULT_DIR).map_err(Into::into),
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

async fn daemon_run(config_path: &PathBuf, args: DaemonArgs) -> Result<()> {
    // ─── Load config ──────────────────────────────────────────────────────
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    info!(
        path = %config_path.display(),
        connections = cfg.connections.len(),
        "config loaded"
    );

    let upstreams = resolve_all(&cfg)?;
    info!(connections = upstreams.len(), "all connections resolved");

    let _ = &args;

    // ─── Fake-IP DNS server ──────────────────────────────────────────────
    let dns = match DnsResolver::new(&cfg.runtime.fake_ip_cidr, &cfg.runtime.fake_ip6_cidr) {
        Ok(r) => {
            let r = Arc::new(r);
            let listen: SocketAddr =
                cfg.runtime.dns_listen.parse().with_context(|| {
                    format!("parse runtime.dnsListen `{}`", cfg.runtime.dns_listen)
                })?;
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

    // Shared between Shared{} (relay reads), AppState (HTTP register
    // endpoints write), and the `heimdall run` flow. Initialised here
    // so AppState gets a clone before it's spawned. See type aliases
    // above for semantics.
    let cli_overrides: CliOverrides = Arc::new(parking_lot::RwLock::new(StdHashMap::new()));
    let policy_engine_slot: PolicyEngineSlot = Arc::new(parking_lot::Mutex::new(None));
    let api_listen: SocketAddr = cfg
        .runtime
        .api_listen
        .parse()
        .with_context(|| format!("parse daemon.apiListen `{}`", cfg.runtime.api_listen))?;
    let app_state = api::AppState {
        connections: cfg.connections.clone(),
        cli_overrides: cli_overrides.clone(),
        policy_engine: policy_engine_slot.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = api::serve(app_state, api_listen).await {
            warn!(error = %e, "control API exited");
        }
    });

    let shared = Arc::new(Shared {
        cfg,
        upstreams,
        dns,
        cli_overrides: cli_overrides.clone(),
    });

    // ─── Load eBPF object and attach programs ─────────────────────────────
    let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF object")?;

    {
        let relay_ip_be = u32::from(shared.cfg.runtime.relay_ip).to_be();
        let mut relay_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(bpf.map_mut("RELAY_ADDR").context("RELAY_ADDR not found")?)?;
        relay_map
            .set(0, relay_ip_be, 0)
            .context("failed to set relay IP in BPF map")?;
        info!(relay_ip = %shared.cfg.runtime.relay_ip, "relay IP written to BPF map");
    }

    // RELAY_ADDR6: 16-byte IPv6 relay address for connect6 to redirect to.
    // Written even when relay_ip6 is the default `::1` so the program has
    // *something* — connect6 reads slot 0 and bails if missing.
    {
        let relay6_bytes = shared.cfg.runtime.relay_ip6.octets();
        let mut relay6_map: Array<&mut aya::maps::MapData, [u8; 16]> = Array::try_from(
            bpf.map_mut("RELAY_ADDR6")
                .context("RELAY_ADDR6 not found")?,
        )?;
        relay6_map
            .set(0, relay6_bytes, 0)
            .context("failed to set relay IPv6 in BPF map")?;
        info!(relay_ip6 = %shared.cfg.runtime.relay_ip6, "relay IPv6 written to BPF map");
    }

    // DNS_ADDR_V4 / DNS_ADDR_V6 / DNS_PORT_V6: where eBPF should
    // redirect :53 traffic for cgroups marked POLICY_DNS_HIJACK
    // (typically `heimdall run` invocations with dns=fake). The
    // daemon's own DNS server listens on `runtime.dnsListen`; we
    // resolve that to a loopback address + port so v4 hijack lands
    // on 127.0.0.1:5358 and v6 hijack lands on ::1:5358 by default.
    {
        let dns_listen = &shared.cfg.runtime.dns_listen;
        let dns_port: u16 = dns_listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5358);

        // v4 — assume the daemon's DNS is reachable at 127.0.0.1:<port>
        // (loopback to itself). For exotic configs where dnsListen is
        // an explicit non-loopback IP, we'd want to use that instead;
        // for now the loopback assumption matches every realistic
        // deployment.
        let dns_v4_be = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
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
            .set(0, std::net::Ipv6Addr::LOCALHOST.octets(), 0)
            .context("DNS_ADDR_V6 set addr")?;
        let mut dns6_port_map: Array<&mut aya::maps::MapData, u32> = Array::try_from(
            bpf.map_mut("DNS_PORT_V6")
                .context("DNS_PORT_V6 not found")?,
        )?;
        dns6_port_map
            .set(0, dns_port_be, 0)
            .context("DNS_PORT_V6 set")?;

        info!(dns_port, "DNS hijack target written to BPF maps (loopback)");
    }

    // Wait for the cgroup to appear — system.slice exists from early
    // boot, but retrying keeps startup robust if the unit races ahead.
    // Previous approach used an ExecStartPre bash script that checked `-d`,
    // but it was racy: the directory could vanish between the shell test and
    // File::open here. Retrying the actual open inside the daemon avoids
    // full restart overhead (config reload, BPF load, BPF map writes) and
    // eliminates the TOCTOU race.
    let cgroup = {
        let cgroup_path = &shared.cfg.runtime.cgroup;
        let mut attempts = 0u32;
        const MAX_WAIT_SECS: u32 = 60;
        loop {
            match std::fs::File::open(cgroup_path) {
                Ok(f) => {
                    if attempts > 0 {
                        info!(path = %cgroup_path, waited_secs = attempts, "cgroup appeared");
                    }
                    break f;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempts < MAX_WAIT_SECS => {
                    if attempts == 0 {
                        info!(path = %cgroup_path, "cgroup not found; waiting");
                    }
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("failed to open cgroup path: {cgroup_path}"));
                }
            }
        }
    };

    // ─── eBPF attach (cgroup_sock_addr connect4 + cgroup_skb egress) ────────
    // Primary attach at runtime.cgroup (defaults to
    // /sys/fs/cgroup/system.slice) covers host services. Secondary at
    // /sys/fs/cgroup/user.slice covers `heimdall run` / interactive
    // user processes.
    //
    // A single root-cgroup attach (/sys/fs/cgroup) would cover both in
    // one shot, but historically appeared to attach yet never fire
    // connect4 in cgroup v2 hierarchical mode. The dual-attach approach
    // is the verified-working path; keep it.
    const USER_SLICE: &str = "/sys/fs/cgroup/user.slice";
    let user_slice_file = std::path::Path::new(USER_SLICE)
        .exists()
        .then(|| std::fs::File::open(USER_SLICE).ok())
        .flatten();
    {
        let connect4: &mut CgroupSockAddr = bpf
            .program_mut("connect4")
            .context("connect4 eBPF program not found")?
            .try_into()?;
        connect4.load().context("failed to load connect4")?;
        connect4
            .attach(&cgroup, CgroupAttachMode::default())
            .context("failed to attach connect4")?;
        info!(cgroup = %shared.cfg.runtime.cgroup, "eBPF connect4 attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match connect4.attach(user_cg, CgroupAttachMode::default()) {
                Ok(_) => info!(cgroup = USER_SLICE, "eBPF connect4 attached (extra)"),
                Err(e) => warn!(error = %e, cgroup = USER_SLICE, "extra connect4 attach failed"),
            }
        }
    }
    {
        let connect6: &mut CgroupSockAddr = bpf
            .program_mut("connect6")
            .context("connect6 eBPF program not found")?
            .try_into()?;
        connect6.load().context("failed to load connect6")?;
        connect6
            .attach(&cgroup, CgroupAttachMode::default())
            .context("failed to attach connect6")?;
        info!(cgroup = %shared.cfg.runtime.cgroup, "eBPF connect6 attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match connect6.attach(user_cg, CgroupAttachMode::default()) {
                Ok(_) => info!(cgroup = USER_SLICE, "eBPF connect6 attached (extra)"),
                Err(e) => warn!(error = %e, cgroup = USER_SLICE, "extra connect6 attach failed"),
            }
        }
    }
    // sock_release: reap COOKIE_MAP entries when the kernel destroys a
    // socket, regardless of whether it ever sent a packet. Without this,
    // sockets that connect() but never egress (glibc src-addr probes,
    // failed routing, abort-before-send) leak cookies forever — past
    // incident filled the map at 65536 in a few hours and silently broke
    // every new redirect on the host. See the matching comment on the
    // sock_release program in heimdall-ebpf for the kernel-hook details.
    {
        let sock_release: &mut CgroupSock = bpf
            .program_mut("sock_release")
            .context("sock_release eBPF program not found")?
            .try_into()?;
        sock_release.load().context("failed to load sock_release")?;
        sock_release
            .attach(&cgroup, CgroupAttachMode::default())
            .context("failed to attach sock_release")?;
        info!(cgroup = %shared.cfg.runtime.cgroup, "eBPF sock_release attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match sock_release.attach(user_cg, CgroupAttachMode::default()) {
                Ok(_) => info!(cgroup = USER_SLICE, "eBPF sock_release attached (extra)"),
                Err(e) => {
                    warn!(error = %e, cgroup = USER_SLICE, "extra sock_release attach failed")
                }
            }
        }
    }
    // udp{4,6}_sendmsg: catch connectionless UDP DNS sends (Go's
    // pure-Go resolver, etc.) — connect4/connect6 don't fire on
    // sendto without a prior connect.
    for name in ["udp4_sendmsg", "udp6_sendmsg"] {
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .with_context(|| format!("{name} eBPF program not found"))?
            .try_into()?;
        prog.load()
            .with_context(|| format!("failed to load {name}"))?;
        prog.attach(&cgroup, CgroupAttachMode::default())
            .with_context(|| format!("failed to attach {name}"))?;
        info!(cgroup = %shared.cfg.runtime.cgroup, prog = name, "eBPF sendmsg attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match prog.attach(user_cg, CgroupAttachMode::default()) {
                Ok(_) => info!(
                    cgroup = USER_SLICE,
                    prog = name,
                    "eBPF sendmsg attached (extra)"
                ),
                Err(e) => {
                    warn!(error = %e, cgroup = USER_SLICE, prog = name, "extra sendmsg attach failed")
                }
            }
        }
    }
    {
        let skb_egress: &mut CgroupSkb = bpf
            .program_mut("skb_egress")
            .context("skb_egress eBPF program not found")?
            .try_into()?;
        skb_egress.load().context("failed to load skb_egress")?;
        skb_egress
            .attach(
                &cgroup,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            )
            .context("failed to attach skb_egress")?;
        info!(cgroup = %shared.cfg.runtime.cgroup, "eBPF skb_egress attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match skb_egress.attach(
                user_cg,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            ) {
                Ok(_) => info!(cgroup = USER_SLICE, "eBPF skb_egress attached (extra)"),
                Err(e) => warn!(error = %e, cgroup = USER_SLICE, "extra skb_egress attach failed"),
            }
        }
    }

    let port_map: PortMap = Arc::new(RwLock::new(HashMap::try_from(
        bpf.take_map("PORT_MAP").context("PORT_MAP not found")?,
    )?));

    // ─── CLI-owned cgroup policy registry ───────────────────────────────
    {
        let policy_map = HashMap::try_from(
            bpf.take_map("CGROUP_POLICY")
                .context("CGROUP_POLICY not found")?,
        )?;
        let engine = std::sync::Arc::new(policy::PolicyEngine::new(policy_map));
        // Hand a clone to the HTTP API so /api/cli/register endpoints
        // can write the policy byte alongside its userspace proxy choice.
        *policy_engine_slot.lock() = Some(engine.clone());
        info!("CLI policy registry started");

        // GC orphan `heimdall run` cgroups: when the wrapping CLI is
        // killed before it can deregister + rmdir, the transient
        // cgroup + BPF policy entry leak. Periodic walker reaps any
        // empty `heimdall-cli-*` cgroups under user.slice.
        gc::spawn(cli_overrides.clone(), policy_engine_slot.clone());
        info!("orphan-cgroup GC spawned (interval 30s)");
    }

    // ─── Relay listener (dual-stack) ──────────────────────────────────────
    // Bind a single listener that accepts both IPv4 and IPv6. Linux
    // doesn't set `IPV6_V6ONLY` by default, so `[::]:N` accepts v4
    // connections via v4-mapped-v6. We cooperate by:
    //   - rewriting an explicit `0.0.0.0:N` into `[::]:N` so existing
    //     configs Just Work
    //   - leaving any explicit IP (v4 or v6) alone for users who want
    //     strict binding
    // This keeps PORT_MAP unambiguous (only one accept loop, one ephemeral
    // port pool), avoids EADDRINUSE between paired listeners, and
    // covers connect6 redirects without an extra socket.
    let listen_for_bind = if shared.cfg.runtime.listen.starts_with("0.0.0.0:") {
        let port = shared
            .cfg
            .runtime
            .listen
            .strip_prefix("0.0.0.0:")
            .unwrap_or("12345");
        format!("[::]:{port}")
    } else {
        shared.cfg.runtime.listen.clone()
    };
    let listener = TcpListener::bind(&listen_for_bind).await.with_context(|| {
        format!(
            "failed to bind relay listener on {} (config: {})",
            listen_for_bind, shared.cfg.runtime.listen
        )
    })?;
    info!(listen = %listen_for_bind, configured = %shared.cfg.runtime.listen, "heimdall ready");

    // ─── systemd notify: READY + WATCHDOG ─────────────────────────────────
    // `READY=1` lets `Type=notify` units depending on heimdall (e.g. a
    // downstream unit, or a deployment script
    // running `systemctl is-active --wait heimdall`) actually wait for
    // the relay to be accepting connections, instead of the Type=simple
    // "ready the moment exec returns" lie. The relay and CLI policy
    // registry are ready at this point. Safe to call when
    // not under systemd — sd-notify returns Ok(()) silently.
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        warn!(error = %e, "sd_notify READY failed");
    }
    // Watchdog heartbeat: WATCHDOG=1 every 1/3 of WatchdogSec so a hung
    // daemon (deadlocked tokio runtime or stalled relay) gets killed
    // + restarted by systemd instead of holding eBPF state hostage.
    // sd-notify exposes the configured period via WATCHDOG_USEC.
    let mut watchdog_usec: u64 = 0;
    if sd_notify::watchdog_enabled(false, &mut watchdog_usec) && watchdog_usec > 0 {
        let beat = std::time::Duration::from_micros(watchdog_usec / 3);
        info!(
            period_secs = beat.as_secs_f32(),
            "systemd watchdog heartbeat starting"
        );
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(beat);
            loop {
                tick.tick().await;
                if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]) {
                    warn!(error = %e, "sd_notify WATCHDOG failed");
                }
            }
        });
    } else {
        debug!("systemd WATCHDOG_USEC unset; no heartbeat");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let map = port_map.clone();
        let shared = shared.clone();

        tokio::spawn(async move {
            let client_port = peer.port() as u32;
            debug!(client_port, %peer, "accepted redirected connection");
            if let Err(e) = relay(stream, client_port, map, shared).await {
                warn!(client_port, "relay error: {e:#}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection relay: registered CLI cgroup → upstream
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

    let dst_port = u16::from_be(orig.port);

    // ─── Dual-stack destination decode + fake-IP reverse lookup ───────────
    // OrigDst.addr is 16 bytes network-byte-order; for v4 the first 4 bytes
    // are the address and the rest are zero. Pick the right family per
    // `orig.family`. If the dst falls in heimdall's fake-IP pool (v4 OR v6)
    // we have a hostname for it and prefer SOCKS5 ATYP=0x03 so the upstream
    // proxy resolves it via its own resolver (which knows internal /
    // VPN-pushed DNS we don't).
    let (dst, dst_ip_display) = match orig.family {
        heimdall_common::FAMILY_V6 => {
            let v6 = std::net::Ipv6Addr::from(orig.addr);
            let from_dns = shared.dns.as_ref().and_then(|d| d.lookup6(&v6));
            let display = v6.to_string();
            match from_dns {
                Some(host) => {
                    debug!(addr = %v6, %host, "fake-IP reverse lookup hit (v6)");
                    (Dst::Domain(host), display)
                }
                None => (Dst::Ip6(v6), display),
            }
        }
        _ => {
            // v4 (default for older OrigDst with family=0).
            let v4_be =
                u32::from_ne_bytes([orig.addr[0], orig.addr[1], orig.addr[2], orig.addr[3]]);
            let v4 = Ipv4Addr::from(u32::from_be(v4_be));
            let from_dns = shared.dns.as_ref().and_then(|d| d.lookup_be(v4_be));
            let display = v4.to_string();
            match from_dns {
                Some(host) => {
                    debug!(addr = %v4, %host, "fake-IP reverse lookup hit (v4)");
                    (Dst::Domain(host), display)
                }
                None => (Dst::Ip4(v4), display),
            }
        }
    };
    // Backward-compat alias used by older log lines below.
    let dst_ip = dst_ip_display;

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
    let conn_name = decision.use_.clone();
    let upstream = shared
        .upstreams
        .get(&conn_name)
        .with_context(|| format!("resolved connection `{conn_name}` not in registry"))?
        .clone();

    let unit_label = format!("cgroup:{}", orig.cgroup_id);

    // ─── SNI fallback for IP-literal destinations ─────────────────────────
    // Clients can land here with `Dst::Ip*` for two distinct reasons:
    //   (a) Genuinely connecting to a public IP literal (e.g. service
    //       mesh, hardcoded `https://1.1.1.1/`).
    //   (b) Connecting to a stale or out-of-pool fake IP — the unit's
    //       application-level DNS cache (Java InetAddress, Python
    //       `dns.resolver`, runtime libs that bypass libc, etc.) holds
    //       an IP that heimdall's fake-IP map no longer recognises.
    //
    // For (b) the IP is unroutable (heimdall's pool sits in the IETF
    // benchmark range 198.18.0.0/15), so forwarding by IP makes the
    // upstream SOCKS5 server time out / reject with 0x04. To honour
    // the "failure shouldn't break the network" principle, we peek
    // the TLS ClientHello: if SNI gives us a hostname, *promote* the
    // destination to `Dst::Domain(host)` so the SOCKS5 CONNECT goes
    // out as ATYP=0x03 (DOMAINNAME). The upstream resolves the name
    // through its own resolver (Mac scoped DNS, AnyConnect, etc.)
    // and the connection lands cleanly.
    //
    // For (a) we still benefit: SOCKS5 ATYP=0x03 is no worse than
    // 0x01 when the IP is routable, and arguably better for upstream
    // observability ("this client wanted google.com, here's the IP
    // they tried"). The `dst_ip` field in the flow record always
    // preserves the original IP literal so a forensic chain stays
    // intact.
    //
    // The peek is non-destructive (`TcpStream::peek`), 150 ms time-
    // bounded, and silent on miss — non-TLS or zero-SNI clients
    // simply fall through to the legacy IP path.
    let sni_host: Option<String> = match &dst {
        Dst::Domain(_) => None, // already have a hostname from fake-IP DNS
        Dst::Ip4(_) | Dst::Ip6(_) => {
            sni::peek_sni(&client, std::time::Duration::from_millis(150)).await
        }
    };
    if let Some(host) = sni_host.as_deref() {
        info!(%host, dst = %dst_ip, "relay: SNI fallback promoted IP-literal connection to hostname");
    }
    let dst = match (dst, sni_host.clone()) {
        (Dst::Ip4(_) | Dst::Ip6(_), Some(host)) => Dst::Domain(host),
        (other, _) => other,
    };

    let dst_label = match &dst {
        Dst::Ip4(ip) => ip.to_string(),
        Dst::Ip6(ip) => ip.to_string(),
        Dst::Domain(domain) => domain.clone(),
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
                    unit = %unit_label,
                    connection = %conn_name,
                    dst = %dst_label,
                    dst_port,
                    via = %addr,
                    "tunnel established"
                );
                let (u, d) = copy_bidirectional(&mut client, &mut up).await?;
                Ok((u, d))
            }
        }
    }
    .await;

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
    anyhow::ensure!(
        sel[0] == 0x05,
        "SOCKS5: bad version in method reply: {sel:?}"
    );

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
        Dst::Ip4(ip) => {
            req.push(0x01); // ATYP=IPv4
            req.extend_from_slice(&ip.octets());
        }
        Dst::Ip6(ip) => {
            req.push(0x04); // ATYP=IPv6
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
    anyhow::ensure!(
        hdr[0] == 0x05,
        "SOCKS5: bad version in CONNECT reply: {hdr:?}"
    );
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
    anyhow::ensure!(
        resp[0] == 0x01,
        "SOCKS5 user/pass: bad sub-version: {resp:?}"
    );
    anyhow::ensure!(
        resp[1] == 0x00,
        "SOCKS5 user/pass: auth failed (status=0x{:02x})",
        resp[1]
    );
    Ok(())
}
