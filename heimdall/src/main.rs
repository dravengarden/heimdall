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
//!       │  Moves COOKIE_MAP[cookie] → PORT_MAP[family, src_port]
//!       │
//!       ▼
//!   heimdall daemon
//!     1. accept() → (family, src_port) → original destination + cgroup
//!     2. cgroup_id → policy name from the active CLI registration
//!     3. evaluate the ordered rules and execute route/direct/reject
//!
//! ## Configuration
//!
//! Driven by one `/etc/heimdall/config.{toml,yaml,json,ncl}` file.

mod api;
mod cli;
mod dns;
mod gc;
mod policy;

use std::{
    collections::HashMap as StdHashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::{Array, HashMap},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr},
};
use clap::Parser;
use heimdall_common::{FAMILY_V4, FAMILY_V6, OrigDst, RELAY_PORT, relay_key};
use heimdall_config::{Action, HeimdallConfig, Outbound, Socks5Auth, Socks5Outbound};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
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
type UdpPortMap = Arc<RwLock<HashMap<aya::maps::MapData, u32, OrigDst>>>;

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

    /// Validate, explain a policy decision, show source, or print its path.
    #[command(subcommand)]
    Config(cli::config::ConfigCmd),

    /// Show the selected config and local daemon health.
    Status(StatusArgs),

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
        connect_timeout: Duration,
    },
}

#[derive(Clone, Debug)]
struct ResolvedAuth {
    username: String,
    password: Vec<u8>,
}

impl Upstream {
    fn from_outbound(outbound: &Outbound) -> Result<Self> {
        match outbound {
            Outbound::Socks5(Socks5Outbound {
                auth,
                connect_timeout,
                ..
            }) => {
                let resolved = auth.as_ref().map(resolve_auth).transpose()?;
                Ok(Upstream::Socks5 {
                    addr: outbound_address(outbound),
                    auth: resolved,
                    connect_timeout: parse_timeout(connect_timeout),
                })
            }
        }
    }
}

fn resolve_auth(a: &Socks5Auth) -> Result<ResolvedAuth> {
    let password = a
        .read_password()
        .with_context(|| format!("read password file {}", a.password_file.display()))?;
    anyhow::ensure!(
        (1..=255).contains(&password.len()),
        "SOCKS5 password must contain 1..=255 bytes after trimming one trailing newline"
    );
    Ok(ResolvedAuth {
        username: a.username.clone(),
        password,
    })
}

/// Pre-resolve every outbound in the config so the relay path doesn't
/// re-read password files per connection.
fn resolve_all(cfg: &HeimdallConfig) -> Result<StdHashMap<String, Arc<Upstream>>> {
    let mut out = StdHashMap::with_capacity(cfg.proxy.outbounds.len());
    for (name, outbound) in &cfg.proxy.outbounds {
        let up = Upstream::from_outbound(outbound)
            .with_context(|| format!("resolving outbound `{name}`"))?;
        out.insert(name.clone(), Arc::new(up));
    }
    Ok(out)
}

fn outbound_address(outbound: &Outbound) -> String {
    match outbound {
        Outbound::Socks5(socks) => socks.address(),
    }
}

fn parse_timeout(value: &str) -> Duration {
    let (raw, multiplier) = value
        .strip_suffix("ms")
        .map(|raw| (raw, 1))
        .or_else(|| value.strip_suffix('s').map(|raw| (raw, 1_000)))
        .or_else(|| value.strip_suffix('m').map(|raw| (raw, 60_000)))
        .expect("strict config validation accepted connect_timeout");
    Duration::from_millis(
        raw.parse::<u64>()
            .expect("strict config validation accepted duration digits")
            * multiplier,
    )
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
    let cfg = HeimdallConfig::load(config_path).map_err(|error| {
        anyhow::anyhow!(
            "invalid config {}\n\n{}",
            config_path.display(),
            error.actionable_message()
        )
    })?;
    info!(
        path = %config_path.display(),
        outbounds = cfg.proxy.outbounds.len(),
        "config loaded"
    );

    let upstreams = resolve_all(&cfg)?;
    info!(outbounds = upstreams.len(), "all outbounds resolved");

    let _ = &args;

    // ─── Fake-IP DNS server ──────────────────────────────────────────────
    let dns = Arc::new(
        DnsResolver::new(&cfg.daemon.fake_ip_cidr, &cfg.daemon.fake_ip6_cidr)
            .context("initialize fake-IP DNS resolver")?,
    );
    let dns_server = dns.clone().bind(cfg.daemon.dns_port).await?;
    tokio::spawn(async move {
        if let Err(e) = dns_server.serve().await {
            warn!(error = %e, "DNS server exited");
        }
    });
    let dns = Some(dns);

    // Shared between Shared{} (relay reads), AppState (HTTP register
    // endpoints write), and the `heimdall run` flow. Initialised here
    // so AppState gets a clone before it's spawned. See type aliases
    // above for semantics.
    let cli_overrides: CliOverrides = Arc::new(parking_lot::RwLock::new(StdHashMap::new()));
    let policy_engine_slot: PolicyEngineSlot = Arc::new(parking_lot::Mutex::new(None));
    let api_listen: SocketAddr = cfg
        .daemon
        .api_listen
        .parse()
        .with_context(|| format!("parse daemon.api_listen `{}`", cfg.daemon.api_listen))?;
    let app_state = api::AppState {
        policies: cfg.proxy.policies.clone(),
        cli_overrides: cli_overrides.clone(),
        policy_engine: policy_engine_slot.clone(),
    };
    let api_listener = TcpListener::bind(api_listen)
        .await
        .with_context(|| format!("bind control API on {api_listen}"))?;
    tokio::spawn(async move {
        if let Err(e) = api::serve(app_state, api_listener).await {
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
        let relay_ip_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
        let mut relay_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(bpf.map_mut("RELAY_ADDR").context("RELAY_ADDR not found")?)?;
        relay_map
            .set(0, relay_ip_be, 0)
            .context("failed to set relay IP in BPF map")?;
        info!(relay_ip = %Ipv4Addr::LOCALHOST, "relay IP written to BPF map");
    }

    // RELAY_ADDR6: 16-byte IPv6 relay address for connect6 to redirect to.
    // Always write IPv6 loopback; connect6 reads slot 0 and bails if missing.
    {
        let relay6_bytes = Ipv6Addr::LOCALHOST.octets();
        let mut relay6_map: Array<&mut aya::maps::MapData, [u8; 16]> = Array::try_from(
            bpf.map_mut("RELAY_ADDR6")
                .context("RELAY_ADDR6 not found")?,
        )?;
        relay6_map
            .set(0, relay6_bytes, 0)
            .context("failed to set relay IPv6 in BPF map")?;
        info!(relay_ip6 = %Ipv6Addr::LOCALHOST, "relay IPv6 written to BPF map");
    }

    // DNS_ADDR_V4 / DNS_ADDR_V6 / DNS_PORT_V6: where eBPF should
    // redirect :53 traffic for cgroups marked POLICY_DNS_HIJACK
    // (typically `heimdall run` invocations with dns=fake). The
    // daemon's DNS server binds both loopback families so v4 hijack lands
    // on 127.0.0.1:5358 and v6 hijack lands on ::1:5358 by default.
    {
        let dns_port = shared.cfg.daemon.dns_port;

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
        let cgroup_path = &shared.cfg.daemon.cgroup;
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
    // Primary attach at daemon.cgroup (defaults to
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
        info!(cgroup = %shared.cfg.daemon.cgroup, "eBPF connect4 attached");
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
        info!(cgroup = %shared.cfg.daemon.cgroup, "eBPF connect6 attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match connect6.attach(user_cg, CgroupAttachMode::default()) {
                Ok(_) => info!(cgroup = USER_SLICE, "eBPF connect6 attached (extra)"),
                Err(e) => warn!(error = %e, cgroup = USER_SLICE, "extra connect6 attach failed"),
            }
        }
    }
    for name in ["getpeername4", "getpeername6"] {
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .with_context(|| format!("{name} eBPF program not found"))?
            .try_into()?;
        prog.load()
            .with_context(|| format!("failed to load {name}"))?;
        prog.attach(&cgroup, CgroupAttachMode::default())
            .with_context(|| format!("failed to attach {name}"))?;
        info!(cgroup = %shared.cfg.daemon.cgroup, prog = name, "eBPF peer identity hook attached");
        if let Some(user_cg) = user_slice_file.as_ref() {
            match prog.attach(user_cg, CgroupAttachMode::default()) {
                Ok(_) => info!(
                    cgroup = USER_SLICE,
                    prog = name,
                    "eBPF peer identity hook attached (extra)"
                ),
                Err(e) => {
                    warn!(error = %e, cgroup = USER_SLICE, prog = name, "extra peer identity hook attach failed")
                }
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
        info!(cgroup = %shared.cfg.daemon.cgroup, "eBPF sock_release attached");
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
    // pure-Go resolver, etc.) and fail closed for non-DNS traffic whose
    // destination cannot be correlated safely. connect4/connect6 own the
    // connected UDP relay path.
    for name in ["udp4_sendmsg", "udp6_sendmsg"] {
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .with_context(|| format!("{name} eBPF program not found"))?
            .try_into()?;
        prog.load()
            .with_context(|| format!("failed to load {name}"))?;
        prog.attach(&cgroup, CgroupAttachMode::default())
            .with_context(|| format!("failed to attach {name}"))?;
        info!(cgroup = %shared.cfg.daemon.cgroup, prog = name, "eBPF sendmsg attached");
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
        info!(cgroup = %shared.cfg.daemon.cgroup, "eBPF skb_egress attached");
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
    let udp_port_map: UdpPortMap = Arc::new(RwLock::new(HashMap::try_from(
        bpf.take_map("UDP_PORT_MAP")
            .context("UDP_PORT_MAP not found")?,
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

    // ─── Relay listeners (IPv4 + IPv6 loopback) ────────────────────────
    // Separate sockets avoid exposing the internal relay and do not depend on
    // the host's IPV6_V6ONLY default.
    let relay_v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, RELAY_PORT))
        .await
        .context("bind IPv4 relay loopback")?;
    let relay_v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, RELAY_PORT))
        .await
        .context("bind IPv6 relay loopback")?;
    let udp_v4 = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, RELAY_PORT))
            .await
            .context("bind IPv4 UDP relay loopback")?,
    );
    let udp_v6 = Arc::new(
        UdpSocket::bind((Ipv6Addr::LOCALHOST, RELAY_PORT))
            .await
            .context("bind IPv6 UDP relay loopback")?,
    );
    info!(ipv4 = %relay_v4.local_addr()?, ipv6 = %relay_v6.local_addr()?, "heimdall ready");

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

    let mut udp4_buf = vec![0u8; 65_535];
    let mut udp6_buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            accepted = relay_v4.accept() => {
                let (stream, peer) = accepted?;
                spawn_tcp_relay(stream, peer, port_map.clone(), shared.clone());
            }
            accepted = relay_v6.accept() => {
                let (stream, peer) = accepted?;
                spawn_tcp_relay(stream, peer, port_map.clone(), shared.clone());
            }
            received = udp_v4.recv_from(&mut udp4_buf) => {
                let (len, peer) = received?;
                spawn_udp_relay(udp4_buf[..len].to_vec(), peer, udp_v4.clone(), udp_port_map.clone(), shared.clone());
            }
            received = udp_v6.recv_from(&mut udp6_buf) => {
                let (len, peer) = received?;
                spawn_udp_relay(udp6_buf[..len].to_vec(), peer, udp_v6.clone(), udp_port_map.clone(), shared.clone());
            }
        }
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
    relay: Arc<UdpSocket>,
    map: UdpPortMap,
    shared: Arc<Shared>,
) {
    tokio::spawn(async move {
        let key = relay_key_for_peer(peer);
        if let Err(e) = relay_udp(payload, peer, relay, key, map, shared).await {
            warn!(key, "UDP relay error: {e:#}");
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
    let action = policy.decide_tcp(domain, ip, dst_port);

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
                let (u, d) = copy_bidirectional(&mut client, &mut up).await?;
                Ok((u, d))
            }
            Action::Direct => {
                let mut direct = TcpStream::connect((dst_label.as_str(), dst_port))
                    .await
                    .with_context(|| format!("direct CONNECT {dst_label}:{dst_port}"))?;
                info!(unit = %unit_label, policy = %decision.policy, dst = %dst_label, dst_port, "direct connection established");
                let (u, d) = copy_bidirectional(&mut client, &mut direct).await?;
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

async fn relay_udp(
    payload: Vec<u8>,
    peer: SocketAddr,
    relay: Arc<UdpSocket>,
    key: u32,
    map: UdpPortMap,
    shared: Arc<Shared>,
) -> Result<()> {
    let orig = map
        .read()
        .await
        .get(&key, 0)
        .with_context(|| format!("BPF map miss for UDP relay key {key:#010x}"))?;
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
    let dst = destination_from_orig(&orig, &shared);
    let dst_port = u16::from_be(orig.port);
    let (domain, ip) = match &dst {
        Dst::Domain(domain) => (Some(domain.as_str()), None),
        Dst::Ip4(ip) => (None, Some(std::net::IpAddr::V4(*ip))),
        Dst::Ip6(ip) => (None, Some(std::net::IpAddr::V6(*ip))),
    };

    let response = match policy.decide_udp(domain, ip, dst_port).clone() {
        Action::Route { outbound } => {
            let upstream = shared
                .upstreams
                .get(&outbound)
                .with_context(|| format!("resolved outbound `{outbound}` not in registry"))?;
            socks5_udp_exchange(upstream, &dst, dst_port, &payload).await?
        }
        Action::Direct => direct_udp_exchange(&dst, dst_port, &payload).await?,
        Action::Reject { method } => anyhow::bail!(
            "policy `{}` rejected UDP destination port {dst_port} with {method:?}",
            decision.policy
        ),
    };
    relay
        .send_to(&response, peer)
        .await
        .with_context(|| format!("return UDP response to {peer}"))?;
    Ok(())
}

async fn direct_udp_exchange(dst: &Dst, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let bind = match dst {
        Dst::Ip6(_) => "[::]:0",
        Dst::Ip4(_) | Dst::Domain(_) => "0.0.0.0:0",
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("bind direct UDP socket")?;
    let target = destination_socket_addr(dst, port).await?;
    socket
        .connect(target)
        .await
        .context("connect direct UDP socket")?;
    socket
        .send(payload)
        .await
        .context("send direct UDP payload")?;
    let mut response = vec![0u8; 65_535];
    let len = tokio::time::timeout(SOCKS5_HANDSHAKE_TIMEOUT, socket.recv(&mut response))
        .await
        .context("timed out waiting for direct UDP response")??;
    response.truncate(len);
    Ok(response)
}

async fn destination_socket_addr(dst: &Dst, port: u16) -> Result<SocketAddr> {
    match dst {
        Dst::Ip4(ip) => Ok(SocketAddr::new((*ip).into(), port)),
        Dst::Ip6(ip) => Ok(SocketAddr::new((*ip).into(), port)),
        Dst::Domain(domain) => tokio::net::lookup_host((domain.as_str(), port))
            .await
            .with_context(|| format!("resolve UDP destination {domain}:{port}"))?
            .next()
            .with_context(|| format!("no address for UDP destination {domain}:{port}")),
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake (RFC 1928 + RFC 1929 user/pass)
// ---------------------------------------------------------------------------

const M_NO_AUTH: u8 = 0x00;
const M_USER_PASS: u8 = 0x02;
const M_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn socks5_udp_exchange(
    upstream: &Upstream,
    dst: &Dst,
    port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let Upstream::Socks5 {
        addr,
        auth,
        connect_timeout,
    } = upstream;
    let mut control = tokio::time::timeout(*connect_timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to SOCKS5 {addr}"))?
        .with_context(|| format!("connect to SOCKS5 {addr}"))?;
    let relay_addr = tokio::time::timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        socks5_udp_associate(&mut control, auth.as_ref()),
    )
    .await
    .with_context(|| format!("timed out negotiating SOCKS5 UDP with {addr}"))??;
    let relay_addr = if relay_addr.ip().is_unspecified() {
        SocketAddr::new(control.peer_addr()?.ip(), relay_addr.port())
    } else {
        relay_addr
    };
    let bind = if relay_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("bind SOCKS5 UDP socket")?;
    socket
        .connect(relay_addr)
        .await
        .with_context(|| format!("connect SOCKS5 UDP relay {relay_addr}"))?;
    let mut frame = Vec::with_capacity(payload.len() + 262);
    frame.extend_from_slice(&[0, 0, 0]);
    encode_socks5_destination(&mut frame, dst, port)?;
    frame.extend_from_slice(payload);
    socket.send(&frame).await.context("send SOCKS5 UDP frame")?;
    let mut response = vec![0u8; 65_535];
    let len = tokio::time::timeout(SOCKS5_HANDSHAKE_TIMEOUT, socket.recv(&mut response))
        .await
        .context("timed out waiting for SOCKS5 UDP response")??;
    response.truncate(len);
    decode_socks5_udp_payload(&response).map(ToOwned::to_owned)
}

async fn socks5_udp_associate(
    stream: &mut TcpStream,
    auth: Option<&ResolvedAuth>,
) -> Result<SocketAddr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    socks5_negotiate(stream, auth).await?;
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    anyhow::ensure!(header[0] == 5, "SOCKS5: bad UDP ASSOCIATE version");
    anyhow::ensure!(
        header[1] == 0,
        "SOCKS5 UDP ASSOCIATE rejected: code=0x{:02x}",
        header[1]
    );
    anyhow::ensure!(header[2] == 0, "SOCKS5: non-zero reserved reply byte");
    read_socks5_socket_addr(stream, header[3]).await
}

async fn socks5_negotiate(stream: &mut TcpStream, auth: Option<&ResolvedAuth>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let methods: &[u8] = if auth.is_some() {
        &[M_USER_PASS]
    } else {
        &[M_NO_AUTH]
    };
    stream.write_all(&[5, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await?;
    anyhow::ensure!(selected[0] == 5, "SOCKS5: bad method reply version");
    match (selected[1], auth) {
        (M_NO_AUTH, None) => Ok(()),
        (M_USER_PASS, Some(auth)) => socks5_userpass(stream, &auth.username, &auth.password).await,
        (M_NO_ACCEPTABLE, _) => anyhow::bail!("SOCKS5: server rejected all offered methods"),
        (method, _) => anyhow::bail!(
            "SOCKS5: server selected method 0x{method:02x} that the client did not offer"
        ),
    }
}

async fn read_socks5_socket_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
    use tokio::io::AsyncReadExt;

    let ip = match atyp {
        1 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            std::net::IpAddr::V4(Ipv4Addr::from(raw))
        }
        4 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            std::net::IpAddr::V6(Ipv6Addr::from(raw))
        }
        3 => anyhow::bail!("SOCKS5 UDP relay replies must use an IP address"),
        other => anyhow::bail!("SOCKS5: unknown reply ATYP 0x{other:02x}"),
    };
    let mut raw_port = [0u8; 2];
    stream.read_exact(&mut raw_port).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(raw_port)))
}

fn encode_socks5_destination(output: &mut Vec<u8>, dst: &Dst, port: u16) -> Result<()> {
    match dst {
        Dst::Ip4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Dst::Ip6(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        Dst::Domain(host) => {
            anyhow::ensure!(
                (1..=255).contains(&host.len()),
                "SOCKS5: invalid domain length"
            );
            anyhow::ensure!(valid_socks5_domain(host), "SOCKS5: invalid domain name");
            output.push(3);
            output.push(host.len() as u8);
            output.extend_from_slice(host.as_bytes());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn decode_socks5_udp_payload(frame: &[u8]) -> Result<&[u8]> {
    anyhow::ensure!(frame.len() >= 4, "SOCKS5 UDP response is truncated");
    anyhow::ensure!(
        frame[0..2] == [0, 0],
        "SOCKS5 UDP response has non-zero RSV"
    );
    anyhow::ensure!(
        frame[2] == 0,
        "fragmented SOCKS5 UDP responses are unsupported"
    );
    let address_len = match frame[3] {
        1 => 4,
        4 => 16,
        3 => {
            anyhow::ensure!(frame.len() >= 5, "SOCKS5 UDP domain response is truncated");
            1 + frame[4] as usize
        }
        other => anyhow::bail!("SOCKS5 UDP response has unknown ATYP 0x{other:02x}"),
    };
    let payload_offset = 4 + address_len + 2;
    anyhow::ensure!(
        frame.len() >= payload_offset,
        "SOCKS5 UDP response is truncated"
    );
    Ok(&frame[payload_offset..])
}

async fn open_socks5_tunnel_with_timeouts(
    addr: &str,
    dst: &Dst,
    port: u16,
    auth: Option<&ResolvedAuth>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<TcpStream> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to SOCKS5 {addr}"))?
        .with_context(|| format!("connect to SOCKS5 {addr}"))?;
    tokio::time::timeout(
        handshake_timeout,
        socks5_connect(&mut stream, dst, port, auth),
    )
    .await
    .with_context(|| format!("timed out negotiating SOCKS5 with {addr}"))??;
    Ok(stream)
}

async fn socks5_connect(
    s: &mut TcpStream,
    dst: &Dst,
    port: u16,
    auth: Option<&ResolvedAuth>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ─── Method negotiation (RFC 1928 §3) ────────────────────────────────
    let methods: &[u8] = if auth.is_some() {
        &[M_USER_PASS]
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

    match (sel[1], auth) {
        (M_NO_AUTH, None) => {}
        (M_USER_PASS, Some(auth)) => {
            socks5_userpass(s, &auth.username, &auth.password).await?;
        }
        (M_NO_AUTH, Some(_)) | (M_USER_PASS, None) => {
            anyhow::bail!(
                "SOCKS5: server selected method 0x{:02x} that the client did not offer",
                sel[1]
            )
        }
        (M_NO_ACCEPTABLE, _) => anyhow::bail!("SOCKS5: server rejected all offered methods"),
        (other, _) => anyhow::bail!("SOCKS5: unsupported method 0x{other:02x}"),
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
                !host.is_empty() && host.len() <= 255,
                "SOCKS5: domain name must contain 1..=255 bytes (got {})",
                host.len()
            );
            anyhow::ensure!(
                valid_socks5_domain(host),
                "SOCKS5: domain name must be an ASCII hostname with 1..=63-byte labels"
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
    anyhow::ensure!(hdr[2] == 0x00, "SOCKS5: non-zero reserved reply byte");
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

fn valid_socks5_domain(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.is_ascii()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

async fn socks5_userpass(s: &mut TcpStream, user: &str, pass: &[u8]) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    anyhow::ensure!(
        (1..=255).contains(&user.len()),
        "SOCKS5 user/pass: username must contain 1..=255 bytes"
    );
    anyhow::ensure!(
        (1..=255).contains(&pass.len()),
        "SOCKS5 user/pass: password must contain 1..=255 bytes"
    );

    let mut req = Vec::with_capacity(3 + user.len() + pass.len());
    req.push(0x01);
    req.push(user.len() as u8);
    req.extend_from_slice(user.as_bytes());
    req.push(pass.len() as u8);
    req.extend_from_slice(pass);
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

#[cfg(test)]
mod socks5_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn relay_peer_key_separates_ipv4_and_ipv6() {
        let v4: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let v6: SocketAddr = "[::1]:40000".parse().unwrap();
        assert_ne!(relay_key_for_peer(v4), relay_key_for_peer(v6));
        assert_eq!(relay_key_for_peer(v4), relay_key(FAMILY_V4, 40_000));
        assert_eq!(relay_key_for_peer(v6), relay_key(FAMILY_V6, 40_000));
    }

    #[test]
    fn encodes_and_decodes_socks5_udp_frames() {
        let cases = [
            Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8)),
            Dst::Ip6("2001:db8::8".parse().unwrap()),
            Dst::Domain("internal.example.com".into()),
        ];

        for dst in cases {
            let mut frame = vec![0, 0, 0];
            encode_socks5_destination(&mut frame, &dst, 5353).unwrap();
            frame.extend_from_slice(b"payload");
            assert_eq!(decode_socks5_udp_payload(&frame).unwrap(), b"payload");
        }
    }

    #[test]
    fn rejects_fragmented_or_truncated_socks5_udp_frames() {
        assert!(
            decode_socks5_udp_payload(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53])
                .unwrap_err()
                .to_string()
                .contains("fragmented")
        );
        assert!(decode_socks5_udp_payload(&[0, 0, 0, 4, 0]).is_err());
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    fn request_bytes(dst: &Dst, port: u16) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00];
        match dst {
            Dst::Ip4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            Dst::Ip6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
            Dst::Domain(domain) => {
                request.push(0x03);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    #[tokio::test]
    async fn encodes_ipv4_ipv6_and_domain_connect_requests() {
        let cases = [
            Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8)),
            Dst::Ip6("2001:db8::8".parse().unwrap()),
            Dst::Domain("internal.example.com".into()),
        ];

        for dst in cases {
            let (mut client, mut server) = tcp_pair().await;
            let expected = request_bytes(&dst, 443);
            let server_task = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [0x05, 0x01, M_NO_AUTH]);
                server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();

                let mut request = vec![0u8; expected.len()];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, expected);
                server
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
            });

            socks5_connect(&mut client, &dst, 443, None).await.unwrap();
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn configured_auth_cannot_downgrade_and_preserves_password_bytes() {
        let (mut client, mut server) = tcp_pair().await;
        let auth = ResolvedAuth {
            username: "alice".into(),
            password: vec![0xff, 0x00, b'p'],
        };
        let dst = Dst::Domain("example.com".into());
        let expected_request = request_bytes(&dst, 443);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, M_USER_PASS]);
            server.write_all(&[0x05, M_USER_PASS]).await.unwrap();

            let mut auth_request = [0u8; 11];
            server.read_exact(&mut auth_request).await.unwrap();
            assert_eq!(
                auth_request,
                [0x01, 5, b'a', b'l', b'i', b'c', b'e', 3, 0xff, 0x00, b'p',]
            );
            server.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = vec![0u8; expected_request.len()];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected_request);
            server
                .write_all(&[
                    0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                ])
                .await
                .unwrap();
        });

        socks5_connect(&mut client, &dst, 443, Some(&auth))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_server_selected_auth_method_that_was_not_offered() {
        let (mut client, mut server) = tcp_pair().await;
        let auth = ResolvedAuth {
            username: "alice".into(),
            password: b"secret".to_vec(),
        };
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, M_USER_PASS]);
            server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
        });

        let error = socks5_connect(
            &mut client,
            &Dst::Domain("example.com".into()),
            443,
            Some(&auth),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("did not offer"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_nonzero_reserved_reply_byte() {
        let (mut client, mut server) = tcp_pair().await;
        let dst = Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8));
        let request_len = request_bytes(&dst, 443).len();
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
            let mut request = vec![0u8; request_len];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });

        let error = socks5_connect(&mut client, &dst, 443, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reserved"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_empty_and_non_ascii_domains() {
        for domain in [
            String::new(),
            "例.example".into(),
            "bad host.example".into(),
            "-bad.example".into(),
        ] {
            let (mut client, mut server) = tcp_pair().await;
            let server_task = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
            });
            assert!(
                socks5_connect(&mut client, &Dst::Domain(domain), 443, None)
                    .await
                    .is_err()
            );
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn handshake_timeout_bounds_silent_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let error = open_socks5_tunnel_with_timeouts(
            &addr.to_string(),
            &Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8)),
            443,
            None,
            Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out negotiating"));
        server_task.abort();
    }
}
