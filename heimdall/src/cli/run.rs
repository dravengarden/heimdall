//! `heimdall run` — proxychains-style CLI proxy via cgroup + eBPF.
//!
//! Wraps an arbitrary command so its egress flows through one of the
//! `connections:` declared in /etc/heimdall/heimdall.<ext>. No
//! LD_PRELOAD: works with statically-linked Go binaries, setuid
//! binaries, and UDP traffic, because heimdall's existing
//! cgroup-attached eBPF programs do the redirection.
//!
//! Flow:
//!
//!   1. Resolve final (connection, observe, tag) by merging
//!      `cli.run.default` ← `cli.run.profiles.<--profile>` ← flags.
//!   2. Verify we're inside `user@<UID>.service` (where the user has
//!      cgroup write permission). If not, re-exec via
//!      `systemd-run --user --scope --quiet -- heimdall run --no-reentry …`
//!      so we land in `app.slice/run-<id>.scope/`.
//!   3. mkdir a sibling cgroup `<parent>/heimdall-cli-<pid>-<rand>/`.
//!      Read its inode → cgroup_id (cgroup v2 invariant).
//!   4. POST `/api/cli/register` to the daemon, which writes both the
//!      userspace cli_overrides map (relay reads) and the
//!      CGROUP_POLICY BPF map (kernel-side connect4 reads).
//!   5. Fork. Child writes its PID to `cgroup.procs` and exec's the
//!      wrapped command. Parent waits.
//!   6. On child exit, POST `/api/cli/deregister` and rmdir the
//!      cgroup. Forwards the child's exit code (or signal) as our own.
//!
//! Permission model: completely non-root. Users land under their
//! systemd user manager's delegated subtree; everything we do is
//! within their own UID's authority.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use heimdall_config::{CliRunProfile, HeimdallConfig, SYSTEM_TAG};
use nix::sys::signal::{self, SigHandler, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Connection name to use (or the reserved `system` to bypass
    /// the relay entirely). Overrides any value from
    /// `cli.run.default` and the active --profile.
    #[arg(short = 'c', long)]
    pub connection: Option<String>,

    /// Apply `cli.run.profiles.<NAME>` from the config before flag
    /// overrides. Resolution order: flag > profile > cli.run.default.
    #[arg(short = 'p', long)]
    pub profile: Option<String>,

    /// Capture plaintext for the wrapped command's TLS sessions.
    /// Requires `runtime.tap.enabled = true` on the daemon side to
    /// actually attach uprobes.
    #[arg(long)]
    pub observe: Option<bool>,

    /// Free-form label, surfaces in the flow log entries.
    #[arg(long)]
    pub tag: Option<String>,

    /// DNS strategy for the wrapped command. `fake` makes heimdall
    /// hijack DNS lookups (UDP/TCP :53 destinations) for the cgroup
    /// and serve them from the fake-IP DNS server, so hostnames in
    /// the upstream proxy's scope (e.g. corporate VPN) resolve to a
    /// fake IP that connect4/connect6 then routes via the relay.
    /// `system` uses the host's normal resolver (systemd-resolved /
    /// /etc/resolv.conf) — useful when the wrapped command needs
    /// public DNS only.
    #[arg(long, value_parser = ["fake", "system"])]
    pub dns: Option<String>,

    /// Print the resolved RunDecision as JSON and exit without
    /// running the command. Useful for debugging profile resolution.
    #[arg(long)]
    pub print_decision: bool,

    /// Skip the systemd-run --user --scope re-exec. Set automatically
    /// by the re-exec path so we don't loop. Hidden from --help.
    #[arg(long, hide = true)]
    pub no_reentry: bool,

    /// Don't rmdir the transient cgroup on exit (debug aid; cgroup
    /// stays around so you can inspect cgroup.events / cgroup.procs).
    #[arg(long)]
    pub keep_cgroup: bool,

    /// The command to execute, with its arguments. Pass after `--`:
    ///
    ///   heimdall run -p corp -- curl https://internal/...
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..,
          value_name = "CMD")]
    pub command: Vec<String>,
}

/// Final knobs after profile + flag resolution.
#[derive(Debug, Clone, Serialize)]
struct RunDecision {
    connection: String,
    observe: bool,
    /// `"fake"` (heimdall hijacks :53 lookups for this cgroup) or
    /// `"system"` (host resolver / systemd-resolved). Defaults to
    /// `"fake"` because most `heimdall run` use cases want the
    /// upstream proxy's DNS scope (corp VPN), not the host's.
    dns: String,
    tag: Option<String>,
}

/// JSON body for `POST /api/cli/register`.
#[derive(Debug, Serialize)]
struct RegisterReq {
    cgroup_id: u64,
    connection: String,
    observe: bool,
    dns: String,
}

/// Response shape — mirrors api::CliOverrideEntry.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RegisterResp {
    cgroup_id: u64,
    connection: String,
    observe: bool,
}

pub fn run(config_path: &Path, args: RunArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let decision = resolve_decision(&cfg, &args)?;

    if args.print_decision {
        println!("{}", serde_json::to_string_pretty(&decision)?);
        return Ok(());
    }

    if args.command.is_empty() {
        bail!("missing command — pass it after `--`. e.g. `heimdall run -- curl https://example.com`");
    }

    // Re-entry: if not under user@<UID>.service, hand off to
    // systemd-run so the next invocation lands in a writable cgroup.
    if !args.no_reentry && !in_user_service_scope()? {
        return reexec_via_systemd_run(&args);
    }

    let api_addr = api_loopback_addr(&cfg.runtime.api_listen);
    let cgroup_path = create_sibling_cgroup()?;
    let cgroup_id = read_cgroup_id(&cgroup_path)?;

    // Register before fork so the child inherits the policy.
    register_with_daemon(&api_addr, cgroup_id, &decision).map_err(|e| {
        // Best-effort cleanup before bailing.
        let _ = fs::remove_dir(&cgroup_path);
        e
    })?;

    // For dns=fake we need to short-circuit nss-resolve / systemd-resolved
    // so the child's getaddrinfo actually issues UDP to the resolver
    // (where eBPF can hijack it). Drop two tmp files and bind-mount them
    // over /etc/nsswitch.conf + /etc/resolv.conf inside the child's
    // private mount namespace. Cleaned up by the parent after waitpid.
    let dns_shim = if decision.dns == "fake" {
        Some(prepare_dns_shim(cgroup_id)?)
    } else {
        None
    };

    let exit_code = fork_into_cgroup_and_exec(&cgroup_path, &args.command, dns_shim.as_ref());

    // Always deregister + cleanup, even on child failure.
    if let Err(e) = deregister_with_daemon(&api_addr, cgroup_id) {
        warn!(error = %e, "deregister failed; daemon will GC eventually");
    }
    if !args.keep_cgroup {
        if let Err(e) = fs::remove_dir(&cgroup_path) {
            warn!(error = %e, path = %cgroup_path.display(), "rmdir cgroup failed");
        }
    }
    if let Some(shim) = dns_shim {
        // Tmp files are cheap; ignore cleanup errors (parent might have
        // restarted between fork and waitpid leaving them around).
        let _ = fs::remove_file(&shim.nsswitch);
        let _ = fs::remove_file(&shim.resolv);
    }

    std::process::exit(exit_code);
}

/// Files generated by `prepare_dns_shim` and bind-mounted into the
/// wrapped command's mount namespace.
struct DnsShim {
    nsswitch: PathBuf,
    resolv: PathBuf,
}

/// Generate per-invocation `nsswitch.conf` and `resolv.conf` in /tmp.
/// The child unshares a mount namespace and bind-mounts these over
/// `/etc/nsswitch.conf` and `/etc/resolv.conf` so:
///   - NSS doesn't dispatch hostname lookups to nss-resolve / D-Bus
///     (which would talk to systemd-resolved, returning NXDOMAIN for
///      hosts only heimdall's fake-IP DNS knows about)
///   - libc's nss-dns falls back to UDP `127.0.0.1:53` queries that
///     the eBPF DNS-hijack rewrites to heimdall's fake-IP DNS port
fn prepare_dns_shim(cgroup_id: u64) -> Result<DnsShim> {
    let nsswitch = PathBuf::from(format!(
        "/tmp/heimdall-cli-nsswitch-{cgroup_id}.conf"
    ));
    let resolv = PathBuf::from(format!(
        "/tmp/heimdall-cli-resolv-{cgroup_id}.conf"
    ));

    // `hosts: files dns` skips `resolve` and `mymachines` so libc goes
    // straight to /etc/resolv.conf (which we override below). The
    // other databases stay on `files` to avoid surprising the wrapped
    // command's user/group lookups.
    fs::write(
        &nsswitch,
        b"passwd:    files\n\
          group:     files\n\
          shadow:    files\n\
          hosts:     files dns\n\
          networks:  files\n\
          ethers:    files\n\
          rpc:       files\n\
          services:  files\n\
          protocols: files\n",
    )
    .with_context(|| format!("write {}", nsswitch.display()))?;

    // `nameserver 127.0.0.1` would normally fail (nothing on port 53),
    // but heimdall's eBPF connect4 / udp4_sendmsg hijack on this
    // cgroup rewrites :53 traffic to the daemon's fake-IP DNS port
    // (5358 by default). `single-request` reduces glibc's parallel
    // A+AAAA query churn — we synthesise both anyway.
    fs::write(
        &resolv,
        b"nameserver 127.0.0.1\noptions single-request ndots:0\n",
    )
    .with_context(|| format!("write {}", resolv.display()))?;

    Ok(DnsShim { nsswitch, resolv })
}

// ────────────────────────────────────────────────────────────────────────────
// Decision resolution: cli.run.default ← profile ← flags
// ────────────────────────────────────────────────────────────────────────────

fn resolve_decision(cfg: &HeimdallConfig, args: &RunArgs) -> Result<RunDecision> {
    let base = &cfg.cli.run.default;
    let profile: Option<&CliRunProfile> = match &args.profile {
        Some(name) => Some(cfg.cli.run.profiles.get(name).ok_or_else(|| {
            let known: Vec<&str> =
                cfg.cli.run.profiles.keys().map(String::as_str).collect();
            anyhow!(
                "unknown profile `{name}` — declared profiles: [{}]",
                known.join(", ")
            )
        })?),
        None => None,
    };

    // Resolve in order: compiled-in default → cli.run.default → profile → flag.
    let connection = pick(
        args.connection.clone(),
        profile.and_then(|p| p.connection.clone()),
        base.connection.clone(),
        || "default".into(),
    );
    let observe = pick(
        args.observe,
        profile.and_then(|p| p.observe),
        base.observe,
        || true,
    );
    // DNS strategy: `--dns fake|system` flag wins, then profile, then
    // cli.run.default. Compiled fallback is "fake" — heimdall run's
    // primary use case is reaching scoped/internal hosts that the
    // host resolver doesn't know about.
    let dns = args
        .dns
        .clone()
        .or_else(|| profile.and_then(|p| p.dns).map(dns_strategy_str))
        .or_else(|| base.dns.map(dns_strategy_str))
        .unwrap_or_else(|| "fake".into());
    if dns != "fake" && dns != "system" {
        bail!(
            "invalid dns strategy `{dns}` — expected `fake` or `system`"
        );
    }
    let tag = args
        .tag
        .clone()
        .or_else(|| profile.and_then(|p| p.tag.clone()))
        .or_else(|| base.tag.clone());

    // Validate connection name against the live config so we surface
    // typos before round-tripping to the daemon.
    if connection != SYSTEM_TAG && !cfg.connections.contains_key(&connection) {
        let known: Vec<&str> = cfg
            .connections
            .keys()
            .map(String::as_str)
            .chain(std::iter::once(SYSTEM_TAG))
            .collect();
        bail!(
            "unknown connection `{connection}` — declared connections + reserved tag: [{}]",
            known.join(", ")
        );
    }

    Ok(RunDecision { connection, observe, dns, tag })
}

fn dns_strategy_str(d: heimdall_config::DnsStrategy) -> String {
    match d {
        heimdall_config::DnsStrategy::Fake => "fake".into(),
        heimdall_config::DnsStrategy::System => "system".into(),
    }
}

fn pick<T, F>(flag: Option<T>, profile: Option<T>, base: Option<T>, fallback: F) -> T
where
    F: FnOnce() -> T,
{
    flag.or(profile).or(base).unwrap_or_else(fallback)
}

// ────────────────────────────────────────────────────────────────────────────
// systemd user-scope re-exec — gives us a writable cgroup tree
// ────────────────────────────────────────────────────────────────────────────

fn in_user_service_scope() -> Result<bool> {
    let cgroup = read_proc_self_cgroup()?;
    let uid = unsafe { libc::getuid() };
    let needle = format!("/user.slice/user-{uid}.slice/user@{uid}.service/");
    Ok(cgroup.contains(&needle))
}

fn read_proc_self_cgroup() -> Result<String> {
    let raw = fs::read_to_string("/proc/self/cgroup").context("read /proc/self/cgroup")?;
    // cgroup v2 unified hierarchy: single `0::/path` line.
    let line = raw.lines().next().unwrap_or("");
    let path = line.splitn(3, ':').nth(2).unwrap_or("").to_string();
    Ok(path)
}

fn reexec_via_systemd_run(args: &RunArgs) -> Result<()> {
    let exe = std::env::current_exe().context("current_exe")?;
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--scope", "--quiet", "--collect", "--"]);
    cmd.arg(&exe);
    cmd.arg("run");
    cmd.arg("--no-reentry");
    if let Some(c) = &args.connection {
        cmd.arg("--connection").arg(c);
    }
    if let Some(p) = &args.profile {
        cmd.arg("--profile").arg(p);
    }
    if let Some(o) = args.observe {
        cmd.arg("--observe").arg(o.to_string());
    }
    if let Some(t) = &args.tag {
        cmd.arg("--tag").arg(t);
    }
    if args.keep_cgroup {
        cmd.arg("--keep-cgroup");
    }
    cmd.arg("--");
    for a in &args.command {
        cmd.arg(a);
    }
    let status = cmd
        .status()
        .context("exec systemd-run --user --scope (is systemd-user running?)")?;
    std::process::exit(status.code().unwrap_or(1));
}

// ────────────────────────────────────────────────────────────────────────────
// Cgroup management
// ────────────────────────────────────────────────────────────────────────────

fn current_cgroup_path() -> Result<PathBuf> {
    let rel = read_proc_self_cgroup()?;
    let abs = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    Ok(abs)
}

fn create_sibling_cgroup() -> Result<PathBuf> {
    let current = current_cgroup_path()?;
    let parent = current.parent().ok_or_else(|| {
        anyhow!("/proc/self/cgroup pointed at root; refusing to mkdir at /sys/fs/cgroup itself")
    })?;
    let name = format!(
        "heimdall-cli-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );
    let path = parent.join(&name);
    fs::create_dir(&path).with_context(|| {
        format!(
            "mkdir {} (parent must be user-writable; pass via systemd-run --user --scope?)",
            path.display()
        )
    })?;
    Ok(path)
}

/// In cgroup v2 the kernel `cgroup_id` IS the directory's inode in
/// the cgroupfs. Read it via fstat — no special syscall needed.
fn read_cgroup_id(path: &Path) -> Result<u64> {
    let m = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(m.ino())
}

// ────────────────────────────────────────────────────────────────────────────
// Daemon HTTP API — register / deregister
// ────────────────────────────────────────────────────────────────────────────

fn api_loopback_addr(api_listen: &str) -> String {
    // `runtime.apiListen` is "0.0.0.0:9999" by default; rewrite to
    // loopback for the local CLI roundtrip so we're not dependent on
    // the binding being LAN-reachable.
    let port = api_listen.rsplit(':').next().unwrap_or("9999");
    format!("http://127.0.0.1:{port}")
}

fn register_with_daemon(base: &str, cgroup_id: u64, d: &RunDecision) -> Result<()> {
    let body = RegisterReq {
        cgroup_id,
        connection: d.connection.clone(),
        observe: d.observe,
        dns: d.dns.clone(),
    };
    let url = format!("{base}/api/cli/register");
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(&body)?)
        .map_err(|e| anyhow!("POST {url}: {e}"))?;
    let _: RegisterResp = resp
        .into_json()
        .context("parse /api/cli/register response")?;
    Ok(())
}

fn deregister_with_daemon(base: &str, cgroup_id: u64) -> Result<()> {
    let url = format!("{base}/api/cli/deregister?cgroup_id={cgroup_id}");
    ureq::post(&url)
        .send_string("")
        .map_err(|e| anyhow!("POST {url}: {e}"))?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// fork → child joins cgroup → execvp ; parent waits and forwards exit
// ────────────────────────────────────────────────────────────────────────────

fn fork_into_cgroup_and_exec(
    cgroup_path: &Path,
    cmd: &[String],
    dns_shim: Option<&DnsShim>,
) -> i32 {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Move ourselves into the new cgroup before exec. Errors
            // here go to stderr and exit 127 so the parent reports a
            // sensible code rather than the wrapped command's stale
            // status from a previous run.
            let pid_str = std::process::id().to_string();
            let cgroup_procs = cgroup_path.join("cgroup.procs");
            if let Err(e) = fs::write(&cgroup_procs, pid_str.as_bytes()) {
                eprintln!(
                    "heimdall run: write {} failed: {e}",
                    cgroup_procs.display()
                );
                std::process::exit(127);
            }

            // DNS shim: enter a private user+mount namespace and
            // bind-mount custom nsswitch + resolv.conf so the wrapped
            // command's libc resolver issues UDP DNS queries that
            // eBPF can hijack (instead of D-Bus to systemd-resolved
            // which we can't intercept).
            if let Some(shim) = dns_shim {
                if let Err(e) = apply_dns_shim(shim) {
                    eprintln!("heimdall run: dns shim failed: {e:#}");
                    std::process::exit(127);
                }
            }

            // Restore default SIGINT/SIGTERM so Ctrl+C reaches the
            // wrapped command, not the parent only.
            unsafe {
                let _ = signal::signal(Signal::SIGINT, SigHandler::SigDfl);
                let _ = signal::signal(Signal::SIGTERM, SigHandler::SigDfl);
            }

            // Strip every "use this HTTP proxy" env var. Without this,
            // applications like curl/git/pip honour http_proxy /
            // https_proxy and short-circuit straight to v2raya
            // (127.0.0.1:20170/20171), which falls in heimdall's
            // loopback bypass list — the relay never sees the
            // connection and our routing decision becomes a no-op.
            // Strip both lower- and upper-case variants because every
            // tool seems to read a different one.
            for var in [
                "http_proxy", "HTTP_PROXY",
                "https_proxy", "HTTPS_PROXY",
                "all_proxy", "ALL_PROXY",
                "no_proxy", "NO_PROXY",
                "ftp_proxy", "FTP_PROXY",
            ] {
                std::env::remove_var(var);
            }

            // execvp — replaces this process image with the wrapped
            // command. From the kernel's POV the cgroup membership
            // sticks across exec.
            let prog =
                CString::new(cmd[0].as_bytes()).expect("command path contained NUL");
            let argv: Vec<CString> = cmd
                .iter()
                .map(|s| CString::new(s.as_bytes()).expect("arg contained NUL"))
                .collect();
            let argv_refs: Vec<&std::ffi::CStr> = argv.iter().map(|c| c.as_c_str()).collect();
            let _ = nix::unistd::execvp(&prog, &argv_refs);
            // execvp returned → it failed (otherwise we'd never be here).
            eprintln!("heimdall run: execvp({}) failed", cmd[0]);
            std::process::exit(127);
        }
        Ok(ForkResult::Parent { child }) => wait_for_child(child),
        Err(e) => {
            eprintln!("heimdall run: fork failed: {e}");
            127
        }
    }
}

/// Run inside the child after fork + cgroup join. Creates a user + mount
/// namespace owned by the current uid, makes `/` mounts private (so our
/// bind-mounts don't propagate back to the host), and bind-mounts the
/// shim files over `/etc/nsswitch.conf` and `/etc/resolv.conf`.
///
/// User namespaces let an unprivileged user gain CAP_SYS_ADMIN inside
/// their own ns, which is required to mount(2). The uid_map maps the
/// current real uid to itself (`<uid> <uid> 1`) so file permissions
/// stay sane after the namespace switch.
fn apply_dns_shim(shim: &DnsShim) -> Result<()> {
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
        .context("unshare(CLONE_NEWUSER | CLONE_NEWNS)")?;

    // setgroups must be denied before gid_map can be written for
    // unprivileged user namespace setup (kernel rule since 3.19).
    fs::write("/proc/self/setgroups", b"deny").context("/proc/self/setgroups deny")?;
    fs::write(
        "/proc/self/uid_map",
        format!("{real_uid} {real_uid} 1\n").as_bytes(),
    )
    .context("/proc/self/uid_map")?;
    fs::write(
        "/proc/self/gid_map",
        format!("{real_gid} {real_gid} 1\n").as_bytes(),
    )
    .context("/proc/self/gid_map")?;

    // Make root mount private+rec so our bind-mounts don't escape into
    // the host's mount namespace via shared subtrees.
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("mount(none, /, MS_PRIVATE|MS_REC)")?;

    mount(
        Some(&shim.nsswitch),
        "/etc/nsswitch.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("bind shim nsswitch.conf")?;

    mount(
        Some(&shim.resolv),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("bind shim resolv.conf")?;

    // glibc consults /var/run/nscd/socket BEFORE walking nsswitch —
    // if nscd is up, it caches lookups in the daemon's mount namespace
    // (not ours), so even our shimmed nsswitch + resolv.conf get
    // bypassed. Overmount the socket with /dev/null so connect() to
    // it fails with ENOTSOCK/ECONNREFUSED; glibc falls back to direct
    // NSS resolution that DOES see our shimmed files. Best-effort —
    // not all distros / setups have nscd, missing socket is fine.
    let _ = mount(
        Some("/dev/null"),
        "/var/run/nscd/socket",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    );

    Ok(())
}

fn wait_for_child(child: Pid) -> i32 {
    loop {
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return code,
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                // POSIX convention: 128 + signal number.
                return 128 + sig as i32;
            }
            Ok(_) => continue, // stopped/continued — keep waiting
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("heimdall run: waitpid: {e}");
                return 127;
            }
        }
    }
}

