//! `heimdall run` — proxychains-style CLI proxy via cgroup + eBPF.
//!
//! Wraps an arbitrary command so its egress flows through one of the
//! named policy declared in /etc/heimdall/config.<ext>. No
//! LD_PRELOAD: works with statically-linked Go binaries, setuid
//! binaries. UDP uses reversible IPv4 tokens or an IPv6 single-peer fallback;
//! ambiguous IPv6 multi-target and shared-source-port patterns remain
//! fail-closed. The cgroup-attached eBPF programs do the redirection.
//!
//! Flow:
//!
//!   1. Resolve the policy from `proxy.default_policy`, then CLI flags.
//!   2. Verify we're inside `user@<UID>.service` (where the user has
//!      cgroup write permission). If not, re-exec via
//!      `systemd-run --user --scope --quiet -- heimdall run --no-reentry …`
//!      so we land in `app.slice/run-<id>.scope/`.
//!   3. mkdir a sibling cgroup `<parent>/heimdall-cli-<pid>-<rand>/`.
//!      Read its inode → cgroup_id (cgroup v2 invariant).
//!   4. Bind per-run relay and DNS listeners, then invoke a short-lived
//!      privileged setup worker. The worker attaches eBPF to only this
//!      cgroup and transfers the map/link FDs back before exiting.
//!   5. Fork. Child writes its PID to `cgroup.procs` and exec's the
//!      wrapped command. Parent waits for the child and every descendant
//!      inherited by the command cgroup.
//!   6. Once the cgroup is empty, close the per-run listeners/maps/links and
//!      rmdir it. Forward the immediate child's exit code (or signal).
//!
//! Permission model: the session owner and relay are unprivileged. One
//! short-lived authorized setup worker runs as root only to load/attach eBPF
//! and transfers owned FDs back before the wrapped command starts.

use std::ffi::{CString, OsString};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use heimdall_config::HeimdallConfig;
use nix::sys::signal::{self, SigHandler, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Named policy from `proxy.policies`. Overrides proxy.default_policy.
    #[arg(short = 'p', long)]
    pub policy: Option<String>,

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

/// Final knobs after config + flag resolution.
#[derive(Debug, Clone, Serialize)]
struct RunDecision {
    policy: String,
    dns: String,
}

#[derive(Debug, Serialize)]
struct RegisterReq {
    cgroup_id: u64,
    policy: String,
    run_id: uuid::Uuid,
    event_socket: PathBuf,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RegisterResp {
    cgroup_id: u64,
    policy: String,
    run_id: uuid::Uuid,
}

pub async fn run(config_path: &Path, args: RunArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path).map_err(|error| {
        anyhow!(
            "invalid config {}\n\n{}",
            config_path.display(),
            error.actionable_message()
        )
    })?;

    let decision = resolve_decision(&cfg, &args)?;

    if args.command.is_empty() {
        bail!(
            "missing command — pass it after `--`. e.g. `heimdall run -- curl https://example.com`"
        );
    }

    // Re-entry: if not under user@<UID>.service, hand off to
    // systemd-run so the next invocation lands in a writable cgroup.
    if !args.no_reentry && !in_user_service_scope()? {
        return reexec_via_systemd_run(config_path, &args);
    }

    let backend = if cfg.decrypt.mode == heimdall_config::DecryptMode::Runtime {
        "linux-ebpf-compatibility-daemon"
    } else {
        "linux-ebpf-foreground"
    };
    let event_log = crate::event_log::RunLog::create(&args.command, &decision.policy, backend)?;
    let rotation_server = crate::event_log::RotationServer::start(event_log.clone())?;
    let outcome = run_registered(
        &cfg,
        &decision,
        &args,
        &event_log,
        rotation_server.event_socket_path(),
    )
    .await;
    match outcome {
        Ok((exit_code, descendants_cleaned)) => {
            event_log.finish(exit_code, descendants_cleaned)?;
            drop(rotation_server);
            std::process::exit(exit_code);
        }
        Err(error) => {
            let _ = event_log.fail("run_failed", "heimdall run failed before completion");
            drop(rotation_server);
            Err(error)
        }
    }
}

async fn run_registered(
    cfg: &HeimdallConfig,
    decision: &RunDecision,
    args: &RunArgs,
    event_log: &crate::event_log::RunLog,
    event_socket: &Path,
) -> Result<(i32, bool)> {
    if cfg.decrypt.mode == heimdall_config::DecryptMode::Runtime {
        return run_registered_daemon(cfg, decision, args, event_log, event_socket);
    }

    let cgroup_path = create_sibling_cgroup()?;
    let cgroup_id = read_cgroup_id(&cgroup_path).inspect_err(|_| {
        let _ = fs::remove_dir(&cgroup_path);
    })?;

    let session = crate::ForegroundSession::start(
        cfg,
        &decision.policy,
        cgroup_path.clone(),
        cgroup_id,
        event_socket.to_path_buf(),
        event_log.run_dir()?.join("fake-dns.json"),
    )
    .await
    .inspect_err(|_| {
        let _ = fs::remove_dir(&cgroup_path);
    })?;
    let boundaries = match cfg.decrypt.mode {
        heimdall_config::DecryptMode::Off => vec!["transport"],
        heimdall_config::DecryptMode::Runtime => {
            vec!["transport", "tls_plaintext.runtime"]
        }
        heimdall_config::DecryptMode::Relay => vec!["transport", "tls_plaintext.relay"],
    };
    if let Err(error) = event_log.ready("heimdall-run", None, &boundaries) {
        session.shutdown().await;
        cleanup_before_exec(&cgroup_path, args.keep_cgroup);
        return Err(error);
    }

    // For dns=fake we need to short-circuit nss-resolve / systemd-resolved
    // so the child's getaddrinfo actually issues UDP to the resolver
    // (where eBPF can hijack it). Drop two tmp files and bind-mount them
    // over /etc/nsswitch.conf + /etc/resolv.conf inside the child's
    // private mount namespace. Cleaned up by the parent after waitpid.
    let dns_shim = if decision.dns == "fake" {
        match prepare_dns_shim(cgroup_id) {
            Ok(shim) => Some(shim),
            Err(error) => {
                session.shutdown().await;
                cleanup_before_exec(&cgroup_path, args.keep_cgroup);
                return Err(error);
            }
        }
    } else {
        None
    };

    let exit_code =
        fork_into_cgroup_and_exec(&cgroup_path, &args.command, dns_shim.as_ref(), event_log);

    // A shell or CLI can leave background descendants after its immediate
    // process exits. Closing the foreground links here would turn those
    // still-running descendants into unproxied traffic. Keep the complete
    // session alive until cgroup v2 reports that the command tree is empty.
    let cgroup_empty = wait_for_cgroup_empty(&cgroup_path).inspect_err(|e| {
        warn!(error = %e, path = %cgroup_path.display(), "cannot prove command cgroup is empty before foreground shutdown");
    });
    let descendants_cleaned = cgroup_empty.is_ok();
    let flows_drained = session.shutdown().await;
    if !flows_drained {
        warn!("foreground relay event flows did not drain before shutdown");
    }
    if descendants_cleaned
        && !args.keep_cgroup
        && let Err(e) = fs::remove_dir(&cgroup_path)
    {
        warn!(error = %e, path = %cgroup_path.display(), "rmdir cgroup failed");
    }
    if let Some(shim) = dns_shim {
        // Tmp files are cheap; ignore cleanup errors (parent might have
        // restarted between fork and waitpid leaving them around).
        let _ = fs::remove_file(&shim.nsswitch);
        let _ = fs::remove_file(&shim.resolv);
    }

    Ok((exit_code, descendants_cleaned))
}

fn run_registered_daemon(
    cfg: &HeimdallConfig,
    decision: &RunDecision,
    args: &RunArgs,
    event_log: &crate::event_log::RunLog,
    event_socket: &Path,
) -> Result<(i32, bool)> {
    let api_addr = api_loopback_addr(&cfg.daemon.api_listen);
    let cgroup_path = create_sibling_cgroup()?;
    let cgroup_id = read_cgroup_id(&cgroup_path).inspect_err(|_| {
        let _ = fs::remove_dir(&cgroup_path);
    })?;
    register_with_daemon(
        &api_addr,
        cgroup_id,
        decision,
        event_log.run_id()?,
        event_socket,
    )
    .inspect_err(|_| {
        let _ = fs::remove_dir(&cgroup_path);
    })?;
    if let Err(error) = event_log.ready(
        "heimdall-daemon",
        Some(&api_addr),
        &["transport", "tls_plaintext.runtime"],
    ) {
        cleanup_daemon_registration(&api_addr, cgroup_id, &cgroup_path, args.keep_cgroup);
        return Err(error);
    }
    let dns_shim = if decision.dns == "fake" {
        match prepare_dns_shim(cgroup_id) {
            Ok(shim) => Some(shim),
            Err(error) => {
                cleanup_daemon_registration(&api_addr, cgroup_id, &cgroup_path, args.keep_cgroup);
                return Err(error);
            }
        }
    } else {
        None
    };
    let exit_code =
        fork_into_cgroup_and_exec(&cgroup_path, &args.command, dns_shim.as_ref(), event_log);
    let descendants_cleaned = wait_for_cgroup_empty(&cgroup_path).is_ok();
    if descendants_cleaned {
        if let Err(error) = deregister_with_daemon(&api_addr, cgroup_id) {
            warn!(%error, "cannot deregister compatibility-daemon run");
        }
        if !args.keep_cgroup
            && let Err(error) = fs::remove_dir(&cgroup_path)
        {
            warn!(%error, path = %cgroup_path.display(), "cannot remove command cgroup");
        }
    }
    if let Some(shim) = dns_shim {
        let _ = fs::remove_file(&shim.nsswitch);
        let _ = fs::remove_file(&shim.resolv);
    }
    Ok((exit_code, descendants_cleaned))
}

fn cleanup_before_exec(cgroup_path: &Path, keep_cgroup: bool) {
    if !keep_cgroup && let Err(error) = fs::remove_dir(cgroup_path) {
        warn!(%error, path = %cgroup_path.display(), "cannot remove failed pre-exec cgroup");
    }
}

fn cleanup_daemon_registration(base: &str, cgroup_id: u64, cgroup_path: &Path, keep_cgroup: bool) {
    if let Err(error) = deregister_with_daemon(base, cgroup_id) {
        warn!(%error, "cannot deregister failed compatibility-daemon run");
    }
    cleanup_before_exec(cgroup_path, keep_cgroup);
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
///
/// - NSS doesn't dispatch hostname lookups to nss-resolve / D-Bus
///   (which would talk to systemd-resolved, returning NXDOMAIN for
///   hosts only heimdall's fake-IP DNS knows about)
/// - libc's nss-dns falls back to UDP `127.0.0.1:53` queries that
///   the eBPF DNS-hijack rewrites to heimdall's fake-IP DNS port
fn prepare_dns_shim(cgroup_id: u64) -> Result<DnsShim> {
    let nsswitch = PathBuf::from(format!("/tmp/heimdall-cli-nsswitch-{cgroup_id}.conf"));
    let resolv = PathBuf::from(format!("/tmp/heimdall-cli-resolv-{cgroup_id}.conf"));

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
// Decision resolution: config defaults ← flags
// ────────────────────────────────────────────────────────────────────────────

fn resolve_decision(cfg: &HeimdallConfig, args: &RunArgs) -> Result<RunDecision> {
    let policy = args
        .policy
        .clone()
        .unwrap_or_else(|| cfg.proxy.default_policy.clone());
    let selected = cfg.policy(&policy).ok_or_else(|| {
        let known: Vec<&str> = cfg.proxy.policies.keys().map(String::as_str).collect();
        anyhow!(
            "unknown policy `{policy}` — declared policies: [{}]; fix: choose one with --policy NAME or update proxy.default_policy",
            known.join(", ")
        )
    })?;
    let dns = match selected.dns.mode {
        heimdall_config::DnsMode::Fake => "fake",
        heimdall_config::DnsMode::System => "system",
    }
    .to_string();
    Ok(RunDecision { policy, dns })
}

// ────────────────────────────────────────────────────────────────────────────
// systemd user-scope re-exec — gives us a writable cgroup tree
// ────────────────────────────────────────────────────────────────────────────

#[allow(
    unsafe_code,
    reason = "libc getuid has no safety preconditions and only reads process credentials"
)]
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

fn reexec_via_systemd_run(config_path: &Path, args: &RunArgs) -> Result<()> {
    let exe = std::env::current_exe().context("current_exe")?;
    let mut cmd = Command::new("systemd-run");
    // systemd-run expands `$VAR`, `${VAR}`, and `$$` in argv by default.
    // Agent commands are already structured argv and must reach execvp byte
    // for byte; a shell snippet such as `kill -TERM $$` cannot survive that
    // second interpretation. Disable expansion before the command separator.
    cmd.args([
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--expand-environment=no",
        "--",
    ]);
    cmd.args(reentry_command_args(&exe, config_path, args));
    let status = cmd
        .status()
        .context("exec systemd-run --user --scope (is systemd-user running?)")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn reentry_command_args(exe: &Path, config_path: &Path, args: &RunArgs) -> Vec<OsString> {
    let mut argv = vec![
        exe.as_os_str().to_owned(),
        "--config".into(),
        config_path.as_os_str().to_owned(),
        "run".into(),
        "--no-reentry".into(),
    ];
    if let Some(policy) = &args.policy {
        argv.push("--policy".into());
        argv.push(policy.into());
    }
    if args.keep_cgroup {
        argv.push("--keep-cgroup".into());
    }
    argv.push("--".into());
    for a in &args.command {
        argv.push(a.into());
    }
    argv
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

fn wait_for_cgroup_empty(path: &Path) -> Result<()> {
    let events = path.join("cgroup.events");
    loop {
        let raw =
            fs::read_to_string(&events).with_context(|| format!("read {}", events.display()))?;
        if !cgroup_is_populated(&raw)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn cgroup_is_populated(events: &str) -> Result<bool> {
    events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .map(|value| match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => bail!("invalid cgroup.events populated value `{value}`"),
        })
        .transpose()?
        .ok_or_else(|| anyhow!("cgroup.events has no populated field"))
}

fn api_loopback_addr(api_listen: &str) -> String {
    format!("http://{api_listen}")
}

fn register_with_daemon(
    base: &str,
    cgroup_id: u64,
    decision: &RunDecision,
    run_id: uuid::Uuid,
    event_socket: &Path,
) -> Result<()> {
    let url = format!("{base}/api/cli/register");
    let response = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(RegisterReq {
            cgroup_id,
            policy: decision.policy.clone(),
            run_id,
            event_socket: event_socket.to_path_buf(),
        })?)
        .map_err(|error| anyhow!("POST {url}: {error}"))?;
    let _: RegisterResp = response
        .into_json()
        .context("parse /api/cli/register response")?;
    Ok(())
}

fn deregister_with_daemon(base: &str, cgroup_id: u64) -> Result<()> {
    let url = format!("{base}/api/cli/deregister?cgroup_id={cgroup_id}");
    ureq::post(&url)
        .send_string("")
        .map_err(|error| anyhow!("POST {url}: {error}"))?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// fork → child joins cgroup → execvp ; parent waits and forwards exit
// ────────────────────────────────────────────────────────────────────────────

#[allow(
    unsafe_code,
    reason = "fork and signal disposition changes are confined to the immediate pre-exec child path"
)]
fn fork_into_cgroup_and_exec(
    cgroup_path: &Path,
    cmd: &[String],
    dns_shim: Option<&DnsShim>,
    event_log: &crate::event_log::RunLog,
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
                eprintln!("heimdall run: write {} failed: {e}", cgroup_procs.display());
                std::process::exit(127);
            }

            // DNS shim: enter a private user+mount namespace and
            // bind-mount custom nsswitch + resolv.conf so the wrapped
            // command's libc resolver issues UDP DNS queries that
            // eBPF can hijack (instead of D-Bus to systemd-resolved
            // which we can't intercept).
            if let Some(shim) = dns_shim
                && let Err(e) = apply_dns_shim(shim)
            {
                eprintln!("heimdall run: dns shim failed: {e:#}");
                std::process::exit(127);
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
                "http_proxy",
                "HTTP_PROXY",
                "https_proxy",
                "HTTPS_PROXY",
                "all_proxy",
                "ALL_PROXY",
                "no_proxy",
                "NO_PROXY",
                "ftp_proxy",
                "FTP_PROXY",
            ] {
                // SAFETY: this is the post-fork child immediately before exec;
                // it cannot race another thread's environment access.
                unsafe { std::env::remove_var(var) };
            }

            // execvp — replaces this process image with the wrapped
            // command. From the kernel's POV the cgroup membership
            // sticks across exec.
            let prog = CString::new(cmd[0].as_bytes()).expect("command path contained NUL");
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
        Ok(ForkResult::Parent { child }) => {
            if let Err(error) = event_log.emit(
                "run.exec",
                Some(child.as_raw().try_into().unwrap_or(u32::MAX)),
                serde_json::json!({
                    "child_pid": child.as_raw(),
                    "executable": cmd[0],
                    "argv_count": cmd.len()
                }),
            ) {
                warn!(%error, "cannot record run.exec event");
            }
            wait_for_child(child)
        }
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
#[allow(
    unsafe_code,
    reason = "libc getuid and getgid have no safety preconditions and only read process credentials"
)]
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

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::Path};

    use super::{RunArgs, cgroup_is_populated, reentry_command_args};

    #[test]
    fn parses_cgroup_population_without_field_order_assumptions() {
        assert!(cgroup_is_populated("frozen 0\npopulated 1\n").unwrap());
        assert!(!cgroup_is_populated("populated 0\nfrozen 0\n").unwrap());
    }

    #[test]
    fn rejects_missing_or_invalid_population_state() {
        assert!(cgroup_is_populated("frozen 0\n").is_err());
        assert!(cgroup_is_populated("populated maybe\n").is_err());
    }

    #[test]
    fn reentry_preserves_the_resolved_global_config_path() {
        let args = RunArgs {
            policy: Some("corp".to_string()),
            no_reentry: false,
            keep_cgroup: true,
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        };

        assert_eq!(
            reentry_command_args(
                Path::new("/opt/heimdall/bin/heimdall"),
                Path::new("/etc/heimdall/runtime.toml"),
                &args,
            ),
            Vec::<OsString>::from([
                "/opt/heimdall/bin/heimdall".into(),
                "--config".into(),
                "/etc/heimdall/runtime.toml".into(),
                "run".into(),
                "--no-reentry".into(),
                "--policy".into(),
                "corp".into(),
                "--keep-cgroup".into(),
                "--".into(),
                "sh".into(),
                "-c".into(),
                "exit 0".into(),
            ])
        );
    }
}
