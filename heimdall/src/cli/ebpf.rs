//! Explicit lifecycle operations for Heimdall-owned bpffs state.

use anyhow::Result;
use serde::Serialize;

use crate::{ebpf, gc, state};

const CONTRACT: &str = "heimdall.ebpf.cleanup/v1";

#[derive(clap::Subcommand, Debug)]
pub enum EbpfCmd {
    /// Remove Heimdall-owned pinned maps and links after the daemon stops.
    Cleanup(CleanupArgs),
}

#[derive(clap::Args, Debug)]
pub struct CleanupArgs {
    /// Emit one stable JSON document for automation.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct CleanupReport {
    contract: &'static str,
    cleaned: bool,
    code: &'static str,
    message: String,
    active_cgroups: Vec<u64>,
    registrations: Vec<u64>,
    removed_entries: usize,
}

pub fn run(command: EbpfCmd) -> Result<bool> {
    match command {
        EbpfCmd::Cleanup(args) => cleanup(args),
    }
}

fn cleanup(args: CleanupArgs) -> Result<bool> {
    if effective_uid() != 0 {
        return emit(
            args.json,
            CleanupReport {
                contract: CONTRACT,
                cleaned: false,
                code: "root_required",
                message: "Run this lifecycle operation as root.".into(),
                active_cgroups: Vec::new(),
                registrations: Vec::new(),
                removed_entries: 0,
            },
        );
    }

    let _lock = match state::DaemonLock::acquire() {
        Ok(lock) => lock,
        Err(error) => {
            return emit(
                args.json,
                CleanupReport {
                    contract: CONTRACT,
                    cleaned: false,
                    code: "daemon_active",
                    message: format!(
                        "Stop heimdall.service before cleanup. Lifecycle lock error: {error:#}"
                    ),
                    active_cgroups: Vec::new(),
                    registrations: Vec::new(),
                    removed_entries: 0,
                },
            );
        }
    };

    let active_cgroups = gc::command_cgroups()?
        .into_iter()
        .filter(|cgroup| cgroup.populated)
        .map(|cgroup| cgroup.id)
        .collect::<Vec<_>>();
    let registrations = state::load_registrations()?
        .into_iter()
        .map(|registration| registration.cgroup_id)
        .collect::<Vec<_>>();
    if !active_cgroups.is_empty() || !registrations.is_empty() {
        return emit(
            args.json,
            CleanupReport {
                contract: CONTRACT,
                cleaned: false,
                code: "active_workloads",
                message: "Wait for every `heimdall run` process to exit, then retry cleanup."
                    .into(),
                active_cgroups,
                registrations,
                removed_entries: 0,
            },
        );
    }

    let removed_entries = ebpf::cleanup_pins()?;
    emit(
        args.json,
        CleanupReport {
            contract: CONTRACT,
            cleaned: true,
            code: "cleaned",
            message: "Removed Heimdall-owned pinned eBPF maps and links.".into(),
            active_cgroups,
            registrations,
            removed_entries,
        },
    )
}

fn emit(json: bool, report: CleanupReport) -> Result<bool> {
    let cleaned = report.cleaned;
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}: {}", report.code, report.message);
    }
    Ok(cleaned)
}

#[allow(
    unsafe_code,
    reason = "libc provides the effective UID used for privileged lifecycle checks"
)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::CONTRACT;

    #[test]
    fn cleanup_contract_is_versioned() {
        assert_eq!(CONTRACT, "heimdall.ebpf.cleanup/v1");
    }
}
