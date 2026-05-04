//! Orphan cleanup for `heimdall run` cgroups.
//!
//! When a `heimdall run` invocation exits cleanly, its parent process
//! deregisters the cgroup_id with the daemon and rmdirs the transient
//! cgroup. But abnormal exits (`kill -9` on the parent, OOM kill,
//! daemon-side error mid-flight) leave behind:
//!
//!   - a `heimdall-cli-<pid>-<rand>/` directory under
//!     `/sys/fs/cgroup/user.slice/.../app.slice/`
//!   - a `CGROUP_POLICY` BPF map entry for that cgroup_id
//!   - a `cli_overrides` userspace map entry
//!   - a `PolicyEngine.external` set entry
//!
//! This module runs a periodic GC pass that walks the user.slice
//! subtree, finds empty `heimdall-cli-*` cgroups (`cgroup.events:
//! populated 0` — no live procs), and reaps everything in one shot.
//! The walk is bounded depth-first; depth ≤ 6 is enough to reach
//! `/sys/fs/cgroup/user.slice/user-<UID>.slice/user@<UID>.service/
//! app.slice/heimdall-cli-*/` without descending into kubepods or
//! system.slice.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use std::os::unix::fs::MetadataExt;
use tracing::{debug, info, warn};

use crate::policy::PolicyEngine;
use crate::CliOverrides;

const GC_INTERVAL: Duration = Duration::from_secs(30);
const USER_SLICE: &str = "/sys/fs/cgroup/user.slice";
const CGROUP_NAME_PREFIX: &str = "heimdall-cli-";
/// Maximum directory depth to traverse below `/sys/fs/cgroup/user.slice/`.
/// `user-<UID>.slice/user@<UID>.service/app.slice/heimdall-cli-*/` is 4
/// levels; `+1` to descend into the heimdall-cli dir itself when
/// checking `cgroup.events`. Keeps the walk linear.
const MAX_DEPTH: usize = 6;

pub fn spawn(
    cli_overrides: CliOverrides,
    policy_engine: Arc<parking_lot::Mutex<Option<Arc<PolicyEngine>>>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(GC_INTERVAL);
        // First tick fires immediately; skip it so we don't race the
        // initial register-from-API window during `heimdall run` warm-up.
        interval.tick().await;
        loop {
            interval.tick().await;
            let engine_snap = policy_engine.lock().clone();
            match gc_pass(&cli_overrides, engine_snap.as_deref()).await {
                Ok(0) => debug!("gc: no orphans"),
                Ok(n) => info!(removed = n, "gc: cleaned orphan heimdall-cli cgroups"),
                Err(e) => warn!(error = %e, "gc: pass failed"),
            }
        }
    });
}

async fn gc_pass(overrides: &CliOverrides, engine: Option<&PolicyEngine>) -> Result<usize> {
    let candidates = find_cgroups(Path::new(USER_SLICE))?;
    debug!(found = candidates.len(), "gc: walked user.slice");
    let mut removed = 0;

    for path in candidates {
        // Skip if cgroup still has live processes.
        match read_populated(&path) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                debug!(error = %e, path = %path.display(), "gc: read populated failed; skipping");
                continue;
            }
        }

        // cgroup_id is the inode of the directory in cgroupfs (cgroup v2).
        let cgroup_id = match std::fs::metadata(&path) {
            Ok(m) => m.ino(),
            Err(e) => {
                debug!(error = %e, path = %path.display(), "gc: stat failed");
                continue;
            }
        };

        // Userspace map first so the relay can't resolve against this
        // entry while we're tearing it down. (Mirror of api.rs DELETE.)
        overrides.write().remove(&cgroup_id);
        if let Some(engine) = engine {
            if let Err(e) = engine.deregister_external(cgroup_id).await {
                debug!(cgroup_id, error = %e, "gc: deregister_external failed");
            }
        }

        match std::fs::remove_dir(&path) {
            Ok(_) => {
                info!(cgroup_id, path = %path.display(), "gc: reaped orphan cgroup");
                removed += 1;
            }
            Err(e) => {
                // EBUSY usually means a process raced into the cgroup
                // between populated check and rmdir. Leave it; next GC
                // pass tries again.
                debug!(error = %e, path = %path.display(), "gc: rmdir failed (will retry)");
            }
        }
    }
    Ok(removed)
}

/// Depth-first walk under `root` looking for directories whose name
/// starts with `heimdall-cli-`. Returns the matched paths; doesn't
/// recurse into them (heimdall-cli cgroups don't have heimdall-cli
/// children). Errors at individual entries are swallowed so one
/// permission-denied subdir doesn't tank the whole pass.
fn find_cgroups(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    walk(root, 0, &mut out);
    Ok(out)
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth >= MAX_DEPTH {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name.starts_with(CGROUP_NAME_PREFIX) {
            out.push(path);
            // Don't descend; heimdall-cli cgroups don't nest.
        } else {
            walk(&path, depth + 1, out);
        }
    }
}

fn read_populated(cgroup_dir: &Path) -> Result<bool> {
    let events = std::fs::read_to_string(cgroup_dir.join("cgroup.events"))
        .with_context(|| format!("read {}/cgroup.events", cgroup_dir.display()))?;
    for line in events.lines() {
        if let Some(rest) = line.strip_prefix("populated ") {
            return Ok(rest.trim() == "1");
        }
    }
    // Old kernels without "populated" — assume populated to be safe.
    Ok(true)
}
