//! systemd unit identity resolution.
//!
//! Maps cgroup_id (u64, from eBPF `bpf_get_current_cgroup_id`) to the
//! systemd identity heimdall routes on: the leaf unit (`*.service` /
//! `*.scope`) and the enclosing slice (`*.slice`). Both are read
//! straight from the cgroup v2 directory hierarchy — systemd encodes
//! the unit name in the path, so no API or informer is needed.
//!
//! The resolver walks `/sys/fs/cgroup` once at construction and on
//! demand: a `cgroup_id` miss triggers a rate-limited rescan, and the
//! policy engine drives an explicit rescan every reconcile tick so
//! unit churn is picked up promptly.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use tracing::debug;

// ---------------------------------------------------------------------------
// UnitInfo
// ---------------------------------------------------------------------------

/// The systemd identity derived from a process's cgroup path. Suitable
/// for routing decisions and flow tagging.
#[derive(Clone, Debug, Default)]
pub struct UnitInfo {
    /// Leaf unit name, e.g. `nginx.service` or a transient `*.scope`.
    /// None for a bare slice cgroup with no unit below it.
    pub unit: Option<String>,
    /// Nearest enclosing slice, e.g. `system.slice`, `user.slice`.
    pub slice: Option<String>,
}

impl UnitInfo {
    /// Human label for logs: `slice/unit`, or whichever half exists.
    pub fn label(&self) -> String {
        match (&self.slice, &self.unit) {
            (Some(s), Some(u)) => format!("{s}/{u}"),
            (_, Some(u)) => u.clone(),
            (Some(s), None) => s.clone(),
            (None, None) => "unknown".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// UnitResolver — cgroup_id → UnitInfo
// ---------------------------------------------------------------------------

/// Walks `/sys/fs/cgroup` once at construction and on demand, mapping
/// every cgroup directory's inode (== cgroup_id in cgroup v2) to the
/// `UnitInfo` implied by its path.
pub struct UnitResolver {
    root: PathBuf,
    cache: RwLock<HashMap<u64, UnitInfo>>,
    /// Throttle full rescans to at most once per `min_rescan_interval`
    /// when a miss triggers one.
    last_rescan: RwLock<Instant>,
    min_rescan_interval: Duration,
}

impl UnitResolver {
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let res = Self {
            root,
            cache: RwLock::new(HashMap::new()),
            last_rescan: RwLock::new(Instant::now() - Duration::from_secs(60)),
            min_rescan_interval: Duration::from_millis(500),
        };
        res.scan();
        res
    }

    /// Resolve cgroup_id to its unit identity. On miss, trigger at most
    /// one rescan (rate-limited) and try again.
    pub fn resolve(&self, cgroup_id: u64) -> Option<UnitInfo> {
        if cgroup_id == 0 {
            return None;
        }
        if let Some(info) = self.cache.read().get(&cgroup_id).cloned() {
            return Some(info);
        }
        if self.maybe_rescan() {
            return self.cache.read().get(&cgroup_id).cloned();
        }
        None
    }

    /// Snapshot of every (cgroup_id, UnitInfo) entry currently cached.
    /// The policy engine reconcile pass and the bootstrap scan iterate
    /// this.
    pub fn snapshot(&self) -> Vec<(u64, UnitInfo)> {
        self.cache
            .read()
            .iter()
            .map(|(cg, info)| (*cg, info.clone()))
            .collect()
    }

    /// Force a fresh scan, bypassing the rate limit. The policy engine
    /// runs this on every reconcile tick so cgroup churn is picked up
    /// without waiting for a `resolve()` miss to trigger it.
    pub fn rescan(&self) {
        *self.last_rescan.write() = Instant::now();
        self.scan();
    }

    /// Rescan if enough time has elapsed; returns true if we did.
    fn maybe_rescan(&self) -> bool {
        let now = Instant::now();
        {
            let last = self.last_rescan.read();
            if now.duration_since(*last) < self.min_rescan_interval {
                return false;
            }
        }
        *self.last_rescan.write() = now;
        self.scan();
        true
    }

    fn scan(&self) {
        let mut new_cache = HashMap::new();
        walk_cgroups(&self.root, None, None, &mut new_cache);
        let count = new_cache.len();
        *self.cache.write() = new_cache;
        debug!(entries = count, root = %self.root.display(), "cgroup → unit cache rebuilt");
    }
}

/// Recursively walk `dir`, threading the nearest enclosing slice and
/// unit through to descendants. Each visited directory's inode is
/// inserted into `out` with the `UnitInfo` its path implies.
fn walk_cgroups(
    dir: &Path,
    slice: Option<&str>,
    unit: Option<&str>,
    out: &mut HashMap<u64, UnitInfo>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // systemd encodes identity in the directory suffix. A `.slice`
        // dir updates the enclosing slice; a `.service` / `.scope` dir
        // names the leaf unit. Anything else (e.g. cgroup controller
        // subdirs) inherits the parent's context unchanged.
        let this_slice = if name_str.ends_with(".slice") {
            Some(name_str.as_ref())
        } else {
            slice
        };
        let this_unit = if name_str.ends_with(".service") || name_str.ends_with(".scope") {
            Some(name_str.as_ref())
        } else {
            unit
        };

        if let Ok(meta) = std::fs::metadata(&path) {
            use std::os::unix::fs::MetadataExt;
            out.insert(
                meta.ino(),
                UnitInfo {
                    unit: this_unit.map(String::from),
                    slice: this_slice.map(String::from),
                },
            );
        }

        walk_cgroups(&path, this_slice, this_unit, out);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Build a small cgroup-like tree under a tempdir and confirm the
    /// walker derives the right unit/slice per directory inode.
    #[test]
    fn walk_derives_unit_and_slice() {
        let tmp = std::env::temp_dir().join(format!("heimdall-unit-test-{}", std::process::id()));
        let system = tmp.join("system.slice");
        let svc = system.join("nginx.service");
        let nested = system.join("system-getty.slice").join("getty@tty1.service");
        std::fs::create_dir_all(&svc).unwrap();
        std::fs::create_dir_all(&nested).unwrap();

        let mut out = HashMap::new();
        walk_cgroups(&tmp, None, None, &mut out);

        let svc_ino = std::fs::metadata(&svc).unwrap().ino();
        let info = out.get(&svc_ino).expect("nginx.service present");
        assert_eq!(info.unit.as_deref(), Some("nginx.service"));
        assert_eq!(info.slice.as_deref(), Some("system.slice"));

        let nested_ino = std::fs::metadata(&nested).unwrap().ino();
        let ninfo = out.get(&nested_ino).expect("getty present");
        assert_eq!(ninfo.unit.as_deref(), Some("getty@tty1.service"));
        assert_eq!(ninfo.slice.as_deref(), Some("system-getty.slice"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn label_formats() {
        let u = UnitInfo {
            unit: Some("nginx.service".into()),
            slice: Some("system.slice".into()),
        };
        assert_eq!(u.label(), "system.slice/nginx.service");
        assert_eq!(UnitInfo::default().label(), "unknown");
    }
}
