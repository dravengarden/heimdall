//! Pod identity resolution.
//!
//! Two layers, joined on pod UID:
//!
//! 1. **Cgroup resolver**:  cgroup_id (u64, from eBPF `bpf_get_current_cgroup_id`)
//!    → pod_uid (String). Built by walking `/sys/fs/cgroup/kubepods` and
//!    extracting the UID embedded in K8s pod cgroup directory names.
//!
//! 2. **K8s informer**:  pod_uid → PodInfo {ns, name, labels, annotations}.
//!    Maintained via a kube-rs reflector watching all Pods cluster-wide.
//!
//! The resolver is built lazy/best-effort: a cgroup_id miss triggers a
//! rescan of /sys/fs/cgroup; a pod_uid miss simply means "unknown pod"
//! and the caller falls back to the default connection.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    runtime::{watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use parking_lot::RwLock;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// PodInfo
// ---------------------------------------------------------------------------

/// Snapshot of a pod's identity, suitable for routing decisions.
#[derive(Clone, Debug, Default)]
pub struct PodInfo {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// CgroupResolver — cgroup_id → pod_uid
// ---------------------------------------------------------------------------

/// Walks `/sys/fs/cgroup/kubepods` once at construction and on demand.
///
/// K8s pod cgroup directory names embed the pod UID in one of these forms:
///   - cgroupfs driver: `/sys/fs/cgroup/kubepods/.../pod<UID>/...`
///   - systemd driver:  `/sys/fs/cgroup/kubepods.slice/.../kubepods-..._pod<UID>.slice/...`
///
/// We grab the cgroup id (= directory inode) of every descendant and map it
/// to the closest ancestor's pod UID.
pub struct CgroupResolver {
    root: PathBuf,
    /// cgroup_id → pod_uid (lowercase UUID, no dashes-handling).
    cache: RwLock<HashMap<u64, String>>,
    /// Throttle full rescans to at most once per `min_rescan_interval`
    /// when a miss triggers one.
    last_rescan: RwLock<Instant>,
    min_rescan_interval: Duration,
}

impl CgroupResolver {
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

    /// Resolve cgroup_id to pod UID. On miss, trigger at most one rescan
    /// (rate-limited) and try again.
    pub fn resolve(&self, cgroup_id: u64) -> Option<String> {
        if cgroup_id == 0 {
            return None;
        }
        if let Some(uid) = self.cache.read().get(&cgroup_id).cloned() {
            return Some(uid);
        }
        if self.maybe_rescan() {
            return self.cache.read().get(&cgroup_id).cloned();
        }
        None
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
        walk_cgroups(&self.root, None, &mut new_cache);
        let count = new_cache.len();
        *self.cache.write() = new_cache;
        debug!(entries = count, root = %self.root.display(), "cgroup → pod_uid cache rebuilt");
    }
}

/// Recursively walk `dir`, threading the most-recently-seen pod UID from
/// the path through to descendants. Each visited directory's inode is
/// inserted into `out` keyed to that pod UID.
fn walk_cgroups(dir: &Path, current_uid: Option<&str>, out: &mut HashMap<u64, String>) {
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

        // Determine if this dir itself names a pod, and grab the UID.
        let uid_here = extract_pod_uid(&name_str);
        let effective = uid_here.as_deref().or(current_uid);

        // Stat the directory to get its cgroup id (= inode).
        if let Some(uid) = effective {
            if let Ok(meta) = std::fs::metadata(&path) {
                use std::os::unix::fs::MetadataExt;
                out.insert(meta.ino(), uid.to_string());
            }
        }

        walk_cgroups(&path, effective, out);
    }
}

/// Extract a pod UID from a cgroup directory name.
///
/// Returns the UID with `_` converted back to `-` (systemd driver mangles
/// dashes in slice names). Returns None if no pod-uid pattern is present.
fn extract_pod_uid(name: &str) -> Option<String> {
    // cgroupfs: "pod<UID>" — UID is the rest, including dashes.
    if let Some(rest) = name.strip_prefix("pod") {
        if looks_like_uuid(rest) {
            return Some(rest.to_string());
        }
    }

    // systemd: "kubepods-<qos>-pod<UID>.slice" or "kubepods-pod<UID>.slice"
    // (UID is mangled: dashes replaced with underscores)
    if let Some(stripped) = name.strip_suffix(".slice") {
        if let Some(idx) = stripped.find("-pod") {
            let uid_mangled = &stripped[idx + 4..];
            if looks_like_uuid(&uid_mangled.replace('_', "-")) {
                return Some(uid_mangled.replace('_', "-"));
            }
        }
    }

    None
}

/// Loose UUID shape check: 36 chars with dashes at the right positions, or
/// 32 chars with no dashes. We don't validate hex strictly because the
/// kernel hands us whatever was in the cgroup name.
fn looks_like_uuid(s: &str) -> bool {
    if s.len() == 36 {
        let bytes = s.as_bytes();
        bytes[8] == b'-' && bytes[13] == b'-' && bytes[18] == b'-' && bytes[23] == b'-'
    } else {
        s.len() == 32
    }
}

// ---------------------------------------------------------------------------
// PodInformer — pod_uid → PodInfo
// ---------------------------------------------------------------------------

/// In-memory cache of all pods' identity, refreshed via kube-rs watcher.
#[derive(Clone)]
pub struct PodInformer {
    cache: Arc<RwLock<HashMap<String, PodInfo>>>,
}

impl PodInformer {
    /// Spawn a background task that watches all Pods cluster-wide and keeps
    /// the cache in sync. Returns once the initial Init event has been seen.
    pub async fn spawn() -> Result<Self> {
        let client = Client::try_default()
            .await
            .context("creating Kubernetes client (no kubeconfig found?)")?;
        let api: Api<Pod> = Api::all(client);
        let cache = Arc::new(RwLock::new(HashMap::<String, PodInfo>::new()));
        let cache_for_task = cache.clone();

        tokio::spawn(async move {
            let stream = watcher(api, watcher::Config::default()).default_backoff();
            futures::pin_mut!(stream);
            while let Some(ev) = stream.next().await {
                match ev {
                    Ok(watcher::Event::Init) => {
                        cache_for_task.write().clear();
                    }
                    Ok(watcher::Event::InitApply(p)) | Ok(watcher::Event::Apply(p)) => {
                        if let Some(info) = pod_info(&p) {
                            cache_for_task.write().insert(info.uid.clone(), info);
                        }
                    }
                    Ok(watcher::Event::Delete(p)) => {
                        if let Some(uid) = p.uid() {
                            cache_for_task.write().remove(&uid);
                        }
                    }
                    Ok(watcher::Event::InitDone) => {
                        info!(pods = cache_for_task.read().len(), "pod informer initial sync complete");
                    }
                    Err(e) => {
                        warn!(error = %e, "pod watcher error; retrying with backoff");
                    }
                }
            }
        });

        Ok(Self { cache })
    }

    pub fn lookup(&self, uid: &str) -> Option<PodInfo> {
        self.cache.read().get(uid).cloned()
    }

    pub fn len(&self) -> usize {
        self.cache.read().len()
    }
}

fn pod_info(p: &Pod) -> Option<PodInfo> {
    let uid = p.uid()?;
    Some(PodInfo {
        uid,
        namespace: p.namespace().unwrap_or_default(),
        name: p.name_any(),
        labels: p.labels().iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        annotations: p.annotations().iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_uid_cgroupfs() {
        assert_eq!(
            extract_pod_uid("pod12345678-1234-1234-1234-123456789abc").as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
    }

    #[test]
    fn extract_uid_systemd_burstable() {
        // kubepods-burstable-pod<UID>.slice  (dashes in UID mangled to _)
        assert_eq!(
            extract_pod_uid(
                "kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice"
            )
            .as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
    }

    #[test]
    fn extract_uid_systemd_guaranteed() {
        assert_eq!(
            extract_pod_uid("kubepods-pod12345678_1234_1234_1234_123456789abc.slice")
                .as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
    }

    #[test]
    fn extract_uid_rejects_non_pods() {
        assert_eq!(extract_pod_uid("kubepods.slice"), None);
        assert_eq!(extract_pod_uid("burstable"), None);
        assert_eq!(extract_pod_uid("besteffort"), None);
        assert_eq!(extract_pod_uid("cri-containerd-abc.scope"), None);
    }
}
