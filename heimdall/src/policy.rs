//! PolicyEngine — keeps the eBPF CGROUP_POLICY map in sync with the
//! routing rules in `config.yaml` + the live PodInformer + CgroupResolver.
//!
//! The eBPF kernel programs (connect4, emit_tap, emit_tap_ret) read
//! a single byte of policy flags per cgroup_id to decide whether to
//! redirect / observe / log. This module is the *only* writer of that
//! map; everything else just reads via eBPF.
//!
//! Three triggers drive a re-eval:
//!
//!   1. PodInformer event (Upsert / Delete / InitDone) — handled live
//!      so an annotation flip takes effect within seconds.
//!   2. Periodic reconcile tick — covers the case where a pod's
//!      cgroup_id appeared between informer events (kubelet creates
//!      cgroups slightly out-of-band with the API server's pod state).
//!   3. Initial bootstrap once the daemon has both informer + cgroup
//!      data ready.
//!
//! The reconcile loop is intentionally simple: snapshot both sources,
//! evaluate every pod, write the resulting flags. The whole cycle is
//! O(pods) and runs in milliseconds — premature optimization not
//! warranted.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use heimdall_common::{
    DEFAULT_POLICY, POLICY_NO_BYPASS_LOG, POLICY_OBSERVE_OFF, POLICY_REDIRECT_OFF,
};
use heimdall_config::{HeimdallConfig, PodDecision, SYSTEM_TAG};
use parking_lot::RwLock;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, info, warn};

use crate::pod::{CgroupResolver, PodEvent, PodInfo, PodInformer};
use crate::router;

/// Period between full-reconcile passes. Five seconds is fast enough
/// that a new pod's cgroup is picked up before its first TLS handshake
/// completes in most cases, and slow enough that the work is a rounding
/// error vs the relay's normal load.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

pub type CgroupPolicyMap = BpfHashMap<aya::maps::MapData, u64, u8>;

pub struct PolicyEngine {
    cfg: Arc<HeimdallConfig>,
    informer: Arc<PodInformer>,
    cgroups: Arc<CgroupResolver>,
    /// We own the BPF map exclusively while the engine is running. No
    /// other code path writes to it; readers just use the eBPF helper.
    map: Arc<tokio::sync::Mutex<CgroupPolicyMap>>,
    /// Last-known flags-per-cgroup, keyed by cgroup_id. Used to skip
    /// no-op writes and to detect entries that should be removed
    /// because the pod is gone.
    last: Arc<RwLock<StdHashMap<u64, u8>>>,
}

impl PolicyEngine {
    pub fn new(
        cfg: Arc<HeimdallConfig>,
        informer: Arc<PodInformer>,
        cgroups: Arc<CgroupResolver>,
        map: CgroupPolicyMap,
    ) -> Self {
        Self {
            cfg,
            informer,
            cgroups,
            map: Arc::new(tokio::sync::Mutex::new(map)),
            last: Arc::new(RwLock::new(StdHashMap::new())),
        }
    }

    /// Spawn the engine. Runs forever; reconciles on every PodEvent and
    /// on a 5-second interval.
    pub fn spawn(self: Arc<Self>) {
        let mut events = self.informer.subscribe();

        // Drive an initial reconcile right away so any pods the informer
        // already saw on startup get their policy applied before traffic
        // ramps up.
        {
            let me = self.clone();
            tokio::spawn(async move {
                me.reconcile().await;
            });
        }

        // Event-driven re-eval.
        {
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(PodEvent::Upsert(info)) => me.apply_pod(&info).await,
                        Ok(PodEvent::Delete(uid)) => me.remove_pod(&uid).await,
                        Ok(PodEvent::InitDone) => me.reconcile().await,
                        Err(RecvError::Lagged(n)) => {
                            warn!(skipped = n, "policy: lagged behind pod events; full reconcile");
                            me.reconcile().await;
                        }
                        Err(RecvError::Closed) => return,
                    }
                }
            });
        }

        // Periodic full reconcile.
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(RECONCILE_INTERVAL);
            tick.tick().await; // skip the immediate first tick
            loop {
                tick.tick().await;
                self.reconcile().await;
            }
        });
    }

    /// Re-eval one pod and write its cgroup_ids' policy. Used on Upsert.
    async fn apply_pod(&self, info: &PodInfo) {
        let decision = router::resolve_pod_decision(&self.cfg, Some(info));
        let flags = encode(&decision);

        let cgs = self.cgroups.uid_to_cgroups(&info.uid);
        if cgs.is_empty() {
            // CgroupResolver hasn't seen this pod yet — kubelet may not
            // have created the cgroup, or our scan is stale. The next
            // reconcile tick will cover it.
            return;
        }
        for cg in cgs {
            if let Err(e) = self.write_one(cg, flags).await {
                warn!(cgroup = cg, error = %e, "policy: write failed");
            }
        }
    }

    /// Remove all cgroup entries for a deleted pod. The kernel may have
    /// already reused the cgroup_id by the time we get here, so absent
    /// entries are not an error.
    async fn remove_pod(&self, uid: &str) {
        let cgs = self.cgroups.uid_to_cgroups(uid);
        for cg in cgs {
            if let Err(e) = self.delete_one(cg).await {
                debug!(cgroup = cg, error = %e, "policy: delete failed (likely already gone)");
            }
        }
    }

    /// Full reconcile pass: rescan cgroups, evaluate every pod, apply
    /// missing/changed entries, drop stale ones. Cheap (~ms) and
    /// idempotent.
    async fn reconcile(&self) {
        self.cgroups.rescan();
        let cgroup_snap = self.cgroups.snapshot();
        let pod_snap = self.informer.snapshot();

        // Build uid → flags from current rules + pod info.
        let pod_flags: StdHashMap<String, u8> = pod_snap
            .into_iter()
            .map(|(uid, info)| {
                let dec = router::resolve_pod_decision(&self.cfg, Some(&info));
                (uid, encode(&dec))
            })
            .collect();

        // For each known cgroup_id, compute desired flags. If the pod is
        // unknown to the informer we leave the entry out of the desired
        // set entirely — eBPF DEFAULT_POLICY (observe OFF) takes over,
        // which is the safer default for new/unknown cgroups.
        let mut desired: StdHashMap<u64, u8> = StdHashMap::new();
        for (cg, uid) in &cgroup_snap {
            if let Some(flags) = pod_flags.get(uid) {
                desired.insert(*cg, *flags);
            }
        }

        // Diff against last-known and apply.
        let mut writes = 0usize;
        let mut deletes = 0usize;
        {
            let prev = self.last.read().clone();
            for (cg, flags) in &desired {
                if prev.get(cg) != Some(flags) {
                    if let Err(e) = self.write_one(*cg, *flags).await {
                        warn!(cgroup = cg, error = %e, "policy: write failed");
                    } else {
                        writes += 1;
                    }
                }
            }
            // Drop entries we used to manage but no longer want to.
            let alive: HashSet<u64> = desired.keys().copied().collect();
            for cg in prev.keys() {
                if !alive.contains(cg) {
                    if let Err(e) = self.delete_one(*cg).await {
                        debug!(cgroup = cg, error = %e, "policy: delete failed");
                    } else {
                        deletes += 1;
                    }
                }
            }
        }

        if writes > 0 || deletes > 0 {
            info!(
                writes,
                deletes,
                pods = pod_flags.len(),
                cgroups = cgroup_snap.len(),
                "policy: reconciled"
            );
        }
    }

    async fn write_one(&self, cg: u64, flags: u8) -> Result<()> {
        let mut m = self.map.lock().await;
        m.insert(cg, flags, 0)
            .with_context(|| format!("CGROUP_POLICY.insert({cg}, {flags:#x})"))?;
        drop(m);
        self.last.write().insert(cg, flags);
        Ok(())
    }

    async fn delete_one(&self, cg: u64) -> Result<()> {
        let mut m = self.map.lock().await;
        let _ = m.remove(&cg);
        drop(m);
        self.last.write().remove(&cg);
        Ok(())
    }

    /// External-facing wrapper for writing a single cgroup's policy
    /// byte from a `PodDecision`. Used by the HTTP register endpoints
    /// that drive `heimdall run` — they own the userspace
    /// cli_overrides map; this method keeps the eBPF map in lockstep.
    pub async fn register_external(&self, cgroup_id: u64, decision: &PodDecision) -> Result<()> {
        let flags = encode(decision);
        self.write_one(cgroup_id, flags).await
    }

    /// External-facing wrapper for clearing a previously registered
    /// cgroup. Idempotent — a missing key is treated as success.
    pub async fn deregister_external(&self, cgroup_id: u64) -> Result<()> {
        self.delete_one(cgroup_id).await
    }
}

/// Map a routing decision to the eBPF policy byte.
///
/// The bit layout matches `heimdall-common::POLICY_*`:
///   - `use: system`     → REDIRECT_OFF
///   - `observe: false`  → OBSERVE_OFF + NO_BYPASS_LOG (no synthetic flow)
fn encode(d: &PodDecision) -> u8 {
    let mut flags = 0u8;
    if d.use_ == SYSTEM_TAG {
        flags |= POLICY_REDIRECT_OFF;
    }
    if !d.observe {
        flags |= POLICY_OBSERVE_OFF | POLICY_NO_BYPASS_LOG;
    }
    flags
}

/// Used by the daemon to confirm the engine is hooked up correctly —
/// returns the same constant the eBPF programs see on a map miss.
#[allow(dead_code)]
pub fn default_policy_byte() -> u8 {
    DEFAULT_POLICY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_default_uses_proxy_and_observe() {
        let d = PodDecision { use_: "default".into(), observe: true };
        assert_eq!(encode(&d), 0);
    }

    #[test]
    fn encode_system_use_sets_redirect_off() {
        let d = PodDecision { use_: "system".into(), observe: true };
        assert_eq!(encode(&d), POLICY_REDIRECT_OFF);
    }

    #[test]
    fn encode_observe_off_sets_observe_and_no_bypass_log() {
        let d = PodDecision { use_: "default".into(), observe: false };
        assert_eq!(encode(&d), POLICY_OBSERVE_OFF | POLICY_NO_BYPASS_LOG);
    }

    #[test]
    fn encode_system_with_no_observe_combines() {
        let d = PodDecision { use_: "system".into(), observe: false };
        assert_eq!(
            encode(&d),
            POLICY_REDIRECT_OFF | POLICY_OBSERVE_OFF | POLICY_NO_BYPASS_LOG
        );
    }
}
