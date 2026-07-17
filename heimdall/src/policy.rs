//! PolicyEngine — keeps the eBPF CGROUP_POLICY map in sync with the
//! routing rules in the config + the live UnitResolver.
//!
//! The eBPF kernel programs (connect4, emit_tap, emit_tap_ret) read
//! a single byte of policy flags per cgroup_id to decide whether to
//! redirect / observe / log. This module is the *only* writer of that
//! map; everything else just reads via eBPF.
//!
//! Two triggers drive a re-eval:
//!
//!   1. An initial reconcile at startup so units already running when
//!      the daemon came up get their policy applied before traffic
//!      ramps up.
//!   2. A periodic reconcile tick — picks up new units (the resolver
//!      rescans the cgroup tree each pass) and any config-implied
//!      changes.
//!
//! The reconcile loop is intentionally simple: snapshot the resolver,
//! evaluate every cgroup, write the resulting flags. The whole cycle
//! is O(cgroups) and runs in milliseconds — premature optimization not
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
use heimdall_config::{Decision, HeimdallConfig, SYSTEM_TAG};
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::router;
use crate::unit::UnitResolver;

/// Period between full-reconcile passes. Five seconds is fast enough
/// that a new unit's cgroup is picked up before its first TLS handshake
/// completes in most cases, and slow enough that the work is a rounding
/// error vs the relay's normal load.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

pub type CgroupPolicyMap = BpfHashMap<aya::maps::MapData, u64, u8>;

pub struct PolicyEngine {
    cfg: Arc<HeimdallConfig>,
    units: Arc<UnitResolver>,
    /// We own the BPF map exclusively while the engine is running. No
    /// other code path writes to it; readers just use the eBPF helper.
    map: Arc<tokio::sync::Mutex<CgroupPolicyMap>>,
    /// Last-known flags-per-cgroup, keyed by cgroup_id. Used to skip
    /// no-op writes and to detect entries that should be removed
    /// because the unit is gone.
    last: Arc<RwLock<StdHashMap<u64, u8>>>,
    /// Cgroup IDs registered via `register_external` (i.e. by
    /// `heimdall run` through the HTTP API). The reconcile loop
    /// MUST NOT delete these — they're owned by the external caller,
    /// who'll deregister explicitly. Without this set, every
    /// reconcile pass would treat them as stale and wipe them from
    /// CGROUP_POLICY.
    external: Arc<RwLock<HashSet<u64>>>,
}

impl PolicyEngine {
    pub fn new(cfg: Arc<HeimdallConfig>, units: Arc<UnitResolver>, map: CgroupPolicyMap) -> Self {
        Self {
            cfg,
            units,
            map: Arc::new(tokio::sync::Mutex::new(map)),
            last: Arc::new(RwLock::new(StdHashMap::new())),
            external: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Spawn the engine. Runs forever; reconciles once immediately and
    /// then on a 5-second interval.
    pub fn spawn(self: Arc<Self>) {
        // Drive an initial reconcile right away so any units already
        // running on startup get their policy applied before traffic
        // ramps up.
        {
            let me = self.clone();
            tokio::spawn(async move {
                me.reconcile().await;
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

    /// Full reconcile pass: rescan cgroups, evaluate every unit, apply
    /// missing/changed entries, drop stale ones. Cheap (~ms) and
    /// idempotent.
    async fn reconcile(&self) {
        self.units.rescan();
        let cgroup_snap = self.units.snapshot();

        // For each known cgroup_id, compute desired flags from the
        // unit identity its path implies.
        let mut desired: StdHashMap<u64, u8> = StdHashMap::new();
        for (cg, info) in &cgroup_snap {
            let dec = router::resolve_decision(&self.cfg, Some(info));
            desired.insert(*cg, encode(&dec));
        }

        // Diff against last-known and apply.
        let mut writes = 0usize;
        let mut deletes = 0usize;
        {
            let prev = self.last.read().clone();
            for (cg, flags) in &desired {
                if prev.get(cg) != Some(flags) {
                    match self.write_one(*cg, *flags).await {
                        Err(e) => {
                            warn!(cgroup = cg, error = %e, "policy: write failed");
                        }
                        _ => {
                            writes += 1;
                        }
                    }
                }
            }
            // Drop entries we used to manage but no longer want to.
            // Externally-managed cgroups (registered via `heimdall run`
            // / POST /api/cli/register) are SKIPPED — their owner
            // calls deregister explicitly; reconcile shouldn't race
            // against that lifecycle.
            let alive: HashSet<u64> = desired.keys().copied().collect();
            let external = self.external.read().clone();
            for cg in prev.keys() {
                if !alive.contains(cg) && !external.contains(cg) {
                    match self.delete_one(*cg).await {
                        Err(e) => {
                            debug!(cgroup = cg, error = %e, "policy: delete failed");
                        }
                        _ => {
                            deletes += 1;
                        }
                    }
                }
            }
        }

        if writes > 0 || deletes > 0 {
            info!(
                writes,
                deletes,
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
    /// byte from a `Decision`. Used by the HTTP register endpoints
    /// that drive `heimdall run` — they own the userspace
    /// cli_overrides map; this method keeps the eBPF map in lockstep.
    /// Marks the cgroup_id as externally managed so the periodic
    /// reconcile pass doesn't wipe it.
    ///
    /// `dns_hijack=true` ORs in `POLICY_DNS_HIJACK` so eBPF redirects
    /// :53 traffic to heimdall's fake-IP DNS server. Used by
    /// `heimdall run` invocations whose profile resolves to
    /// `dns: fake`; the per-unit reconcile path never sets this bit.
    pub async fn register_external(
        &self,
        cgroup_id: u64,
        decision: &Decision,
        dns_hijack: bool,
    ) -> Result<()> {
        let mut flags = encode(decision);
        if dns_hijack {
            flags |= heimdall_common::POLICY_DNS_HIJACK;
        }
        self.external.write().insert(cgroup_id);
        self.write_one(cgroup_id, flags).await
    }

    /// External-facing wrapper for clearing a previously registered
    /// cgroup. Removes the external-marker too so a re-used cgroup_id
    /// (e.g. inode reuse after rmdir) is back under reconcile's
    /// control. Idempotent — a missing key is treated as success.
    pub async fn deregister_external(&self, cgroup_id: u64) -> Result<()> {
        self.external.write().remove(&cgroup_id);
        self.delete_one(cgroup_id).await
    }
}

/// Map a routing decision to the eBPF policy byte.
///
/// The bit layout matches `heimdall-common::POLICY_*`:
///   - `use: system`     → REDIRECT_OFF
///   - `observe: false`  → OBSERVE_OFF + NO_BYPASS_LOG (no synthetic flow)
fn encode(d: &Decision) -> u8 {
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
        let d = Decision {
            use_: "default".into(),
            observe: true,
        };
        assert_eq!(encode(&d), 0);
    }

    #[test]
    fn encode_system_use_sets_redirect_off() {
        let d = Decision {
            use_: "system".into(),
            observe: true,
        };
        assert_eq!(encode(&d), POLICY_REDIRECT_OFF);
    }

    #[test]
    fn encode_observe_off_sets_observe_and_no_bypass_log() {
        let d = Decision {
            use_: "default".into(),
            observe: false,
        };
        assert_eq!(encode(&d), POLICY_OBSERVE_OFF | POLICY_NO_BYPASS_LOG);
    }

    #[test]
    fn encode_system_with_no_observe_combines() {
        let d = Decision {
            use_: "system".into(),
            observe: false,
        };
        assert_eq!(
            encode(&d),
            POLICY_REDIRECT_OFF | POLICY_OBSERVE_OFF | POLICY_NO_BYPASS_LOG
        );
    }
}
