//! BPF policy registry owned by `heimdall run`.
//!
//! There is no host-wide reconciliation loop. A cgroup enters the map when
//! the CLI registers it and leaves when the CLI exits or orphan GC reaps it.

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use heimdall_common::{POLICY_DNS_HIJACK, POLICY_DNS_SYSTEM, POLICY_UDP_REJECT};

pub type CgroupPolicyMap = BpfHashMap<aya::maps::MapData, u64, u8>;

pub struct PolicyEngine {
    map: tokio::sync::Mutex<CgroupPolicyMap>,
}

impl PolicyEngine {
    pub fn new(map: CgroupPolicyMap) -> Self {
        Self {
            map: tokio::sync::Mutex::new(map),
        }
    }

    pub async fn register_external(
        &self,
        cgroup_id: u64,
        dns_hijack: bool,
        system_dns: bool,
        reject_udp: bool,
    ) -> Result<()> {
        let mut flags = 0;
        if dns_hijack {
            flags |= POLICY_DNS_HIJACK;
        }
        if system_dns {
            flags |= POLICY_DNS_SYSTEM;
        }
        if reject_udp {
            flags |= POLICY_UDP_REJECT;
        }
        self.map
            .lock()
            .await
            .insert(cgroup_id, flags, 0)
            .with_context(|| format!("write policy for cgroup {cgroup_id}"))
    }

    pub async fn deregister_external(&self, cgroup_id: u64) -> Result<()> {
        self.map
            .lock()
            .await
            .remove(&cgroup_id)
            .with_context(|| format!("remove policy for cgroup {cgroup_id}"))
    }
}
