//! Phase B — synthetic flows for bypassed connections.
//!
//! The relay only sees connections it actively redirects. Pod traffic
//! to addresses inside `is_default_bypass` (loopback, LAN, k0s pod /
//! service CIDR) skips the relay entirely, so plaintext captured by
//! the libssl / Go uprobes for those connections has no flow row to
//! correlate against — every cluster-internal HTTP/2 frame ends up
//! with `flow_id = NULL` in `messages`.
//!
//! This module fixes that by consuming a perf event array that the
//! eBPF connect4 hook fills on bypass. Each event becomes a flow row
//! in the store, tagged with `connection_name = "bypass"` so the UI
//! can distinguish them from real relay flows. The synthetic flow's
//! cgroup_id is also pushed onto the open-flow index so subsequent
//! tap events for that cgroup_id correlate properly.
//!
//! Tradeoffs:
//!  * We never observe a "close" for these connections, so bytes_up
//!    and bytes_down stay at 0 and `ts_end_us` is set to `ts_start_us`
//!    immediately (matching the "instant" semantic). Real flows get
//!    proper byte counts from `copy_bidirectional`.
//!  * The flow row is created on every connect4, even for very
//!    short-lived probes — there's no dedup. That matches the relay's
//!    own "one row per connection" behavior.

use std::{net::Ipv4Addr, sync::Arc};

use anyhow::{Context, Result};
use aya::{maps::AsyncPerfEventArray, util::online_cpus, Ebpf};
use bytes::BytesMut;
use heimdall_common::BypassEvent;
use tracing::{info, warn};

use crate::{
    api::{EventBus, FlowEvent},
    pod::{CgroupResolver, PodInformer, PodInfo},
    store::{FlowFinish, FlowStart, Store},
};

/// Snapshot of state the consumer needs to materialize a synthetic
/// flow. We pass these by Arc rather than threading the whole
/// `Shared` struct here so the dependency direction stays clean
/// (bypass -> store/pod, not bypass -> main).
#[derive(Clone)]
pub struct Deps {
    pub store: Arc<Store>,
    pub events: EventBus,
    pub cgroup_resolver: Option<Arc<CgroupResolver>>,
    pub informer: Option<Arc<PodInformer>>,
    /// Same `open_flows` map shared with the relay; we push synthetic
    /// flow ids here so the tap consumer's correlate() finds them.
    pub open_flows:
        Arc<parking_lot::RwLock<std::collections::HashMap<u64, Vec<i64>>>>,
}

/// Drain BYPASS_EVENTS and create synthetic flow rows. Spawns one
/// task per online CPU; each task owns a perf buffer and forwards
/// decoded events to a single inserter task that serializes writes
/// into the sqlite store.
pub fn start(bpf: &mut Ebpf, deps: Deps) -> Result<usize> {
    let map = bpf
        .take_map("BYPASS_EVENTS")
        .context("BYPASS_EVENTS map not found in eBPF object")?;
    let mut perf: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map)?;

    // Single mpsc channel: many CPU readers, one writer task.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<BypassEvent>(8192);

    let cpus = online_cpus().map_err(|(s, e)| anyhow::anyhow!("online_cpus({s}): {e}"))?;
    let cpu_count = cpus.len();
    for cpu in cpus {
        let buf = perf
            .open(cpu, None)
            .with_context(|| format!("open BYPASS_EVENTS perf buffer on cpu {cpu}"))?;
        let tx = tx.clone();
        tokio::spawn(reader_loop(buf, tx, cpu));
    }
    drop(tx);

    // Single inserter — keeps writes ordered and avoids contention on
    // the sqlite pool. This is fine: with ~3 connect/sec across the
    // bypass set on a typical cluster, one writer is plenty.
    let deps = Arc::new(deps);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            insert_one(&deps, ev).await;
        }
        warn!("bypass: inserter stopped (channel closed)");
    });

    Ok(cpu_count)
}

async fn reader_loop(
    mut buf: aya::maps::perf::AsyncPerfEventArrayBuffer<aya::maps::MapData>,
    tx: tokio::sync::mpsc::Sender<BypassEvent>,
    cpu: u32,
) {
    let event_size = std::mem::size_of::<BypassEvent>();
    let mut bufs: Vec<BytesMut> = (0..16)
        .map(|_| BytesMut::with_capacity(event_size))
        .collect();
    loop {
        let events = match buf.read_events(&mut bufs).await {
            Ok(e) => e,
            Err(e) => {
                warn!(cpu, error = %e, "bypass: perf buffer read error, exiting");
                return;
            }
        };
        if events.lost > 0 {
            warn!(cpu, lost = events.lost, "bypass: perf buffer dropped events");
        }
        for slot in bufs.iter_mut().take(events.read) {
            if slot.len() < event_size {
                continue;
            }
            let mut ev: BypassEvent = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    slot.as_ptr(),
                    (&mut ev as *mut BypassEvent) as *mut u8,
                    event_size,
                );
            }
            // Drop on backpressure rather than block the perf reader —
            // a stuck inserter must not stall kernel ring buffers.
            let _ = tx.try_send(ev);
        }
    }
}

async fn insert_one(deps: &Deps, ev: BypassEvent) {
    // Decode dst per family — same dual-stack scheme as OrigDst.
    let (dst_str, atyp) = if ev.family == heimdall_common::FAMILY_V6 {
        let v6 = std::net::Ipv6Addr::from(ev.dst_addr);
        (v6.to_string(), Some("ip6"))
    } else {
        let v4_be = u32::from_ne_bytes([
            ev.dst_addr[0], ev.dst_addr[1], ev.dst_addr[2], ev.dst_addr[3],
        ]);
        let v4 = Ipv4Addr::from(u32::from_be(v4_be));
        (v4.to_string(), Some("ip"))
    };
    let dst_port = u16::from_be(ev.dst_port_be);

    let pod = lookup_pod(deps, ev.cgroup_id);

    let start = FlowStart {
        socket_cookie: Some(ev.socket_cookie),
        cgroup_id: Some(ev.cgroup_id),
        pod_uid: pod.as_ref().map(|p| p.uid.clone()),
        namespace: pod.as_ref().map(|p| p.namespace.clone()),
        pod_name: pod.as_ref().map(|p| p.name.clone()),
        connection_name: "bypass".to_string(),
        dst_host: None,
        dst_ip: dst_str,
        dst_port,
        upstream_addr: None,
        atyp,
    };

    let id = match deps.store.insert_flow_start(start).await {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "bypass: insert_flow_start failed");
            return;
        }
    };

    // Push to the open-flow index so tap events correlate. We never see
    // a close for these — the relay isn't in the data path — so we
    // immediately stamp ts_end_us = ts_start_us with zeroed byte counts
    // to mark the flow as "closed at start" rather than "open forever".
    deps.open_flows
        .write()
        .entry(ev.cgroup_id)
        .or_default()
        .push(id);

    if let Err(e) = deps
        .store
        .finish_flow(
            id,
            FlowFinish {
                bytes_up: 0,
                bytes_down: 0,
                error: None,
            },
        )
        .await
    {
        warn!(error = %e, "bypass: finish_flow failed");
    }

    deps.events.publish(FlowEvent { flow_id: id });
}

fn lookup_pod(deps: &Deps, cgroup_id: u64) -> Option<PodInfo> {
    let cr = deps.cgroup_resolver.as_ref()?;
    let inf = deps.informer.as_ref()?;
    let uid = cr.resolve(cgroup_id)?;
    inf.lookup(&uid)
}

#[allow(dead_code)]
pub fn log_started(cpu_count: usize) {
    info!(cpus = cpu_count, "bypass: synthetic flow consumer started");
}
