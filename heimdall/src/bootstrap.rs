//! Bootstrap synthesis — one-shot scan at startup that creates
//! synthetic flow rows for TCP connections already established when
//! heimdall came up.
//!
//! Why this exists: connect4 only fires on **new** `connect()` calls.
//! Long-lived TLS streams that were already open (rancher's apiserver
//! Watch, controllers' leader-election, kubelet's kubeapi-server
//! connection, etc.) will never produce a bypass event, so plaintext
//! captured by the libssl / Go uprobes from those sockets has
//! `flow_id = NULL` in the messages table.
//!
//! Scan algorithm:
//!
//!   1. Walk `/proc/<pid>/`. For each pid:
//!      - Read `/proc/<pid>/cgroup` → cgroup_id (= inode of the leaf
//!        cgroup directory).
//!      - Skip if cgroup_id is not a known kubepods cgroup OR if the
//!        pod's policy says observe-off.
//!      - Read `/proc/<pid>/net/tcp` (entries are scoped to the pid's
//!        netns; same-netns pids return identical lists).
//!   2. Dedup by `(netns_inode, src_port, dst_addr, dst_port)` so the
//!      same socket isn't synthesized twice when multiple pids share
//!      the netns.
//!   3. For each unique ESTABLISHED v4 outbound socket, insert a flow
//!      row tagged `connection_name = "bootstrap"` and push to the
//!      open-flow index so subsequent tap events correlate.
//!
//! The scan is cheap (a few thousand `read`s on a typical node) and
//! happens once per daemon lifetime. Any subsequent connections go
//! through the normal connect4 → bypass.rs path.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
    sync::Arc,
};

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::{
    bypass::Deps,
    pod::PodInfo,
    store::FlowStart,
};

/// `tcp_state` value the kernel uses for ESTABLISHED in /proc/net/tcp.
const TCP_ESTABLISHED: u32 = 0x01;

/// Run the one-shot scan. Returns the number of synthetic flow rows
/// inserted. Errors at the per-pid level are logged and skipped — a
/// transient `/proc/<pid>` race must not fail the whole pass.
///
/// Iteration model: walk pods, not pids. For each pod we discover all
/// its cgroups (parent + each container) and pick a representative
/// pid from any container — `/proc/<pid>/net/tcp` is netns-scoped, so
/// any one pid in the pod's netns sees the whole pod's TCP table. We
/// then push the synthetic flow_id into `open_flows` under every one
/// of the pod's cgroups so a later tap event from any container
/// correlates correctly. (A common case: the pause sandbox holds the
/// netns and shows the connection list, but plaintext fires from the
/// rancher container's cgroup — without this, those events would
/// land with `flow_id = NULL`.)
pub async fn synthesize(deps: Arc<Deps>) -> Result<usize> {
    let cr = match deps.cgroup_resolver.as_ref() {
        Some(c) => c.clone(),
        None => {
            debug!("bootstrap: no cgroup resolver; skipping");
            return Ok(0);
        }
    };
    let inf = match deps.informer.as_ref() {
        Some(i) => i.clone(),
        None => {
            debug!("bootstrap: no informer; skipping");
            return Ok(0);
        }
    };

    // pod_uid → all (cgroup_id, /sys/fs/cgroup path) entries.
    cr.rescan();
    let mut pod_cgroups: StdHashMap<String, Vec<(u64, String)>> = StdHashMap::new();
    for (cg, uid) in cr.snapshot() {
        // Need the path back to read cgroup.procs — find_by_inum is
        // O(directories) but we only do it once at boot.
        if let Some(path) = find_path_for_inode(cg) {
            pod_cgroups.entry(uid).or_default().push((cg, path));
        }
    }
    if pod_cgroups.is_empty() {
        debug!("bootstrap: no kubepods cgroups in resolver; skipping");
        return Ok(0);
    }

    let mut inserted = 0usize;
    // Per-pod dedup of (local_port, remote_addr_be, remote_port). Same
    // tuple won't appear twice within a single pod's netns, but
    // different pods can legitimately share the same local_port (each
    // gets its own netns).
    for (uid, cgroups) in &pod_cgroups {
        let pod = match inf.lookup(uid) {
            Some(p) => p,
            None => continue,
        };

        // Find a representative pid by reading cgroup.procs from any
        // container cgroup. /proc/<pid>/net/tcp is netns-scoped so
        // any pid in the pod's netns gives us the same listing.
        let rep_pid = pick_representative_pid(cgroups);
        let pid = match rep_pid {
            Some(p) => p,
            None => continue,
        };

        let primary_cg = cgroups[0].0;
        let all_cgs: Vec<u64> = cgroups.iter().map(|(cg, _)| *cg).collect();

        // ── IPv4 pass ────────────────────────────────────────────────
        let conns_v4 = match read_tcp_v4(pid) {
            Ok(v) => v,
            Err(e) => {
                debug!(pid, uid, error = %e, "bootstrap: read /proc/<pid>/net/tcp failed");
                Vec::new()
            }
        };
        let mut seen4: HashSet<(u16, u32, u16)> = HashSet::new();
        for conn in conns_v4 {
            if conn.state != TCP_ESTABLISHED || conn.remote_addr_be == 0 {
                continue;
            }
            let key = (conn.local_port, conn.remote_addr_be, conn.remote_port);
            if !seen4.insert(key) {
                continue;
            }
            if let Err(e) = insert_one(&deps, primary_cg, &all_cgs, &pod, &conn).await {
                warn!(error = %e, "bootstrap: v4 insert_flow_start failed");
                continue;
            }
            inserted += 1;
        }

        // ── IPv6 pass ────────────────────────────────────────────────
        // /proc/<pid>/net/tcp6 also lists IPv4-mapped (::ffff:x.x.x.x)
        // entries on dual-stack sockets, which would double-count
        // against the v4 pass. read_tcp_v6 filters those out so the
        // two seen-sets stay disjoint.
        let conns_v6 = match read_tcp_v6(pid) {
            Ok(v) => v,
            Err(e) => {
                debug!(pid, uid, error = %e, "bootstrap: read /proc/<pid>/net/tcp6 failed");
                Vec::new()
            }
        };
        let mut seen6: HashSet<(u16, [u8; 16], u16)> = HashSet::new();
        for conn in conns_v6 {
            if conn.state != TCP_ESTABLISHED || conn.remote_addr == [0u8; 16] {
                continue;
            }
            let key = (conn.local_port, conn.remote_addr, conn.remote_port);
            if !seen6.insert(key) {
                continue;
            }
            if let Err(e) = insert_one_v6(&deps, primary_cg, &all_cgs, &pod, &conn).await {
                warn!(error = %e, "bootstrap: v6 insert_flow_start failed");
                continue;
            }
            inserted += 1;
        }
    }

    if inserted > 0 {
        info!(inserted, "bootstrap: synthesized flows for pre-existing connections");
    }
    Ok(inserted)
}

async fn insert_one(
    deps: &Deps,
    primary_cgroup: u64,
    all_cgroups: &[u64],
    pod: &PodInfo,
    conn: &TcpConn,
) -> Result<()> {
    let dst_ip = Ipv4Addr::from(u32::from_be(conn.remote_addr_be)).to_string();
    let dst_port = conn.remote_port;

    let id = deps
        .store
        .insert_flow_start(FlowStart {
            socket_cookie: None, // /proc/net/tcp doesn't expose the cookie
            cgroup_id: Some(primary_cgroup),
            pod_uid: Some(pod.uid.clone()),
            namespace: Some(pod.namespace.clone()),
            pod_name: Some(pod.name.clone()),
            connection_name: "bootstrap".to_string(),
            dst_host: None,
            dst_ip,
            dst_port,
            upstream_addr: None,
            atyp: Some("ip"),
        })
        .await?;

    {
        let mut g = deps.open_flows.write();
        for cg in all_cgroups {
            g.entry(*cg).or_default().push(id);
        }
    }

    let _ = deps
        .store
        .finish_flow(
            id,
            crate::store::FlowFinish {
                bytes_up: 0,
                bytes_down: 0,
                error: None,
            },
        )
        .await;

    deps.events.publish(crate::api::FlowEvent { flow_id: id });
    Ok(())
}

/// Locate the absolute path of a cgroup directory by its inode.
/// Used at boot to walk back from `cgroup_id` to a path we can read
/// `cgroup.procs` from.
fn find_path_for_inode(target: u64) -> Option<String> {
    let mut stack = vec![std::path::PathBuf::from("/sys/fs/cgroup/kubepods")];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if !ft.is_dir() {
                continue;
            }
            if let Ok(meta) = fs::metadata(&path) {
                if meta.ino() == target {
                    return path.to_str().map(String::from);
                }
            }
            stack.push(path);
        }
    }
    None
}

/// Read `cgroup.procs` from any of the pod's cgroups and return the
/// first parseable pid. We don't care which container — they all
/// share the netns, so /proc/<pid>/net/tcp is identical.
fn pick_representative_pid(cgroups: &[(u64, String)]) -> Option<u32> {
    for (_, path) in cgroups {
        let procs = match fs::read_to_string(format!("{path}/cgroup.procs")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for line in procs.lines() {
            if let Ok(pid) = line.trim().parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct TcpConn {
    state: u32,
    local_port: u16,
    remote_addr_be: u32,
    remote_port: u16,
}

/// Parse `/proc/<pid>/net/tcp` (IPv4 only). Format per row:
///
/// ```text
///   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
///    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0        0 12345
/// ```
///
/// Address bytes are big-endian within the hex string but represent
/// the kernel's struct field layout, which on x86_64 is little-endian
/// — so the *first* hex byte we read is the LOWEST byte of the IP.
/// We return the address in network byte order (BE), matching the
/// representation the relay uses elsewhere.
fn read_tcp_v4(pid: u32) -> Result<Vec<TcpConn>> {
    let raw = fs::read_to_string(format!("/proc/{pid}/net/tcp"))?;
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _sl = fields.next();
        let local = match fields.next() {
            Some(s) => s,
            None => continue,
        };
        let remote = match fields.next() {
            Some(s) => s,
            None => continue,
        };
        let state = match fields.next().and_then(|s| u32::from_str_radix(s, 16).ok()) {
            Some(s) => s,
            None => continue,
        };
        let (_local_addr_be, local_port) = match parse_addr_port(local) {
            Some(t) => t,
            None => continue,
        };
        let (remote_addr_be, remote_port) = match parse_addr_port(remote) {
            Some(t) => t,
            None => continue,
        };
        out.push(TcpConn { state, local_port, remote_addr_be, remote_port });
    }
    Ok(out)
}

/// Parse an "AABBCCDD:PPPP" hex pair into (ipv4_be_u32, port).
///
/// The kernel prints inet_saddr / inet_daddr as a `%08X` of the
/// `__be32` value. On x86_64 the LE memory order means
/// `cat /proc/net/tcp` shows e.g. `0100007F` for 127.0.0.1, with
/// the LSB byte of the u32 first. The parsed integer value is then
/// already in the form heimdall stores everywhere as `*_be`:
/// `Ipv4Addr::from(u32::from_be(parsed))` round-trips to the right
/// IPv4. NO byte-swap here — see also `bypass::insert_one` which
/// uses the same convention.
///
/// The port is straightforward `%04X` of host-order u16.
fn parse_addr_port(s: &str) -> Option<(u32, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 8 {
        return None;
    }
    let addr_be = u32::from_str_radix(addr_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr_be, port))
}

#[derive(Debug, Clone, Copy)]
struct TcpConn6 {
    state: u32,
    local_port: u16,
    /// 16 bytes in network byte order — same layout as `Ipv6Addr::octets()`.
    remote_addr: [u8; 16],
    remote_port: u16,
}

/// Parse `/proc/<pid>/net/tcp6`. Same column layout as the v4 file but
/// addresses are 32 hex chars (four `__be32` chunks printed via `%08X`
/// each).
///
/// IPv4-mapped (`::ffff:x.x.x.x`) entries appear here on dual-stack
/// sockets; they're filtered out so we don't double-count against the
/// v4 pass.
fn read_tcp_v6(pid: u32) -> Result<Vec<TcpConn6>> {
    let raw = fs::read_to_string(format!("/proc/{pid}/net/tcp6"))?;
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _sl = fields.next();
        let local = match fields.next() {
            Some(s) => s,
            None => continue,
        };
        let remote = match fields.next() {
            Some(s) => s,
            None => continue,
        };
        let state = match fields.next().and_then(|s| u32::from_str_radix(s, 16).ok()) {
            Some(s) => s,
            None => continue,
        };
        let (_local_addr, local_port) = match parse_v6_addr_port(local) {
            Some(t) => t,
            None => continue,
        };
        let (remote_addr, remote_port) = match parse_v6_addr_port(remote) {
            Some(t) => t,
            None => continue,
        };
        // Skip ::ffff:V4 — already covered by the v4 pass.
        if is_v4_mapped(&remote_addr) {
            continue;
        }
        out.push(TcpConn6 { state, local_port, remote_addr, remote_port });
    }
    Ok(out)
}

/// Parse `<32 hex>:<4 hex>` into ([u8; 16] in NBO, port).
///
/// Each 8-char chunk is the `%08X` of an `__be32` field. On x86_64 the
/// kernel reads the `__be32` value as a host-LE `u32` for printing, so
/// the printed hex is byte-swapped relative to the wire bytes. We undo
/// that here: parse the 8 chars as a host u32, then `to_le_bytes()`
/// gives back the four wire-NBO bytes the address actually carries.
fn parse_v6_addr_port(s: &str) -> Option<([u8; 16], u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &addr_hex[i * 8..(i + 1) * 8];
        let host_value = u32::from_str_radix(chunk, 16).ok()?;
        let wire = host_value.to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&wire);
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((bytes, port))
}

/// True if the 16-byte address is in the IPv4-mapped block
/// (`::ffff:0:0/96` — first 10 bytes zero, next 2 bytes 0xFF).
fn is_v4_mapped(b: &[u8; 16]) -> bool {
    b[..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff
}

async fn insert_one_v6(
    deps: &Deps,
    primary_cgroup: u64,
    all_cgroups: &[u64],
    pod: &PodInfo,
    conn: &TcpConn6,
) -> Result<()> {
    let dst_ip = Ipv6Addr::from(conn.remote_addr).to_string();
    let dst_port = conn.remote_port;

    let id = deps
        .store
        .insert_flow_start(FlowStart {
            socket_cookie: None,
            cgroup_id: Some(primary_cgroup),
            pod_uid: Some(pod.uid.clone()),
            namespace: Some(pod.namespace.clone()),
            pod_name: Some(pod.name.clone()),
            connection_name: "bootstrap".to_string(),
            dst_host: None,
            dst_ip,
            dst_port,
            upstream_addr: None,
            atyp: Some("ip6"),
        })
        .await?;

    {
        let mut g = deps.open_flows.write();
        for cg in all_cgroups {
            g.entry(*cg).or_default().push(id);
        }
    }

    let _ = deps
        .store
        .finish_flow(
            id,
            crate::store::FlowFinish {
                bytes_up: 0,
                bytes_down: 0,
                error: None,
            },
        )
        .await;

    deps.events.publish(crate::api::FlowEvent { flow_id: id });
    Ok(())
}
