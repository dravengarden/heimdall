//! Bootstrap synthesis — one-shot scan at startup that creates
//! synthetic flow rows for TCP connections already established when
//! heimdall came up.
//!
//! Why this exists: connect4 only fires on **new** `connect()` calls.
//! Long-lived TLS streams that were already open (a service's upstream
//! API watch, leader-election, etc.) will never produce a bypass
//! event, so plaintext captured by the libssl / Go uprobes from those
//! sockets has `flow_id = NULL` in the messages table.
//!
//! Scan algorithm (host netns):
//!
//!   1. Build `socket_inode → cgroup_id` by walking `/proc/<pid>/fd`
//!      for every pid and recording each `socket:[inode]` symlink
//!      against the pid's leaf cgroup (inode of the dir named in
//!      `/proc/<pid>/cgroup`).
//!   2. Read `/proc/net/tcp` + `/proc/net/tcp6` once (heimdall runs in
//!      the host netns, so this is the host's connection table).
//!   3. For each ESTABLISHED outbound socket, look up its inode →
//!      cgroup_id → `UnitInfo` and insert a flow row tagged
//!      `connection_name = "bootstrap"`, then push to the open-flow
//!      index so subsequent tap events correlate.
//!
//! Connections in a separate netns (e.g. docker containers) don't show
//! up in the host table and are intentionally skipped — uprobes still
//! observe their plaintext, just without bootstrap correlation.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
    sync::Arc,
};

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::{bypass::Deps, store::FlowStart, unit::UnitInfo};

/// `tcp_state` value the kernel uses for ESTABLISHED in /proc/net/tcp.
const TCP_ESTABLISHED: u32 = 0x01;

/// Run the one-shot scan. Returns the number of synthetic flow rows
/// inserted. Errors at the per-pid / per-row level are logged and
/// skipped — a transient `/proc` race must not fail the whole pass.
pub async fn synthesize(deps: Arc<Deps>) -> Result<usize> {
    let ur = match deps.units.as_ref() {
        Some(u) => u.clone(),
        None => {
            debug!("bootstrap: no unit resolver; skipping");
            return Ok(0);
        }
    };
    ur.rescan();

    let sock_to_cg = build_socket_to_cgroup();
    if sock_to_cg.is_empty() {
        debug!("bootstrap: no socket→cgroup mappings; skipping");
        return Ok(0);
    }

    let mut inserted = 0usize;

    // ── IPv4 pass ────────────────────────────────────────────────────
    let mut seen4: HashSet<(u64, u16, u32, u16)> = HashSet::new();
    for conn in read_tcp_v4().unwrap_or_default() {
        if conn.state != TCP_ESTABLISHED || conn.remote_addr_be == 0 {
            continue;
        }
        let cg = match sock_to_cg.get(&conn.inode) {
            Some(c) => *c,
            None => continue,
        };
        if !seen4.insert((cg, conn.local_port, conn.remote_addr_be, conn.remote_port)) {
            continue;
        }
        let info = ur.resolve(cg).unwrap_or_default();
        if let Err(e) = insert_one(&deps, cg, &info, &conn).await {
            warn!(error = %e, "bootstrap: v4 insert_flow_start failed");
            continue;
        }
        inserted += 1;
    }

    // ── IPv6 pass ────────────────────────────────────────────────────
    // /proc/net/tcp6 also lists IPv4-mapped (::ffff:x.x.x.x) entries on
    // dual-stack sockets; read_tcp_v6 filters those so the passes stay
    // disjoint.
    let mut seen6: HashSet<(u64, u16, [u8; 16], u16)> = HashSet::new();
    for conn in read_tcp_v6().unwrap_or_default() {
        if conn.state != TCP_ESTABLISHED || conn.remote_addr == [0u8; 16] {
            continue;
        }
        let cg = match sock_to_cg.get(&conn.inode) {
            Some(c) => *c,
            None => continue,
        };
        if !seen6.insert((cg, conn.local_port, conn.remote_addr, conn.remote_port)) {
            continue;
        }
        let info = ur.resolve(cg).unwrap_or_default();
        if let Err(e) = insert_one_v6(&deps, cg, &info, &conn).await {
            warn!(error = %e, "bootstrap: v6 insert_flow_start failed");
            continue;
        }
        inserted += 1;
    }

    if inserted > 0 {
        info!(
            inserted,
            "bootstrap: synthesized flows for pre-existing connections"
        );
    }
    Ok(inserted)
}

async fn insert_one(deps: &Deps, cgroup_id: u64, unit: &UnitInfo, conn: &TcpConn) -> Result<()> {
    let dst_ip = Ipv4Addr::from(u32::from_be(conn.remote_addr_be)).to_string();
    let dst_port = conn.remote_port;

    let id = deps
        .store
        .insert_flow_start(FlowStart {
            socket_cookie: None, // /proc/net/tcp doesn't expose the cookie
            cgroup_id: Some(cgroup_id),
            unit: unit.unit.clone(),
            slice: unit.slice.clone(),
            connection_name: "bootstrap".to_string(),
            dst_host: None,
            dst_ip,
            dst_port,
            upstream_addr: None,
            atyp: Some("ip"),
        })
        .await?;

    deps.open_flows
        .write()
        .entry(cgroup_id)
        .or_default()
        .push(id);

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

async fn insert_one_v6(
    deps: &Deps,
    cgroup_id: u64,
    unit: &UnitInfo,
    conn: &TcpConn6,
) -> Result<()> {
    let dst_ip = Ipv6Addr::from(conn.remote_addr).to_string();
    let dst_port = conn.remote_port;

    let id = deps
        .store
        .insert_flow_start(FlowStart {
            socket_cookie: None,
            cgroup_id: Some(cgroup_id),
            unit: unit.unit.clone(),
            slice: unit.slice.clone(),
            connection_name: "bootstrap".to_string(),
            dst_host: None,
            dst_ip,
            dst_port,
            upstream_addr: None,
            atyp: Some("ip6"),
        })
        .await?;

    deps.open_flows
        .write()
        .entry(cgroup_id)
        .or_default()
        .push(id);

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

/// Build a `socket_inode → cgroup_id` map by walking every `/proc/<pid>`.
/// For each pid we read its leaf cgroup (the dir named in
/// `/proc/<pid>/cgroup`, whose inode == cgroup_id) and record every
/// `socket:[inode]` fd it holds. Per-pid errors are skipped silently —
/// pids race against us constantly.
fn build_socket_to_cgroup() -> StdHashMap<u64, u64> {
    let mut out = StdHashMap::new();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid = match name.to_string_lossy().parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue, // not a pid dir
        };
        let cg = match cgroup_id_of_pid(pid) {
            Some(c) => c,
            None => continue,
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path())
                && let Some(inode) = parse_socket_inode(&target.to_string_lossy())
            {
                out.insert(inode, cg);
            }
        }
    }
    out
}

/// cgroup v2: `/proc/<pid>/cgroup` is a single `0::<path>` line. The
/// leaf cgroup's directory inode (== cgroup_id) is `stat` of
/// `/sys/fs/cgroup<path>`.
fn cgroup_id_of_pid(pid: u32) -> Option<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = raw.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let path = format!("/sys/fs/cgroup{rel}");
    fs::metadata(path).ok().map(|m| m.ino())
}

/// Parse `socket:[12345]` → `12345`. Returns None for non-socket fds.
fn parse_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[derive(Debug, Clone, Copy)]
struct TcpConn {
    state: u32,
    local_port: u16,
    remote_addr_be: u32,
    remote_port: u16,
    inode: u64,
}

/// Parse `/proc/net/tcp` (IPv4 only). Columns:
///
/// ```text
///   sl local_address rem_address st tx:rx tr tm->when retrnsmt uid timeout inode
/// ```
///
/// Address bytes are big-endian within the hex string but represent
/// the kernel's struct field layout, which on x86_64 is little-endian
/// — so the *first* hex byte we read is the LOWEST byte of the IP. We
/// return the address in network byte order (BE), matching the
/// representation the relay uses elsewhere.
fn read_tcp_v4() -> Result<Vec<TcpConn>> {
    let raw = fs::read_to_string("/proc/net/tcp")?;
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let state = match u32::from_str_radix(f[3], 16) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (_local_addr_be, local_port) = match parse_addr_port(f[1]) {
            Some(t) => t,
            None => continue,
        };
        let (remote_addr_be, remote_port) = match parse_addr_port(f[2]) {
            Some(t) => t,
            None => continue,
        };
        let inode = match f[9].parse::<u64>() {
            Ok(i) => i,
            Err(_) => continue,
        };
        out.push(TcpConn {
            state,
            local_port,
            remote_addr_be,
            remote_port,
            inode,
        });
    }
    Ok(out)
}

/// Parse an "AABBCCDD:PPPP" hex pair into (ipv4_be_u32, port).
///
/// The kernel prints inet_saddr / inet_daddr as a `%08X` of the
/// `__be32` value. On x86_64 the LE memory order means
/// `cat /proc/net/tcp` shows e.g. `0100007F` for 127.0.0.1, with the
/// LSB byte of the u32 first. The parsed integer value is then already
/// in the form heimdall stores everywhere as `*_be`:
/// `Ipv4Addr::from(u32::from_be(parsed))` round-trips to the right
/// IPv4. NO byte-swap here — see also `bypass::insert_one` which uses
/// the same convention.
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
    inode: u64,
}

/// Parse `/proc/net/tcp6`. Same column layout as the v4 file but
/// addresses are 32 hex chars (four `__be32` chunks printed via `%08X`
/// each). IPv4-mapped (`::ffff:x.x.x.x`) entries are filtered out so we
/// don't double-count against the v4 pass.
fn read_tcp_v6() -> Result<Vec<TcpConn6>> {
    let raw = fs::read_to_string("/proc/net/tcp6")?;
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let state = match u32::from_str_radix(f[3], 16) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (_local_addr, local_port) = match parse_v6_addr_port(f[1]) {
            Some(t) => t,
            None => continue,
        };
        let (remote_addr, remote_port) = match parse_v6_addr_port(f[2]) {
            Some(t) => t,
            None => continue,
        };
        if is_v4_mapped(&remote_addr) {
            continue;
        }
        let inode = match f[9].parse::<u64>() {
            Ok(i) => i,
            Err(_) => continue,
        };
        out.push(TcpConn6 {
            state,
            local_port,
            remote_addr,
            remote_port,
            inode,
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socket_inode_ok() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("/dev/null"), None);
        assert_eq!(parse_socket_inode("anon_inode:[eventpoll]"), None);
    }

    #[test]
    fn parse_addr_port_v4() {
        // 127.0.0.1:8080 → "0100007F:1F90"
        let (addr_be, port) = parse_addr_port("0100007F:1F90").unwrap();
        assert_eq!(
            Ipv4Addr::from(u32::from_be(addr_be)),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(port, 0x1F90);
    }
}
