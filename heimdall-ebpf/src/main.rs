//! eBPF kernel programs for heimdall.
//!
//! Two programs work together:
//!
//! 1. `connect4` (BPF_CGROUP_INET4_CONNECT)
//!    Intercepts connect() syscalls from any process in the attached cgroup.
//!    For non-LAN destinations, rewrites the target to RELAY_IP:PROXY_PORT
//!    and saves the original (ip, port) in COOKIE_MAP keyed by socket cookie.
//!
//! 2. `skb_egress` (BPF_CGROUP_INET_EGRESS)
//!    Fires on every outgoing packet from the cgroup.
//!    For the first TCP packet on a redirected connection, inet_hash_connect has
//!    already assigned the ephemeral source port. We read the socket cookie
//!    (same value as connect4 stored), find orig_dst in COOKIE_MAP, and write
//!    PORT_MAP[src_port] so the relay can find it after accept().
//!
//!    Why not sock_ops ACTIVE_ESTABLISHED_CB?
//!    When Cilium's fast-path socket acceleration is active, the TCP_ESTABLISHED
//!    state transition that triggers ACTIVE_ESTABLISHED_CB is bypassed. The
//!    cgroup_skb egress hook fires at an earlier point (packet send) where
//!    the source port is already assigned but no Cilium intervention has occurred.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_socket_cookie,
    macros::{cgroup_skb, cgroup_sock_addr, map},
    maps::{Array, HashMap},
    programs::{SkBuffContext, SockAddrContext},
    EbpfContext,
};
use heimdall_common::{is_default_bypass, OrigDst};

const PROXY_PORT: u16 = 12345;

// Relay IPv4 address in network byte order, set by userspace at startup.
#[map]
static RELAY_ADDR: Array<u32> = Array::with_max_entries(2, 0);

// Stage-1 map: socket_cookie → original destination
// Populated in connect4, consumed in skb_egress.
#[map]
static COOKIE_MAP: HashMap<u64, OrigDst> = HashMap::with_max_entries(65536, 0);

// Stage-2 map: client_ephemeral_port → original destination
// Populated in skb_egress, consumed by the userspace relay after accept().
#[map]
static PORT_MAP: HashMap<u32, OrigDst> = HashMap::with_max_entries(65536, 0);

// ---------------------------------------------------------------------------
// Program 1: intercept connect() and rewrite destination
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(ctx) {
        Ok(()) | Err(()) => 1,
    }
}

#[inline(always)]
fn try_connect4(ctx: SockAddrContext) -> Result<(), ()> {
    let sa = ctx.sock_addr;
    let dst_ip_be = unsafe { (*sa).user_ip4 };
    let dst_port_be = unsafe { (*sa).user_port as u16 };

    let relay_ip_be = match RELAY_ADDR.get(0) {
        Some(ip) => *ip,
        None => return Ok(()),
    };

    if dst_ip_be == relay_ip_be && u16::from_be(dst_port_be) == PROXY_PORT {
        return Ok(());
    }

    if is_default_bypass(dst_ip_be) {
        return Ok(());
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let orig = OrigDst { ip: dst_ip_be, port: dst_port_be, _pad: 0 };
    COOKIE_MAP.insert(&cookie, &orig, 0).map_err(|_| ())?;

    unsafe {
        (*sa).user_ip4 = relay_ip_be;
        (*sa).user_port = u32::from(PROXY_PORT.to_be());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Program 2: on the first packet of a redirected connection, populate PORT_MAP.
//
// cgroup_skb egress fires after inet_hash_connect has assigned the ephemeral
// source port but before any Cilium TC processing. The socket cookie matches
// what connect4 stored. We read src_port from the TCP header and write
// PORT_MAP[src_port] = orig_dst for the relay to consume after accept().
// ---------------------------------------------------------------------------

#[cgroup_skb(egress)]
pub fn skb_egress(ctx: SkBuffContext) -> i32 {
    match try_skb_egress(&ctx) {
        Ok(()) | Err(()) => 1, // always allow; we only read metadata
    }
}

// IPv4 + TCP header field offsets (IP starts at byte 0 in cgroup_skb).
const OFF_IP_PROTO: usize = 9;
const IPPROTO_TCP: u8 = 6;

#[inline(always)]
fn try_skb_egress(ctx: &SkBuffContext) -> Result<(), ()> {
    // Only handle TCP.
    let proto: u8 = ctx.load(OFF_IP_PROTO).map_err(|_| ())?;
    if proto != IPPROTO_TCP {
        return Ok(());
    }

    // Look up COOKIE_MAP for this socket. Only intercepted connections have entries.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let orig = match unsafe { COOKIE_MAP.get(&cookie) } {
        Some(v) => *v,
        None => return Ok(()),
    };

    // Parse the IPv4 IHL to find the TCP header start.
    let ip_ver_ihl: u8 = ctx.load(0).map_err(|_| ())?;
    let ihl = ((ip_ver_ihl & 0x0f) as usize) * 4;

    // Read TCP source port (network byte order → host byte order).
    // inet_hash_connect has already assigned this ephemeral port.
    let src_port_be: u16 = ctx.load(ihl).map_err(|_| ())?;
    let src_port = u16::from_be(src_port_be) as u32;

    PORT_MAP.insert(&src_port, &orig, 0).map_err(|_| ())?;
    let _ = COOKIE_MAP.remove(&cookie);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
