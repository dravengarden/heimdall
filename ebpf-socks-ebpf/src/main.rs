//! eBPF kernel programs for ebpf-socks.
//!
//! Two programs work together:
//!
//! 1. `connect4` (BPF_CGROUP_INET4_CONNECT)
//!    Intercepts connect() syscalls from any process in the attached cgroup.
//!    For non-LAN destinations, rewrites the target to 127.0.0.1:PROXY_PORT
//!    and saves the original (ip, port) in COOKIE_MAP keyed by socket cookie.
//!
//! 2. `sock_ops` (BPF_CGROUP_SOCK_OPS / ACTIVE_ESTABLISHED_CB)
//!    Fires after the TCP handshake completes (from the connecting side).
//!    At this point the kernel has assigned a local ephemeral port.
//!    Moves the entry from COOKIE_MAP[cookie] → PORT_MAP[local_port] so the
//!    userspace daemon can look it up via getpeername() on the accepted socket.
#![no_std]
#![no_main]

use aya_bpf::{
    bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
    helpers::bpf_get_socket_cookie,
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::HashMap,
    programs::{SockAddrContext, SockOpsContext},
};
use ebpf_socks_common::{is_default_bypass, OrigDst};

// Proxy listen port (must match userspace PROXY_LISTEN_PORT)
const PROXY_PORT: u32 = 12345;

// Stage-1 map: socket_cookie → original destination
// Populated in connect4, consumed in sock_ops.
#[map]
static COOKIE_MAP: HashMap<u64, OrigDst> = HashMap::with_max_entries(65536, 0);

// Stage-2 map: client_ephemeral_port → original destination
// Populated in sock_ops, consumed by the userspace daemon after accept().
#[map]
static PORT_MAP: HashMap<u32, OrigDst> = HashMap::with_max_entries(65536, 0);

// ---------------------------------------------------------------------------
// Program 1: intercept connect() and rewrite destination
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    // Must always return 1 (allow); returning 0 would make connect() fail.
    match try_connect4(ctx) {
        Ok(()) | Err(()) => 1,
    }
}

#[inline(always)]
fn try_connect4(ctx: SockAddrContext) -> Result<(), ()> {
    let sa = ctx.sock_addr;
    let dst_ip_be = unsafe { (*sa).user_ip4 };

    // Let LAN / cluster-internal traffic pass through unchanged.
    if is_default_bypass(dst_ip_be) {
        return Ok(());
    }

    // user_port is stored as a 32-bit value but only the lower 16 bits are
    // meaningful; the byte order matches user_ip4 (network / big-endian).
    let dst_port_be = unsafe { (*sa).user_port as u16 };

    // Save original destination before overwriting.
    let cookie = unsafe { bpf_get_socket_cookie(sa as *mut _) };
    let orig = OrigDst { ip: dst_ip_be, port: dst_port_be, _pad: 0 };
    COOKIE_MAP.insert(&cookie, &orig, 0).map_err(|_| ())?;

    // Rewrite destination → 127.0.0.1:PROXY_PORT (big-endian fields).
    unsafe {
        (*sa).user_ip4 = u32::from_ne_bytes([127, 0, 0, 1]).to_be();
        (*sa).user_port = PROXY_PORT.to_be();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Program 2: after TCP handshake, move cookie_map → port_map
// ---------------------------------------------------------------------------

#[sock_ops]
pub fn sock_ops_handler(ctx: SockOpsContext) -> u32 {
    // Only act on outgoing connections that just completed the handshake.
    if ctx.op() != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB as u32 {
        return 0;
    }
    let _ = try_sock_ops(ctx);
    0
}

#[inline(always)]
fn try_sock_ops(ctx: SockOpsContext) -> Result<(), ()> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) };

    // If this connection was not redirected by connect4, nothing to do.
    let orig = match COOKIE_MAP.get(&cookie) {
        Some(v) => *v,
        None => return Ok(()),
    };

    // local_port is available in sock_ops context in host byte order.
    // This is the ephemeral port the kernel assigned for this connection.
    // The userspace daemon will see it as the peer port in getpeername().
    let local_port = ctx.local_port();

    PORT_MAP.insert(&local_port, &orig, 0).map_err(|_| ())?;
    COOKIE_MAP.remove(&cookie).map_err(|_| ())?;

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
