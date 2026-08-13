//! eBPF kernel programs for heimdall.
//!
//! The primary TCP programs work together as follows:
//!
//! 1. `connect4` (BPF_CGROUP_INET4_CONNECT)
//!    Intercepts connect() syscalls from any process in the attached cgroup.
//!    For registered cgroups, rewrites TCP to loopback:RELAY_PORT
//!    and saves the original (ip, port) in COOKIE_MAP keyed by socket cookie.
//!
//! 2. `skb_egress` (BPF_CGROUP_INET_EGRESS)
//!    Fires on every outgoing packet from the cgroup.
//!    For the first TCP packet on a redirected connection, inet_hash_connect has
//!    already assigned the ephemeral source port. We read the socket cookie
//!    (same value as connect4 stored), find orig_dst in COOKIE_MAP, and write
//!    PORT_MAP[family, src_port] so the relay can find it after accept().
//!
//!    Why not sock_ops ACTIVE_ESTABLISHED_CB?
//!    When Cilium's fast-path socket acceleration is active, the TCP_ESTABLISHED
//!    state transition that triggers ACTIVE_ESTABLISHED_CB is bypassed. The
//!    cgroup_skb egress hook fires at an earlier point (packet send) where
//!    the source port is already assigned but no Cilium intervention has occurred.
//!
//! UDP hooks additionally use per-socket-and-destination tokens for IPv4 and
//! retain family-and-source-port correlation for connected IPv6.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_cgroup_id, bpf_get_socket_cookie},
    macros::{cgroup_skb, cgroup_sock, cgroup_sock_addr, map},
    maps::{Array, HashMap, LruHashMap},
    programs::{SkBuffContext, SockAddrContext, SockContext},
};
use heimdall_common::{
    DEFAULT_POLICY, FAMILY_V4, FAMILY_V6, OrigDst, POLICY_DNS_HIJACK, POLICY_DNS_SYSTEM,
    POLICY_REDIRECT_OFF, POLICY_UDP_REJECT, RELAY_PORT, UdpFlowKey, relay_key,
};

const DNS_PORT: u16 = 53;
const SOCK_DGRAM: u32 = 2;

// Relay IPv4 address in network byte order, set by userspace at startup.
#[map]
static RELAY_ADDR: Array<u32> = Array::with_max_entries(2, 0);

// Relay IPv6 address (16 bytes, network byte order) — set to loopback by
// userspace at startup. Stored as a
// 4×u32 array so it's a flat POD for the verifier.
#[map]
static RELAY_ADDR6: Array<[u8; 16]> = Array::with_max_entries(1, 0);

// Heimdall fake-IP DNS endpoint, IPv4. Slot 0 = ip in network byte
// order, slot 1 = port in network byte order (16-bit value stored in
// u32 lower bits). Populated at startup from `daemon.dns_port`.
// Used by connect4 + udp4_sendmsg when the cgroup has POLICY_DNS_HIJACK.
#[map]
static DNS_ADDR_V4: Array<u32> = Array::with_max_entries(2, 0);

// Heimdall fake-IP DNS endpoint, IPv6. addr at slot 0 (16 bytes),
// port at slot 0 of DNS_PORT_V6 (separate map to keep the value type
// simple).
#[map]
static DNS_ADDR_V6: Array<[u8; 16]> = Array::with_max_entries(1, 0);
#[map]
static DNS_PORT_V6: Array<u32> = Array::with_max_entries(1, 0);

// Stage-1 map: socket_cookie → original destination
// Populated in connect4, consumed in skb_egress.
//
// LRU because skb_egress doesn't always fire to consume an entry —
// e.g. a connect() that fails before sending its first SYN, or a
// rewrite to a v6 relay address the source can't actually route to —
// would leak forever in a regular HashMap. A noisy client once filled
// this map with failed IPv6 connections, and connect4's
// `insert(...)?` started early-returning *before the dst rewrite* —
// so EVERY new flow on the host (incl. `heimdall run`) silently went
// to its un-rewritten original IP and got TPROXY-trapped by v2raya.
// LRU evicts the oldest cookie under pressure; a stale cookie loses its
// PORT_MAP correlation but the rewrite still happens, which is the
// correct trade-off (lose one destination lookup > lose redirect entirely).
#[map]
static COOKIE_MAP: LruHashMap<u64, OrigDst> = LruHashMap::with_max_entries(65536, 0);

// Connected UDP sockets keep their destination for the socket lifetime. Unlike
// TCP, the entry cannot be consumed on the first packet because every later
// datagram and getpeername() call needs the same transparent association.
#[map]
static UDP_COOKIE_MAP: LruHashMap<u64, OrigDst> = LruHashMap::with_max_entries(65536, 0);

// UDP relay correlation cannot use the client source port: SO_REUSEPORT and
// connectionless sockets make that value ambiguous. Each socket+destination
// instead receives a unique 24-bit token encoded in 127/8. The relay observes
// the destination address through IP_PKTINFO and responses carry the same
// token as their source address for recvmsg4 to reverse.
#[map]
static UDP_FLOW_MAP: LruHashMap<UdpFlowKey, u32> = LruHashMap::with_max_entries(65536, 0);
#[map]
static UDP_TOKEN_MAP: LruHashMap<u32, OrigDst> = LruHashMap::with_max_entries(65536, 0);

// Stage-2 map: (address family, client_ephemeral_port) → original destination
// Populated in skb_egress, consumed by the userspace relay after accept().
//
// LRU for the same reason as COOKIE_MAP: an entry can leak if the
// relay never accepts the redirected connection (relay died /
// listener torn down mid-connect / connection RST'd between SYN and
// accept). LRU keeps the map self-healing under those edge cases.
#[map]
static PORT_MAP: LruHashMap<u32, OrigDst> = LruHashMap::with_max_entries(65536, 0);

// IPv6 connected UDP retains the legacy family+source-port correlation because
// Linux does not permit a UDP6 sendmsg hook to rewrite to an IPv4-mapped token
// address. IPv4 uses UDP_TOKEN_MAP and does not depend on this map.
#[map]
static UDP_PORT_MAP: LruHashMap<u32, OrigDst> = LruHashMap::with_max_entries(65536, 0);

// Per-cgroup policy. `heimdall run` registers a cgroup before launching
// the command and removes it afterward.
#[map]
static CGROUP_POLICY: HashMap<u64, u8> = HashMap::with_max_entries(65536, 0);

#[inline(always)]
fn policy_for(cgroup_id: u64) -> u8 {
    unsafe { CGROUP_POLICY.get(&cgroup_id) }
        .copied()
        .unwrap_or(DEFAULT_POLICY)
}

#[inline(always)]
fn same_udp_flow(orig: &OrigDst, flow: &UdpFlowKey) -> bool {
    orig.socket_cookie == flow.socket_cookie
        && orig.cgroup_id == flow.cgroup_id
        && orig.port == flow.port
        && orig.family == flow.family
        && orig.addr == flow.addr
}

#[inline(always)]
fn udp_token(flow: &UdpFlowKey, orig: &OrigDst) -> Option<u32> {
    if let Some(token) = unsafe { UDP_FLOW_MAP.get(flow) }
        && let Some(existing) = unsafe { UDP_TOKEN_MAP.get(token) }
        && same_udp_flow(existing, flow)
    {
        return Some(*token);
    }

    let mut seed = flow.socket_cookie
        ^ flow.cgroup_id.rotate_left(17)
        ^ u64::from(flow.port).rotate_left(33)
        ^ u64::from(flow.family).rotate_left(49);
    for chunk in flow.addr.chunks_exact(8) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        seed ^= u64::from_ne_bytes(bytes).rotate_left(11);
    }

    // Bounded collision resolution keeps the verifier happy. BPF_NOEXIST (1)
    // makes token ownership atomic across CPUs; 32 candidates against a
    // 24-bit space is ample while the map itself is capped at 65,536 entries.
    for salt in 0..32u64 {
        let mixed = seed
            .wrapping_add(salt.wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .wrapping_mul(0xbf58_476d_1ce4_e5b9);
        let token = ((mixed ^ (mixed >> 32)) as u32 & 0x00ff_ffff).max(1);
        if UDP_TOKEN_MAP.insert(&token, orig, 1).is_ok() {
            let _ = UDP_FLOW_MAP.insert(flow, &token, 0);
            return Some(token);
        }
        if let Some(existing) = unsafe { UDP_TOKEN_MAP.get(&token) }
            && same_udp_flow(existing, flow)
        {
            let _ = UDP_FLOW_MAP.insert(flow, &token, 0);
            return Some(token);
        }
    }
    None
}

#[inline(always)]
fn token_v4(token: u32) -> u32 {
    u32::from_ne_bytes([
        127,
        ((token >> 16) & 0xff) as u8,
        ((token >> 8) & 0xff) as u8,
        (token & 0xff) as u8,
    ])
}

#[inline(always)]
fn token_from_v4(addr: u32) -> Option<u32> {
    let bytes = addr.to_ne_bytes();
    (bytes[0] == 127)
        .then_some((u32::from(bytes[1]) << 16) | (u32::from(bytes[2]) << 8) | u32::from(bytes[3]))
}

// ---------------------------------------------------------------------------
// DNS hijack helpers — shared between connect4/connect6 and sendmsg4/sendmsg6.
//
// When the cgroup's policy has POLICY_DNS_HIJACK set AND the destination
// port is 53, rewrite the destination to heimdall's fake-IP DNS server
// (taken from DNS_ADDR_V4 / DNS_ADDR_V6 maps populated at startup).
//
// Returns true when the destination was rewritten — caller should treat
// that as "this connection is going to heimdall DNS, NOT the relay" and
// return early (don't store in COOKIE_MAP or run redirect logic).
// ---------------------------------------------------------------------------

#[inline(always)]
fn try_hijack_dns_v4(sa: *mut aya_ebpf::bindings::bpf_sock_addr, policy: u8) -> bool {
    if (policy & POLICY_DNS_HIJACK) == 0 {
        return false;
    }
    let dport = unsafe { (*sa).user_port as u16 };
    if u16::from_be(dport) != DNS_PORT {
        return false;
    }
    let dns_ip_be = match DNS_ADDR_V4.get(0) {
        Some(v) => *v,
        None => return false,
    };
    let dns_port_be = match DNS_ADDR_V4.get(1) {
        Some(v) => *v as u16,
        None => return false,
    };
    unsafe {
        (*sa).user_ip4 = dns_ip_be;
        (*sa).user_port = u32::from(dns_port_be);
    }
    true
}

#[inline(always)]
fn try_hijack_dns_v6(sa: *mut aya_ebpf::bindings::bpf_sock_addr, policy: u8) -> bool {
    if (policy & POLICY_DNS_HIJACK) == 0 {
        return false;
    }
    let dport = unsafe { (*sa).user_port as u16 };
    if u16::from_be(dport) != DNS_PORT {
        return false;
    }
    let dns_addr = match DNS_ADDR_V6.get(0) {
        Some(v) => *v,
        None => return false,
    };
    let dns_port_be = match DNS_PORT_V6.get(0) {
        Some(v) => *v as u16,
        None => return false,
    };
    unsafe {
        let mut words = [0u32; 4];
        for i in 0..4 {
            let b = [
                dns_addr[i * 4],
                dns_addr[i * 4 + 1],
                dns_addr[i * 4 + 2],
                dns_addr[i * 4 + 3],
            ];
            words[i] = u32::from_ne_bytes(b);
        }
        (*sa).user_ip6 = words;
        (*sa).user_port = u32::from(dns_port_be);
    }
    true
}

// ---------------------------------------------------------------------------
// Program 1: intercept connect() and rewrite destination
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(ctx) {
        Ok(()) => 1,
        Err(()) => 0,
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

    if dst_ip_be == relay_ip_be && u16::from_be(dst_port_be) == RELAY_PORT {
        return Ok(());
    }

    // Skip dst_port=0. This is the glibc "connected-UDP source-address
    // discovery" idiom (RFC 6724 src-addr selection): connect a UDP
    // socket to the destination with port 0, getsockname(), close.
    // No SYN/datagram ever leaves the socket, so skb_egress never
    // fires and any COOKIE_MAP entry from this connect would leak.
    // A noisy telemetry client once emitted hundreds of these per
    // second per worker, filling COOKIE_MAP in a few
    // hours. Short-circuiting here keeps the map healthy *and* avoids
    // pointlessly rewriting a connect that isn't going to send a
    // packet.
    if u16::from_be(dst_port_be) == 0 {
        return Ok(());
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);

    // DNS hijack runs BEFORE the bypass/redirect path: any UDP/TCP
    // connect() to *:53 from a hijack-marked cgroup gets steered to
    // heimdall's fake-IP DNS, regardless of where the resolver
    // thought it was sending the query (typically 127.0.0.53 via
    // systemd-resolved).
    if try_hijack_dns_v4(sa, policy) {
        return Ok(());
    }

    if (policy & POLICY_DNS_SYSTEM) != 0 && u16::from_be(dst_port_be) == DNS_PORT {
        return Ok(());
    }

    let is_udp = unsafe { (*sa).type_ } == SOCK_DGRAM;
    if is_udp && (policy & POLICY_UDP_REJECT) != 0 {
        return Err(());
    }

    let user_bypass = (policy & POLICY_REDIRECT_OFF) != 0;

    if user_bypass {
        return Ok(());
    }
    let mut orig = OrigDst {
        addr: [0u8; 16],
        port: dst_port_be,
        family: FAMILY_V4,
        _pad: 0,
        cgroup_id,
        socket_cookie: cookie,
    };
    let ip_bytes = dst_ip_be.to_ne_bytes();
    orig.addr[0] = ip_bytes[0];
    orig.addr[1] = ip_bytes[1];
    orig.addr[2] = ip_bytes[2];
    orig.addr[3] = ip_bytes[3];
    // Best-effort cookie store. If insert fails (-EAGAIN under LRU
    // pressure, verifier weirdness), proceed with the rewrite anyway —
    // losing destination correlation breaks this one connection, but
    // skipping the rewrite would change policy unexpectedly. Past incident:
    // a `?` here on a full
    // (non-LRU) map silently broke every new redirect on the host.
    if is_udp {
        let flow = UdpFlowKey {
            socket_cookie: cookie,
            cgroup_id,
            addr: orig.addr,
            port: orig.port,
            family: orig.family,
            _pad: [0; 5],
        };
        let Some(token) = udp_token(&flow, &orig) else {
            return Err(());
        };
        let _ = UDP_COOKIE_MAP.insert(&cookie, &orig, 0);
        unsafe {
            (*sa).user_ip4 = token_v4(token);
            (*sa).user_port = u32::from(RELAY_PORT.to_be());
        }
        return Ok(());
    } else {
        let _ = COOKIE_MAP.insert(&cookie, &orig, 0);
    }

    unsafe {
        (*sa).user_ip4 = relay_ip_be;
        (*sa).user_port = u32::from(RELAY_PORT.to_be());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// connect6 — IPv6 sibling of connect4.
//
// Mirror logic: read user_ip6 + user_port from the sock_addr, consult
// CGROUP_POLICY, then either bypass or rewrite to RELAY_ADDR6 + RELAY_PORT.
// COOKIE_MAP entries from connect6 carry family=FAMILY_V6 so userspace
// + skb_egress can decode the address bytes correctly.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(ctx) {
        Ok(()) => 1,
        Err(()) => 0,
    }
}

#[inline(always)]
fn try_connect6(ctx: SockAddrContext) -> Result<(), ()> {
    let sa = ctx.sock_addr;
    // user_ip6 is a [u32; 4] in the bpf_sock_addr struct. Each u32 is in
    // network byte order; together they form the 16 wire bytes.
    let dst6_words = unsafe { (*sa).user_ip6 };
    let dst_port_be = unsafe { (*sa).user_port as u16 };

    let relay6 = match RELAY_ADDR6.get(0) {
        Some(a) => *a,
        None => return Ok(()),
    };

    // Compose the on-wire 16-byte destination from the 4 BE u32s.
    let mut dst_addr = [0u8; 16];
    for i in 0..4 {
        let b = dst6_words[i].to_ne_bytes();
        dst_addr[i * 4] = b[0];
        dst_addr[i * 4 + 1] = b[1];
        dst_addr[i * 4 + 2] = b[2];
        dst_addr[i * 4 + 3] = b[3];
    }

    // Self-loop check — already going to the relay's v6 address+port.
    if dst_addr == relay6 && u16::from_be(dst_port_be) == RELAY_PORT {
        return Ok(());
    }

    // Skip dst_port=0 — see the matching comment in try_connect4 for
    // the glibc src-address-discovery rationale.
    if u16::from_be(dst_port_be) == 0 {
        return Ok(());
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);

    // DNS hijack — same semantics as connect4 but for v6 sockets.
    if try_hijack_dns_v6(sa, policy) {
        return Ok(());
    }

    if (policy & POLICY_DNS_SYSTEM) != 0 && u16::from_be(dst_port_be) == DNS_PORT {
        return Ok(());
    }

    let is_udp = unsafe { (*sa).type_ } == SOCK_DGRAM;
    if is_udp && (policy & POLICY_UDP_REJECT) != 0 {
        return Err(());
    }

    let user_bypass = (policy & POLICY_REDIRECT_OFF) != 0;

    if user_bypass {
        return Ok(());
    }

    let orig = OrigDst {
        addr: dst_addr,
        port: dst_port_be,
        family: FAMILY_V6,
        _pad: 0,
        cgroup_id,
        socket_cookie: cookie,
    };
    // Best-effort: see the matching comment in `try_connect4`. The
    // rewrite below MUST run regardless of whether the cookie was
    // recorded.
    if is_udp {
        let _ = UDP_COOKIE_MAP.insert(&cookie, &orig, 0);
    } else {
        let _ = COOKIE_MAP.insert(&cookie, &orig, 0);
    }

    unsafe {
        // Rewrite destination to the relay's v6 address. user_ip6 takes
        // 4 BE u32s — pour the 16 wire bytes back into them.
        let mut words = [0u32; 4];
        for i in 0..4 {
            let b = [
                relay6[i * 4],
                relay6[i * 4 + 1],
                relay6[i * 4 + 2],
                relay6[i * 4 + 3],
            ];
            words[i] = u32::from_ne_bytes(b);
        }
        (*sa).user_ip6 = words;
        (*sa).user_port = u32::from(RELAY_PORT.to_be());
    }

    Ok(())
}

// Preserve the peer identity observed by connected UDP applications after the
// kernel-level destination was rewritten to the loopback relay.
#[cgroup_sock_addr(getpeername4)]
pub fn getpeername4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let Some(orig) = (unsafe { UDP_COOKIE_MAP.get(&cookie) }) else {
        return 1;
    };
    if orig.family != FAMILY_V4 {
        return 1;
    }
    unsafe {
        (*ctx.sock_addr).user_ip4 =
            u32::from_ne_bytes([orig.addr[0], orig.addr[1], orig.addr[2], orig.addr[3]]);
        (*ctx.sock_addr).user_port = u32::from(orig.port);
    }
    1
}

#[cgroup_sock_addr(getpeername6)]
pub fn getpeername6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let Some(orig) = (unsafe { UDP_COOKIE_MAP.get(&cookie) }) else {
        return 1;
    };
    if orig.family != FAMILY_V6 {
        return 1;
    }
    let mut words = [0u32; 4];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_ne_bytes([
            orig.addr[i * 4],
            orig.addr[i * 4 + 1],
            orig.addr[i * 4 + 2],
            orig.addr[i * 4 + 3],
        ]);
    }
    unsafe {
        (*ctx.sock_addr).user_ip6 = words;
        (*ctx.sock_addr).user_port = u32::from(orig.port);
    }
    1
}

// ---------------------------------------------------------------------------
// sock_release — reap COOKIE_MAP entries on socket destruction.
//
// connect4 / connect6 store `(socket_cookie → orig_dst)` in COOKIE_MAP at
// connect() time. Normally skb_egress consumes the entry on the first
// outgoing packet, moving it to PORT_MAP. But many `connect()` calls never
// produce an outgoing packet:
//
//   • glibc's RFC 6724 source-address probe (UDP connect to dst:0,
//     getsockname(), close — see the dst_port=0 short-circuit above).
//   • Synchronous routing failures (ENETUNREACH, EHOSTUNREACH).
//   • Application aborts the socket between connect() and first send.
//   • TCP_FASTOPEN_CONNECT probes that never carry data.
//
// In all those cases skb_egress never fires, leaving the cookie pinned in
// COOKIE_MAP forever. cgroup_sock_release fires the moment the kernel
// destroys the socket — same socket cookie heimdall stored at connect time
// — giving us a clean reap point that doesn't depend on packet flow.
//
// Same hook Cilium uses (`cil_sock_release` shows up in `bpftool cgroup
// show` on this host). Available since kernel 5.13. The return value is
// ignored by the kernel for this attach type; we return 1 by convention.
// ---------------------------------------------------------------------------

#[cgroup_sock(sock_release)]
pub fn sock_release(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let _ = COOKIE_MAP.remove(&cookie);
    let _ = UDP_COOKIE_MAP.remove(&cookie);
    1
}

// ---------------------------------------------------------------------------
// sendmsg4 / sendmsg6 — transparent connectionless UDP relay.
//
// glibc's stub resolver uses connect()ed UDP, so connect4 catches it.
// Pure-Go binaries (netgo build tag) and some other implementations
// use raw sendto / sendmsg without a prior connect, which doesn't
// fire connect4. cgroup_sock_addr/sendmsg4 fires on every UDP send
// (sendto/sendmsg) for AF_INET sockets that aren't connected, giving
// us a chance to rewrite the destination.
//
// Each socket+destination receives a distinct token address. Unlike a source
// port key this remains unambiguous when one unconnected socket targets many
// peers or several SO_REUSEPORT sockets share one local port.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(sendmsg4)]
pub fn udp4_sendmsg(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr;
    let dst_port_be = unsafe { (*sa).user_port as u16 };
    if u16::from_be(dst_port_be) == RELAY_PORT && token_from_v4(unsafe { (*sa).user_ip4 }).is_some()
    {
        return 1;
    }
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);
    if try_hijack_dns_v4(sa, policy) {
        return 1;
    }
    if (policy & POLICY_DNS_SYSTEM) != 0 && u16::from_be(dst_port_be) == DNS_PORT {
        return 1;
    }
    if (policy & POLICY_UDP_REJECT) != 0 {
        return 0;
    }
    if (policy & POLICY_REDIRECT_OFF) != 0 {
        return 1;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let dst_ip = unsafe { (*sa).user_ip4 };
    let mut orig = OrigDst {
        addr: [0; 16],
        port: dst_port_be,
        family: FAMILY_V4,
        _pad: 0,
        cgroup_id,
        socket_cookie: cookie,
    };
    orig.addr[..4].copy_from_slice(&dst_ip.to_ne_bytes());
    let flow = UdpFlowKey {
        socket_cookie: cookie,
        cgroup_id,
        addr: orig.addr,
        port: orig.port,
        family: orig.family,
        _pad: [0; 5],
    };
    let Some(token) = udp_token(&flow, &orig) else {
        return 0;
    };
    let _ = UDP_COOKIE_MAP.insert(&cookie, &orig, 0);
    unsafe {
        (*sa).user_ip4 = token_v4(token);
        (*sa).user_port = u32::from(RELAY_PORT.to_be());
    }
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn udp6_sendmsg(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr;
    let dst_port_be = unsafe { (*sa).user_port as u16 };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);
    if try_hijack_dns_v6(sa, policy) {
        return 1;
    }
    if (policy & POLICY_DNS_SYSTEM) != 0 && u16::from_be(dst_port_be) == DNS_PORT {
        return 1;
    }
    // Linux rejects rewriting an unconnected UDP6 sendmsg destination to an
    // IPv4-mapped address with ENOTSUPP. Connected UDP6 is handled by
    // connect6 and does not need destination recovery in this hook.
    i32::from((policy & POLICY_REDIRECT_OFF) != 0)
}

#[cgroup_sock_addr(recvmsg4)]
pub fn udp4_recvmsg(ctx: SockAddrContext) -> i32 {
    let Some(token) = token_from_v4(unsafe { (*ctx.sock_addr).user_ip4 }) else {
        return 1;
    };
    let Some(orig) = (unsafe { UDP_TOKEN_MAP.get(&token) }) else {
        return 1;
    };
    if orig.family != FAMILY_V4 {
        return 1;
    }
    unsafe {
        (*ctx.sock_addr).user_ip4 =
            u32::from_ne_bytes([orig.addr[0], orig.addr[1], orig.addr[2], orig.addr[3]]);
        (*ctx.sock_addr).user_port = u32::from(orig.port);
    }
    1
}

// ---------------------------------------------------------------------------
// Program 2: on the first packet of a redirected connection, populate PORT_MAP.
//
// cgroup_skb egress fires after inet_hash_connect has assigned the ephemeral
// source port but before any Cilium TC processing. The socket cookie matches
// what connect4 stored. We read src_port from the TCP header and write
// PORT_MAP[family, src_port] = orig_dst for the relay to consume after accept().
// ---------------------------------------------------------------------------

#[cgroup_skb(egress)]
pub fn skb_egress(ctx: SkBuffContext) -> i32 {
    match try_skb_egress(&ctx) {
        Ok(()) | Err(()) => 1, // always allow; we only read metadata
    }
}

// IPv4 + transport header field offsets (IP starts at byte 0 in cgroup_skb).
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
// IPv4 protocol field is at offset 9 in the IP header.
const OFF_IPV4_PROTO: usize = 9;
// IPv6 next-header is at offset 6 in the fixed 40-byte header.
const OFF_IPV6_NEXT: usize = 6;
const IPV6_FIXED_HDR: usize = 40;

// IPv6 extension-header next-header values we know how to skip past.
// Each one (except Fragment) has a uniform layout: byte 0 = next-header,
// byte 1 = Hdr Ext Len in 8-octet units NOT including the first 8 bytes,
// so the on-wire length is `(len + 1) * 8`. Fragment (44) is a fixed 8.
//
// Reference: RFC 8200 §4 + IANA "Protocol Numbers" registry.
const IPV6_EXT_HOPOPT: u8 = 0; // Hop-by-Hop Options
const IPV6_EXT_ROUTING: u8 = 43; // Routing
const IPV6_EXT_FRAGMENT: u8 = 44; // Fragment (fixed 8-byte header)
const IPV6_EXT_DSTOPTS: u8 = 60; // Destination Options
const IPV6_EXT_MOBILITY: u8 = 135; // Mobility (RFC 6275)
const IPV6_EXT_HIP: u8 = 139; // HIP (RFC 7401)
const IPV6_EXT_SHIM6: u8 = 140; // Shim6 (RFC 5533)

/// Bounded extension-header walk. The BPF verifier rejects unbounded
/// loops; 8 ext headers is more than any real-world packet (RFC 8200
/// recommends ≤ a handful).
const MAX_IPV6_EXT_HDRS: usize = 8;

#[inline(always)]
fn try_skb_egress(ctx: &SkBuffContext) -> Result<(), ()> {
    // Detect IP version from the high nibble of the first byte.
    let ver_ihl: u8 = ctx.load(0).map_err(|_| ())?;
    let version = ver_ihl >> 4;

    let (transport_off, protocol) = match version {
        4 => {
            // IPv4: protocol at offset 9, header length encoded as IHL
            // (low nibble of byte 0, in 32-bit words).
            let proto: u8 = ctx.load(OFF_IPV4_PROTO).map_err(|_| ())?;
            if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
                return Ok(());
            }
            (((ver_ihl & 0x0f) as usize) * 4, proto)
        }
        6 => {
            // IPv6: walk the next-header chain past extension headers
            // until we hit TCP (or give up). Extension headers we
            // understand: Hop-by-Hop (0), Routing (43), Fragment (44),
            // Destination Options (60), Mobility (135), HIP (139),
            // Shim6 (140). Anything else (incl. unknown) → bail.
            let mut next: u8 = ctx.load(OFF_IPV6_NEXT).map_err(|_| ())?;
            let mut off = IPV6_FIXED_HDR;
            // Bounded loop for the verifier — enough for any realistic
            // packet (RFC 8200 hints at small fixed limits).
            for _ in 0..MAX_IPV6_EXT_HDRS {
                if next == IPPROTO_TCP || next == IPPROTO_UDP {
                    break;
                }
                let (nh, hdr_len) = match next {
                    IPV6_EXT_HOPOPT | IPV6_EXT_ROUTING | IPV6_EXT_DSTOPTS | IPV6_EXT_MOBILITY
                    | IPV6_EXT_HIP | IPV6_EXT_SHIM6 => {
                        let nh: u8 = ctx.load(off).map_err(|_| ())?;
                        let len: u8 = ctx.load(off + 1).map_err(|_| ())?;
                        (nh, (len as usize + 1) * 8)
                    }
                    IPV6_EXT_FRAGMENT => {
                        let nh: u8 = ctx.load(off).map_err(|_| ())?;
                        (nh, 8)
                    }
                    _ => return Ok(()),
                };
                next = nh;
                off += hdr_len;
            }
            if next != IPPROTO_TCP && next != IPPROTO_UDP {
                return Ok(());
            }
            (off, next)
        }
        _ => return Ok(()),
    };

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let src_port_be: u16 = ctx.load(transport_off).map_err(|_| ())?;
    let src_port = u16::from_be(src_port_be);
    let family = if version == 4 { FAMILY_V4 } else { FAMILY_V6 };
    let key = relay_key(family, src_port);

    if protocol == IPPROTO_UDP && family == FAMILY_V6 {
        if let Some(orig) = unsafe { UDP_COOKIE_MAP.get(&cookie) } {
            let _ = UDP_PORT_MAP.insert(&key, orig, 0);
        }
    } else if protocol == IPPROTO_TCP
        && let Some(orig) = unsafe { COOKIE_MAP.get(&cookie) }
    {
        let _ = PORT_MAP.insert(&key, orig, 0);
        let _ = COOKIE_MAP.remove(&cookie);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
