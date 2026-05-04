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
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_socket_cookie,
        bpf_ktime_get_ns, gen::bpf_probe_read_user,
    },
    macros::{cgroup_skb, cgroup_sock_addr, map, uprobe, uretprobe},
    maps::{Array, HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext, SkBuffContext, SockAddrContext},
    EbpfContext,
};
use heimdall_common::{
    is_default_bypass, is_default_bypass6, BypassEvent, OrigDst, TapDir, TapEvent,
    DEFAULT_POLICY, FAMILY_V4, FAMILY_V6, POLICY_DNS_HIJACK, POLICY_NO_BYPASS_LOG,
    POLICY_OBSERVE_OFF, POLICY_REDIRECT_OFF, TAP_DATA_LEN,
};

const PROXY_PORT: u16 = 12345;
const DNS_PORT: u16 = 53;

// Relay IPv4 address in network byte order, set by userspace at startup.
#[map]
static RELAY_ADDR: Array<u32> = Array::with_max_entries(2, 0);

// Relay IPv6 address (16 bytes, network byte order) — set by userspace
// at startup whenever `runtime.relay_ip6` is configured. Stored as a
// 4×u32 array so it's a flat POD for the verifier.
#[map]
static RELAY_ADDR6: Array<[u8; 16]> = Array::with_max_entries(1, 0);

// Heimdall fake-IP DNS endpoint, IPv4. Slot 0 = ip in network byte
// order, slot 1 = port in network byte order (16-bit value stored in
// u32 lower bits). Populated at startup from runtime.dnsListen.
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
#[map]
static COOKIE_MAP: HashMap<u64, OrigDst> = HashMap::with_max_entries(65536, 0);

// Stage-2 map: client_ephemeral_port → original destination
// Populated in skb_egress, consumed by the userspace relay after accept().
#[map]
static PORT_MAP: HashMap<u32, OrigDst> = HashMap::with_max_entries(65536, 0);

// Phase B: bypass notifications. Connect4 emits one event per bypassed
// connection (loopback / LAN / k0s pod-or-service CIDR) so userspace can
// record a synthetic flow row and let tap events correlate to it.
#[map]
static BYPASS_EVENTS: PerfEventArray<BypassEvent> = PerfEventArray::new(0);

// Per-cgroup policy. Userspace populates this from PodInformer + routing
// rules; eBPF programs read it once per syscall to decide whether to
// redirect / observe / log.
#[map]
static CGROUP_POLICY: HashMap<u64, u8> = HashMap::with_max_entries(65536, 0);

#[inline(always)]
fn policy_for(cgroup_id: u64) -> u8 {
    unsafe { CGROUP_POLICY.get(&cgroup_id) }
        .copied()
        .unwrap_or(DEFAULT_POLICY)
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
// return early (don't store in COOKIE_MAP, don't emit BypassEvent, don't
// run any other redirect logic).
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

    let kernel_bypass = is_default_bypass(dst_ip_be);
    let user_bypass = (policy & POLICY_REDIRECT_OFF) != 0;

    if kernel_bypass || user_bypass {
        if (policy & POLICY_OBSERVE_OFF) == 0 && (policy & POLICY_NO_BYPASS_LOG) == 0 {
            let mut bypass_ev = BypassEvent {
                ts_ns: unsafe { bpf_ktime_get_ns() },
                cgroup_id,
                socket_cookie: cookie,
                dst_addr: [0u8; 16],
                dst_port_be,
                family: FAMILY_V4,
                _pad: 0,
            };
            // Store IPv4 in the first 4 bytes (network byte order).
            let ip_bytes = dst_ip_be.to_ne_bytes();
            bypass_ev.dst_addr[0] = ip_bytes[0];
            bypass_ev.dst_addr[1] = ip_bytes[1];
            bypass_ev.dst_addr[2] = ip_bytes[2];
            bypass_ev.dst_addr[3] = ip_bytes[3];
            BYPASS_EVENTS.output(&ctx, &bypass_ev, 0);
        }
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
    COOKIE_MAP.insert(&cookie, &orig, 0).map_err(|_| ())?;

    unsafe {
        (*sa).user_ip4 = relay_ip_be;
        (*sa).user_port = u32::from(PROXY_PORT.to_be());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// connect6 — IPv6 sibling of connect4.
//
// Mirror logic: read user_ip6 + user_port from the sock_addr, consult
// CGROUP_POLICY + is_default_bypass6, either emit a BypassEvent (with
// family=FAMILY_V6) or rewrite the destination to RELAY_ADDR6 + PROXY_PORT.
// COOKIE_MAP entries from connect6 carry family=FAMILY_V6 so userspace
// + skb_egress can decode the address bytes correctly.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(ctx) {
        Ok(()) | Err(()) => 1,
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
        dst_addr[i * 4]     = b[0];
        dst_addr[i * 4 + 1] = b[1];
        dst_addr[i * 4 + 2] = b[2];
        dst_addr[i * 4 + 3] = b[3];
    }

    // Self-loop check — already going to the relay's v6 address+port.
    if dst_addr == relay6 && u16::from_be(dst_port_be) == PROXY_PORT {
        return Ok(());
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);

    // DNS hijack — same semantics as connect4 but for v6 sockets.
    if try_hijack_dns_v6(sa, policy) {
        return Ok(());
    }

    let kernel_bypass = is_default_bypass6(&dst_addr);
    let user_bypass = (policy & POLICY_REDIRECT_OFF) != 0;

    if kernel_bypass || user_bypass {
        if (policy & POLICY_OBSERVE_OFF) == 0 && (policy & POLICY_NO_BYPASS_LOG) == 0 {
            let bypass_ev = BypassEvent {
                ts_ns: unsafe { bpf_ktime_get_ns() },
                cgroup_id,
                socket_cookie: cookie,
                dst_addr,
                dst_port_be,
                family: FAMILY_V6,
                _pad: 0,
            };
            BYPASS_EVENTS.output(&ctx, &bypass_ev, 0);
        }
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
    COOKIE_MAP.insert(&cookie, &orig, 0).map_err(|_| ())?;

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
        (*sa).user_port = u32::from(PROXY_PORT.to_be());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sendmsg4 / sendmsg6 — DNS-only hijack for connectionless UDP.
//
// glibc's stub resolver uses connect()ed UDP, so connect4 catches it.
// Pure-Go binaries (netgo build tag) and some other implementations
// use raw sendto / sendmsg without a prior connect, which doesn't
// fire connect4. cgroup_sock_addr/sendmsg4 fires on every UDP send
// (sendto/sendmsg) for AF_INET sockets that aren't connected, giving
// us a chance to rewrite the destination.
//
// We DON'T hijack non-DNS UDP traffic — relay-side TCP redirection
// for arbitrary UDP would require holding state per-connection (no
// 5-tuple), which heimdall doesn't do. So this is strictly a DNS
// rewrite gate: same logic as connect4 but bails out for everything
// except the dst:53 case.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(sendmsg4)]
pub fn udp4_sendmsg(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);
    let _ = try_hijack_dns_v4(sa, policy);
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn udp6_sendmsg(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let policy = policy_for(cgroup_id);
    let _ = try_hijack_dns_v6(sa, policy);
    1
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
const IPPROTO_TCP: u8 = 6;
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
const IPV6_EXT_HOPOPT: u8 = 0;       // Hop-by-Hop Options
const IPV6_EXT_ROUTING: u8 = 43;     // Routing
const IPV6_EXT_FRAGMENT: u8 = 44;    // Fragment (fixed 8-byte header)
const IPV6_EXT_DSTOPTS: u8 = 60;     // Destination Options
const IPV6_EXT_MOBILITY: u8 = 135;   // Mobility (RFC 6275)
const IPV6_EXT_HIP: u8 = 139;        // HIP (RFC 7401)
const IPV6_EXT_SHIM6: u8 = 140;      // Shim6 (RFC 5533)

/// Bounded extension-header walk. The BPF verifier rejects unbounded
/// loops; 8 ext headers is more than any real-world packet (RFC 8200
/// recommends ≤ a handful).
const MAX_IPV6_EXT_HDRS: usize = 8;

#[inline(always)]
fn try_skb_egress(ctx: &SkBuffContext) -> Result<(), ()> {
    // Detect IP version from the high nibble of the first byte.
    let ver_ihl: u8 = ctx.load(0).map_err(|_| ())?;
    let version = ver_ihl >> 4;

    let tcp_off = match version {
        4 => {
            // IPv4: protocol at offset 9, header length encoded as IHL
            // (low nibble of byte 0, in 32-bit words).
            let proto: u8 = ctx.load(OFF_IPV4_PROTO).map_err(|_| ())?;
            if proto != IPPROTO_TCP {
                return Ok(());
            }
            ((ver_ihl & 0x0f) as usize) * 4
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
                if next == IPPROTO_TCP {
                    break;
                }
                let (nh, hdr_len) = match next {
                    IPV6_EXT_HOPOPT
                    | IPV6_EXT_ROUTING
                    | IPV6_EXT_DSTOPTS
                    | IPV6_EXT_MOBILITY
                    | IPV6_EXT_HIP
                    | IPV6_EXT_SHIM6 => {
                        let nh: u8 = ctx.load(off).map_err(|_| ())?;
                        let len: u8 = ctx.load(off + 1).map_err(|_| ())?;
                        (nh, (len as usize + 1) * 8)
                    }
                    IPV6_EXT_FRAGMENT => {
                        let nh: u8 = ctx.load(off).map_err(|_| ())?;
                        (nh, 8)
                    }
                    _ => return Ok(()), // not TCP and not an ext header we know
                };
                next = nh;
                off += hdr_len;
            }
            if next != IPPROTO_TCP {
                return Ok(());
            }
            off
        }
        _ => return Ok(()),
    };

    // Look up COOKIE_MAP for this socket. Only intercepted connections have entries.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let orig = match unsafe { COOKIE_MAP.get(&cookie) } {
        Some(v) => *v,
        None => return Ok(()),
    };

    // Read TCP source port (network byte order → host byte order).
    // inet_hash_connect has already assigned this ephemeral port.
    let src_port_be: u16 = ctx.load(tcp_off).map_err(|_| ())?;
    let src_port = u16::from_be(src_port_be) as u32;

    PORT_MAP.insert(&src_port, &orig, 0).map_err(|_| ())?;
    let _ = COOKIE_MAP.remove(&cookie);

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase B uprobes — capture TLS plaintext at the libssl boundary.
//
// SSL_write(SSL *ssl, const void *buf, int num)
//   x86_64 SysV: rdi=ssl, rsi=buf, rdx=num
// SSL_read(SSL *ssl, void *buf, int num)
//   entry: stash buf pointer keyed by tgid_pid
//   ret  : look up state, read `ret` bytes from buf, emit
// ---------------------------------------------------------------------------

#[map]
static TAP_EVENTS: PerfEventArray<TapEvent> = PerfEventArray::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadEntry {
    buf: u64,
}

#[map]
static SSL_READ_STATE: HashMap<u64, ReadEntry> = HashMap::with_max_entries(8192, 0);

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    let _ = try_ssl_write(&ctx);
    0
}

#[inline(always)]
fn try_ssl_write(ctx: &ProbeContext) -> Result<(), ()> {
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;
    if num <= 0 || buf.is_null() {
        return Ok(());
    }
    emit_tap(ctx, TapDir::Send, num as u32, buf);
    Ok(())
}

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    let _ = try_ssl_read_enter(&ctx);
    0
}

#[inline(always)]
fn try_ssl_read_enter(ctx: &ProbeContext) -> Result<(), ()> {
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = ReadEntry { buf: buf as u64 };
    let _ = SSL_READ_STATE.insert(&pid_tgid, &entry, 0);
    Ok(())
}

#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_ssl_read_exit(&ctx);
    0
}

// ---------------------------------------------------------------------------
// Go TLS: crypto/tls.(*Conn).Write — entry probe.
//
// Go uses its own ABI ("ABI Internal", x86_64). For methods on *Conn:
//   func (c *Conn) Write(b []byte) (n int, err error)
//
// Register layout at entry:
//   RAX = receiver  (*Conn)
//   RBX = b.data    (slice ptr)
//   RCX = b.len
//   RDI = b.cap     (unused here)
//
// We don't try to attach a uretprobe — the kernel's uretprobe trampoline
// patches the user-space stack, which collides with the Go runtime's
// movable stacks. The send-side write probe is enough to surface
// outbound HTTP requests (URL, headers, body) without needing the
// return value.
// ---------------------------------------------------------------------------

#[uprobe]
pub fn go_tls_write(ctx: ProbeContext) -> u32 {
    let _ = try_go_tls_write(&ctx);
    0
}

#[inline(always)]
fn try_go_tls_write(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = unsafe { &*ctx.regs };
    let buf = regs.rbx as *const u8;
    let num = regs.rcx as i64;
    if num <= 0 || buf.is_null() {
        return Ok(());
    }
    let total = if num > i32::MAX as i64 { i32::MAX as u32 } else { num as u32 };
    emit_tap(ctx, TapDir::Send, total, buf);
    Ok(())
}

// ---------------------------------------------------------------------------
// Go TLS: crypto/tls.(*Conn).Read — paired entry + return probes.
//
//   func (c *Conn) Read(b []byte) (n int, err error)
//
// At entry:  RAX=*Conn, RBX=b.data, RCX=b.len, RDI=b.cap
// At return: RAX=n, RBX=err.tab, RCX=err.data
//
// We can't use a uretprobe here because the kernel's uretprobe trampoline
// rewrites the return address, which collides with Go's stack-growth
// machinery (movable stacks copy frames around and the trampoline anchor
// gets stale). The standard mitigation, used by Pixie and Coroot, is to
// disassemble the function in userspace, find every RET instruction, and
// attach a regular uprobe at each one. At those uprobes we read RAX as
// the syscall return value.
//
// `go_tls_read_enter` stashes the buf pointer keyed by pid_tgid;
// `go_tls_read_ret` reads RAX (return n) and copies n bytes from the
// stashed buf.
// ---------------------------------------------------------------------------

#[map]
static GO_READ_STATE: HashMap<u64, ReadEntry> = HashMap::with_max_entries(8192, 0);

#[uprobe]
pub fn go_tls_read_enter(ctx: ProbeContext) -> u32 {
    let _ = try_go_tls_read_enter(&ctx);
    0
}

#[inline(always)]
fn try_go_tls_read_enter(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = unsafe { &*ctx.regs };
    let buf = regs.rbx;
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = ReadEntry { buf };
    let _ = GO_READ_STATE.insert(&pid_tgid, &entry, 0);
    Ok(())
}

#[uprobe]
pub fn go_tls_read_ret(ctx: ProbeContext) -> u32 {
    let _ = try_go_tls_read_ret(&ctx);
    0
}

// ---------------------------------------------------------------------------
// rustls — paired entry + uretprobe pair on PlaintextSink::write and
// <Reader as io::Read>::read.
//
// Unlike Go, Rust binaries have a fixed (non-movable) stack and are
// uretprobe-safe. So the read side uses a real uretprobe — no need to
// disassemble for RET offsets.
//
// Rust uses the SysV ABI on x86_64 for these `&mut self, &[u8]` →
// `io::Result<usize>` methods:
//
//   At entry:
//     RDI = &mut self        (PlaintextSink / Reader)
//     RSI = buf.as_ptr()     (slice data)
//     RDX = buf.len()        (slice length)
//
//   At return (`io::Result<usize>` is 16 bytes; passed in (RAX, RDX)):
//     RAX = enum discriminant in low byte (0 = Ok, 1 = Err)
//     RDX = the value (Ok→ usize n, Err→ error pointer)
//
// We trust that layout; if the captured plaintext looks right
// (HTTP/2 frames, JSON, etc.) the ABI assumption is correct. If the
// compiler ever switches to a different niche-packed layout for
// `Result<usize, io::Error>`, this would need updating.
// ---------------------------------------------------------------------------

#[map]
static RUSTLS_READ_STATE: HashMap<u64, ReadEntry> = HashMap::with_max_entries(8192, 0);

#[uprobe]
pub fn rustls_write(ctx: ProbeContext) -> u32 {
    let _ = try_rustls_write(&ctx);
    0
}

#[inline(always)]
fn try_rustls_write(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = unsafe { &*ctx.regs };
    let buf = regs.rsi as *const u8;
    let num = regs.rdx as i64;
    if num <= 0 || buf.is_null() {
        return Ok(());
    }
    let total = if num > i32::MAX as i64 { i32::MAX as u32 } else { num as u32 };
    emit_tap(ctx, TapDir::Send, total, buf);
    Ok(())
}

#[uprobe]
pub fn rustls_read_enter(ctx: ProbeContext) -> u32 {
    let _ = try_rustls_read_enter(&ctx);
    0
}

#[inline(always)]
fn try_rustls_read_enter(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = unsafe { &*ctx.regs };
    let buf = regs.rsi;
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = ReadEntry { buf };
    let _ = RUSTLS_READ_STATE.insert(&pid_tgid, &entry, 0);
    Ok(())
}

#[uretprobe]
pub fn rustls_read_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_rustls_read_exit(&ctx);
    0
}

#[inline(always)]
fn try_rustls_read_exit(ctx: &RetProbeContext) -> Result<(), ()> {
    let regs = unsafe { &*ctx.regs };
    // Discriminant in low byte of RAX. 0 = Ok, anything else = Err.
    if (regs.rax & 0xFF) != 0 {
        return Ok(());
    }
    let n = regs.rdx as i64;
    if n <= 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match unsafe { RUSTLS_READ_STATE.get(&pid_tgid) } {
        Some(e) => *e,
        None => return Ok(()),
    };
    let _ = RUSTLS_READ_STATE.remove(&pid_tgid);

    let buf = entry.buf as *const u8;
    if buf.is_null() {
        return Ok(());
    }
    let total = if n > i32::MAX as i64 { i32::MAX as u32 } else { n as u32 };
    emit_tap_ret(ctx, TapDir::Recv, total, buf);
    Ok(())
}

#[inline(always)]
fn try_go_tls_read_ret(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = unsafe { &*ctx.regs };
    let n = regs.rax as i64;
    if n <= 0 {
        return Ok(());
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match unsafe { GO_READ_STATE.get(&pid_tgid) } {
        Some(e) => *e,
        None => return Ok(()),
    };
    let _ = GO_READ_STATE.remove(&pid_tgid);
    let buf = entry.buf as *const u8;
    if buf.is_null() {
        return Ok(());
    }
    let total = if n > i32::MAX as i64 { i32::MAX as u32 } else { n as u32 };
    emit_tap(ctx, TapDir::Recv, total, buf);
    Ok(())
}

#[inline(always)]
fn try_ssl_read_exit(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match unsafe { SSL_READ_STATE.get(&pid_tgid) } {
        Some(e) => *e,
        None => return Ok(()),
    };
    let _ = SSL_READ_STATE.remove(&pid_tgid);

    let ret: i32 = ctx.ret().ok_or(())?;
    if ret <= 0 {
        return Ok(());
    }
    let buf = entry.buf as *const u8;
    if buf.is_null() {
        return Ok(());
    }
    // Build a `ProbeContext`-shaped wrapper for emit_tap; ret context has
    // its own ctx.as_ptr() — but PerfEventArray::output accepts any
    // ContextLike, so we cast through `EbpfContext`.
    emit_tap_ret(ctx, TapDir::Recv, ret as u32, buf);
    Ok(())
}

// Emit a TapEvent. `total` is the application-visible length, `buf` is
// the userspace pointer we'll read up to TAP_DATA_LEN bytes from.
#[inline(always)]
fn emit_tap(ctx: &ProbeContext, dir: TapDir, total: u32, buf: *const u8) {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if (policy_for(cgroup_id) & POLICY_OBSERVE_OFF) != 0 {
        return;
    }
    let mut ev: TapEvent = unsafe { core::mem::zeroed() };
    ev.tgid_pid = bpf_get_current_pid_tgid();
    ev.ts_ns = unsafe { bpf_ktime_get_ns() };
    ev.cgroup_id = cgroup_id;
    ev.dir = dir as u32;
    ev.total_len = total;
    ev.captured_len = if total > TAP_DATA_LEN as u32 {
        TAP_DATA_LEN as u32
    } else {
        total
    };
    unsafe {
        let _ = bpf_probe_read_user(
            ev.data.as_mut_ptr() as *mut _,
            ev.captured_len,
            buf as *const _,
        );
    }
    TAP_EVENTS.output(ctx, &ev, 0);
}

#[inline(always)]
fn emit_tap_ret(ctx: &RetProbeContext, dir: TapDir, total: u32, buf: *const u8) {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if (policy_for(cgroup_id) & POLICY_OBSERVE_OFF) != 0 {
        return;
    }
    let mut ev: TapEvent = unsafe { core::mem::zeroed() };
    ev.tgid_pid = bpf_get_current_pid_tgid();
    ev.ts_ns = unsafe { bpf_ktime_get_ns() };
    ev.cgroup_id = cgroup_id;
    ev.dir = dir as u32;
    ev.total_len = total;
    ev.captured_len = if total > TAP_DATA_LEN as u32 {
        TAP_DATA_LEN as u32
    } else {
        total
    };
    unsafe {
        let _ = bpf_probe_read_user(
            ev.data.as_mut_ptr() as *mut _,
            ev.captured_len,
            buf as *const _,
        );
    }
    TAP_EVENTS.output(ctx, &ev, 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
