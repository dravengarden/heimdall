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
    is_default_bypass, BypassEvent, OrigDst, TapDir, TapEvent, DEFAULT_POLICY,
    POLICY_NO_BYPASS_LOG, POLICY_OBSERVE_OFF, POLICY_REDIRECT_OFF, TAP_DATA_LEN,
};

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

    let kernel_bypass = is_default_bypass(dst_ip_be);
    let user_bypass = (policy & POLICY_REDIRECT_OFF) != 0;

    if kernel_bypass || user_bypass {
        // Emit a synthetic-flow event unless the policy disables both
        // observation and bypass logging. Userspace correlates tap
        // plaintext to flow_id via cgroup_id, so bypass logging is
        // wasted unless we'd actually observe.
        if (policy & POLICY_OBSERVE_OFF) == 0 && (policy & POLICY_NO_BYPASS_LOG) == 0 {
            let bypass_ev = BypassEvent {
                ts_ns: unsafe { bpf_ktime_get_ns() },
                cgroup_id,
                socket_cookie: cookie,
                dst_ip_be,
                dst_port_be,
                _pad: 0,
            };
            BYPASS_EVENTS.output(&ctx, &bypass_ev, 0);
        }
        return Ok(());
    }
    let orig = OrigDst {
        ip: dst_ip_be,
        port: dst_port_be,
        _pad: 0,
        cgroup_id,
        socket_cookie: cookie,
    };
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
