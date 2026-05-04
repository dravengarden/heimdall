//! Types shared between the eBPF kernel programs and the userspace daemon.
#![cfg_attr(not(feature = "user"), no_std)]

/// Original connection destination + caller identity, saved by the eBPF
/// connect4 hook for the userspace relay to consume after accept().
///
/// `ip` and `port` are in network byte order. `cgroup_id` is the leaf
/// cgroup id of the calling process (from `bpf_get_current_cgroup_id`),
/// used by userspace to resolve pod identity (labels / annotations).
/// `socket_cookie` is the kernel's per-socket identifier
/// (`bpf_get_socket_cookie`); the userspace relay uses it to correlate
/// a flow with TLS plaintext events emitted by the tap (Phase B
/// uprobes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OrigDst {
    /// IPv4 destination address (network byte order)
    pub ip: u32,
    /// TCP destination port (network byte order)
    pub port: u16,
    pub _pad: u16,
    /// Leaf cgroup id of the process that called connect().
    /// 0 if not captured (older builds; treat as "unknown pod").
    pub cgroup_id: u64,
    /// Kernel socket cookie of the underlying TCP socket (set by
    /// `bpf_get_socket_cookie` in connect4). Stable for the lifetime of
    /// the connection and shared with eBPF kprobes / uprobes that can
    /// look up the same cookie on the same socket.
    pub socket_cookie: u64,
}

// ---------------------------------------------------------------------------
// Phase B — TLS plaintext tap
// ---------------------------------------------------------------------------

/// Direction of a [`TapEvent`].
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum TapDir {
    Send = 0,
    Recv = 1,
}

/// Inline buffer length for [`TapEvent::data`]. Values above this are
/// truncated; userspace records `total_len` separately so it knows how
/// many bytes were really written/read.
pub const TAP_DATA_LEN: usize = 256;

/// Single SSL_write entry / SSL_read return event emitted by an eBPF
/// uprobe to a perf event array. Fixed-size so the verifier is happy.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TapEvent {
    /// `bpf_get_current_pid_tgid`: high 32 bits = tgid, low 32 = pid.
    pub tgid_pid: u64,
    /// `bpf_ktime_get_ns()` at uprobe entry/return.
    pub ts_ns: u64,
    /// `bpf_get_current_cgroup_id()` of the calling task. Userspace uses
    /// this to correlate the captured plaintext with a flow recorded by
    /// the relay (which stamped the same cgroup_id at connect4 time).
    pub cgroup_id: u64,
    /// 0 = send (SSL_write), 1 = recv (SSL_read return).
    pub dir: u32,
    /// Bytes captured into `data` (≤ TAP_DATA_LEN).
    pub captured_len: u32,
    /// SSL_write's `num` argument or SSL_read's return value (full size
    /// the application asked for / received).
    pub total_len: u32,
    pub _pad: u32,
    pub data: [u8; TAP_DATA_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TapEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OrigDst {}

// ---------------------------------------------------------------------------
// Bypass notifications — emitted by connect4 when a destination falls into
// `is_default_bypass` (so the relay never sees the connection). Userspace
// uses these to create synthetic flow rows and populate the open-flow index
// so plaintext events captured by the libssl / Go uprobes can still
// correlate to a flow_id in the messages table.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BypassEvent {
    /// Kernel monotonic time at the connect4 hook.
    pub ts_ns: u64,
    /// `bpf_get_current_cgroup_id()` of the calling task.
    pub cgroup_id: u64,
    /// `bpf_get_socket_cookie()` — stable per-socket id, shared with
    /// the tap so future kprobe-based correlation can join on it.
    pub socket_cookie: u64,
    /// Destination IPv4 address in network byte order.
    pub dst_ip_be: u32,
    /// Destination TCP port in network byte order.
    pub dst_port_be: u16,
    pub _pad: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BypassEvent {}

/// Returns true if the given IPv4 address (network byte order) should bypass
/// the proxy entirely (eBPF connect4 won't redirect it).
///
/// Bypass policy is **deliberately narrow** so that anything routable through
/// an upstream proxy (corporate VPN, etc.) actually reaches heimdall:
///
/// | CIDR              | Why                                                |
/// |-------------------|----------------------------------------------------|
/// | 0.0.0.0           | Invalid, never proxy                               |
/// | 127.0.0.0/8       | Loopback (relay self, sidecars)                    |
/// | 169.254.0.0/16    | Link-local (kubelet, AWS metadata, etc.)           |
/// | 192.168.0.0/16    | LAN (router, host IP, Mac)                         |
/// | 10.244.0.0/16     | k0s pod CIDR — pod-to-pod must be direct          |
/// | 10.96.0.0/12      | k0s service CIDR — pod-to-service must be direct  |
///
/// Notably, **the broader RFC-1918 ranges (other 10/8 + 172.16/12) are NOT
/// bypassed** — those address spaces are commonly used by corporate VPNs
/// (e.g. Corp-internal). Pod traffic to such IPs goes through heimdall,
/// gets routed via the chosen connection (e.g. corp), and the upstream
/// proxy decides how to reach them.
///
/// Userspace can extend the bypass set at runtime via `runtime.bypassCidrs`
/// (not yet wired into the eBPF map; tracked for M5+).
pub fn is_default_bypass(ip_be: u32) -> bool {
    let ip = u32::from_be(ip_be);
    ip == 0                              // 0.0.0.0
    || ip >> 24 == 127                   // 127.0.0.0/8     loopback
    || ip >> 16 == 0xA9FE                // 169.254.0.0/16  link-local
    || ip >> 16 == 0xC0A8                // 192.168.0.0/16  LAN
    || ip >> 16 == 0x0AF4                // 10.244.0.0/16   k0s pod CIDR
    || ip >> 20 == 0x0A6                 // 10.96.0.0/12    k0s service CIDR
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: convert host-order IPv4 octets to a network-byte-order u32
    /// matching the format the eBPF hook receives.
    fn be(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_ne_bytes([a, b, c, d])
    }

    #[test]
    fn bypasses_loopback() {
        assert!(is_default_bypass(be(127, 0, 0, 1)));
        assert!(is_default_bypass(be(127, 255, 255, 254)));
    }

    #[test]
    fn bypasses_link_local() {
        assert!(is_default_bypass(be(169, 254, 169, 254)));
    }

    #[test]
    fn bypasses_lan_192_168() {
        assert!(is_default_bypass(be(192, 168, 0, 1)));     // router
        assert!(is_default_bypass(be(192, 168, 0, 96)));    // host
        assert!(is_default_bypass(be(192, 168, 0, 155)));   // Mac
        assert!(is_default_bypass(be(192, 168, 255, 255)));
    }

    #[test]
    fn bypasses_k0s_pod_cidr() {
        assert!(is_default_bypass(be(10, 244, 0, 1)));      // pod CIDR start
        assert!(is_default_bypass(be(10, 244, 255, 254)));  // pod CIDR end
    }

    #[test]
    fn bypasses_k0s_service_cidr() {
        assert!(is_default_bypass(be(10, 96, 0, 10)));      // CoreDNS
        assert!(is_default_bypass(be(10, 96, 0, 1)));       // apiserver
        assert!(is_default_bypass(be(10, 111, 255, 254)));  // /12 last
    }

    #[test]
    fn does_not_bypass_corporate_10_space() {
        // The whole point of narrowing the bypass list: 10.x.x.x outside
        // the cluster's two CIDRs must hit heimdall, so a routing rule
        // can send it via a corp-VPN-aware connection.
        assert!(!is_default_bypass(be(10, 0, 0, 1)));
        assert!(!is_default_bypass(be(10, 50, 1, 2)));
        assert!(!is_default_bypass(be(10, 112, 0, 1)));   // just past 10.96/12
        assert!(!is_default_bypass(be(10, 245, 0, 1)));   // just past 10.244/16
        assert!(!is_default_bypass(be(10, 255, 255, 254)));
    }

    #[test]
    fn does_not_bypass_172_16_or_other_rfc1918() {
        // 172.16/12 may also be corporate-VPN territory.
        assert!(!is_default_bypass(be(172, 16, 0, 1)));
        assert!(!is_default_bypass(be(172, 31, 255, 254)));
    }

    #[test]
    fn does_not_bypass_public() {
        assert!(!is_default_bypass(be(1, 1, 1, 1)));
        assert!(!is_default_bypass(be(8, 8, 8, 8)));
        assert!(!is_default_bypass(be(104, 16, 123, 96)));
    }
}
