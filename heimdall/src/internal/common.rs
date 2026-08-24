//! Types shared between the eBPF kernel programs and the foreground CLI.

/// Original flow destination + caller identity, saved by the eBPF
/// `connect4` / `connect6` hooks for the userspace relay to consume after
/// `accept()`.
///
/// Dual-stack: `addr` holds the destination address bytes in network
/// byte order, `family` discriminates IPv4 vs IPv6, and `port` is in
/// network byte order. For IPv4 only the first 4 bytes of `addr` are
/// significant (rest are zero); for IPv6 all 16 bytes.
///
/// `cgroup_id` is the leaf cgroup id of the calling process (from
/// `bpf_get_current_cgroup_id`). `socket_cookie` is the kernel's
/// per-socket identifier (`bpf_get_socket_cookie`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OrigDst {
    /// Destination address (network byte order). For IPv4, bytes 0..4
    /// hold the address and bytes 4..16 are zero.
    pub addr: [u8; 16],
    /// Transport destination port (network byte order)
    pub port: u16,
    /// `AF_INET` (4) or `AF_INET6` (6) — which `addr` slice is valid.
    /// Stored as the wire-protocol family number directly.
    pub family: u8,
    #[allow(
        clippy::pub_underscore_fields,
        reason = "the explicit ABI padding is shared with eBPF"
    )]
    pub _pad: u8,
    /// Leaf cgroup id of the process that opened or sent on the socket.
    /// 0 if not captured (older builds; treat as "unknown unit").
    pub cgroup_id: u64,
    /// Kernel socket cookie of the underlying transport socket. Stable for the
    /// socket lifetime.
    pub socket_cookie: u64,
}

/// Stable identity for one UDP socket and one destination. Connectionless
/// sockets may have several entries because every `sendmsg()` peer needs its
/// own reversible relay token.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpFlowKey {
    pub socket_cookie: u64,
    pub cgroup_id: u64,
    pub addr: [u8; 16],
    pub port: u16,
    pub family: u8,
    #[allow(
        clippy::pub_underscore_fields,
        reason = "the explicit ABI padding is shared with eBPF"
    )]
    pub _pad: [u8; 5],
}

/// Family discriminator values stored in `OrigDst::family`. We use the
/// wire-protocol numbers (matching `AF_INET` / `AF_INET6` on Linux) so
/// the BPF side and userspace can compare against the same constants
/// without depending on libc.
pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum TapDir {
    Send = 0,
    Recv = 1,
}

pub const TAP_DATA_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TapEvent {
    pub tgid_pid: u64,
    pub cgroup_id: u64,
    pub dir: u32,
    pub captured_len: u32,
    pub total_len: u32,
    #[allow(
        clippy::pub_underscore_fields,
        reason = "the explicit ABI padding is shared with eBPF"
    )]
    pub _pad: u32,
    pub data: [u8; TAP_DATA_LEN],
}

/// Correlate a redirected relay connection without allowing IPv4 and IPv6
/// sockets that reuse the same ephemeral port to overwrite each other.
#[must_use]
pub const fn relay_key(family: u8, source_port: u16) -> u32 {
    (family as u32) << 16 | source_port as u32
}

// ---------------------------------------------------------------------------
// Per-cgroup policy flags written by `heimdall run` and read by the eBPF
// programs for each intercepted syscall.
//
// A map miss bypasses heimdall. Only cgroups registered by `heimdall run`
// are redirected.
// ---------------------------------------------------------------------------

/// Skip eBPF connect4 redirect — let the kernel route the connection
/// natively. Used for units / `heimdall run` profiles resolving to
/// `use: system`.
pub const POLICY_REDIRECT_OFF: u8 = 1 << 0;

/// Hijack DNS for this cgroup: any TCP/UDP connect or UDP sendmsg to
/// port 53 gets its destination rewritten to heimdall's fake-IP DNS
/// server (taken from `DNS_ADDR_V4` / `DNS_ADDR_V6` maps). Used by
/// `heimdall run` when the wrapped command's profile resolves to
/// `dns: fake`, so the child uses heimdall's resolver instead of the
/// host's systemd-resolved / /etc/resolv.conf.
pub const POLICY_DNS_HIJACK: u8 = 1 << 1;

/// Reject non-DNS UDP for a registered cgroup. The connect hooks cover
/// connected datagram sockets and the sendmsg hooks cover connectionless UDP.
/// DNS hijack is evaluated first so fake DNS remains usable.
pub const POLICY_UDP_REJECT: u8 = 1 << 2;

/// Allow DNS port 53 to use the host resolver. Without this explicit flag,
/// fail-closed UDP policy would also block `dns.mode = system`.
pub const POLICY_DNS_SYSTEM: u8 = 1 << 3;

/// Default for cgroups not present in `CGROUP_POLICY`: bypass heimdall.
pub const DEFAULT_POLICY: u8 = POLICY_REDIRECT_OFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_key_separates_address_families_and_ports() {
        assert_ne!(relay_key(FAMILY_V4, 40_000), relay_key(FAMILY_V6, 40_000));
        assert_ne!(relay_key(FAMILY_V4, 40_000), relay_key(FAMILY_V4, 40_001));
    }
}
