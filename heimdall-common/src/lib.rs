//! Types shared between the eBPF kernel programs and the userspace daemon.
#![cfg_attr(not(feature = "user"), no_std)]

/// Original connection destination + caller identity, saved by the eBPF
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
    /// TCP destination port (network byte order)
    pub port: u16,
    /// `AF_INET` (4) or `AF_INET6` (6) — which `addr` slice is valid.
    /// Stored as the wire-protocol family number directly.
    pub family: u8,
    #[allow(
        clippy::pub_underscore_fields,
        reason = "the explicit ABI padding is shared with eBPF"
    )]
    pub _pad: u8,
    /// Leaf cgroup id of the process that called `connect()`.
    /// 0 if not captured (older builds; treat as "unknown unit").
    pub cgroup_id: u64,
    /// Kernel socket cookie of the underlying TCP socket (set by
    /// `bpf_get_socket_cookie` in connect4 / connect6). Stable for the
    /// lifetime of the connection.
    pub socket_cookie: u64,
}

/// Family discriminator values stored in `OrigDst::family`. We use the
/// wire-protocol numbers (matching `AF_INET` / `AF_INET6` on Linux) so
/// the BPF side and userspace can compare against the same constants
/// without depending on libc.
pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

#[cfg(feature = "user")]
#[allow(
    unsafe_code,
    reason = "repr(C) contains only fixed-width Pod fields shared verbatim with eBPF"
)]
unsafe impl aya::Pod for OrigDst {}

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

/// Default for cgroups not present in `CGROUP_POLICY`: bypass heimdall.
pub const DEFAULT_POLICY: u8 = POLICY_REDIRECT_OFF;

/// Returns true if the given IPv4 address (network byte order) should bypass
/// the proxy entirely (eBPF connect4 won't redirect it).
///
/// Bypass policy is **deliberately narrow** so that anything routable through
/// an upstream proxy (corporate VPN, etc.) actually reaches heimdall:
///
/// | CIDR              | Why                                                |
/// |-------------------|----------------------------------------------------|
/// | 0.0.0.0           | Invalid, never proxy                               |
/// | 127.0.0.0/8       | Loopback (relay self, host-local services)         |
/// | 169.254.0.0/16    | Link-local (cloud metadata, etc.)                  |
/// | 192.168.0.0/16    | LAN (router, host IP, upstream box)                |
///
/// Notably, **the broader RFC-1918 ranges (10/8 + 172.16/12) are NOT
/// bypassed** — those address spaces are commonly used by corporate VPNs.
/// Traffic to such IPs goes through heimdall, gets routed via the
/// chosen connection (e.g. `corp`), and the upstream proxy decides how
/// to reach them.
///
#[must_use]
pub fn is_default_bypass(ip_be: u32) -> bool {
    let ip = u32::from_be(ip_be);
    ip == 0                              // 0.0.0.0
    || ip >> 24 == 127                   // 127.0.0.0/8     loopback
    || ip >> 16 == 0xA9FE                // 169.254.0.0/16  link-local
    || ip >> 16 == 0xC0A8 // 192.168.0.0/16  LAN
}

/// IPv6 sibling of [`is_default_bypass`]. Bytes are the on-wire IPv6
/// address (network byte order, 16 bytes). Returns true for ranges
/// that should NEVER hit the relay so the eBPF connect6 hook lets
/// them through unmodified.
///
/// | CIDR              | Why                                              |
/// |-------------------|--------------------------------------------------|
/// | `::/128`          | Unspecified                                      |
/// | `::1/128`         | Loopback                                         |
/// | `fe80::/10`       | Link-local                                       |
/// | `ff00::/8`        | Multicast                                        |
/// | `::ffff:/96`      | IPv4-mapped IPv6 — bypassed iff the inner IPv4   |
/// |                   | address itself is bypassed                       |
///
/// Notably, **`fc00::/7` (ULA) is NOT bypassed**. heimdall's own
/// IPv6 fake-IP pool defaults to `fc00:198:19::/96` which sits inside
/// the ULA range, so blanket-bypassing `fc00::/7` would short-circuit
/// every fake-IP redirect. Mirrors the v4 narrow-bypass philosophy
/// (RFC-1918 10/8 + 172.16/12 are NOT bypassed either).
#[must_use]
pub fn is_default_bypass6(addr: &[u8; 16]) -> bool {
    // ::1 (loopback) — all zero except final byte == 1.
    let all_but_last_zero = addr[..15].iter().all(|&b| b == 0);
    if all_but_last_zero && (addr[15] == 0 || addr[15] == 1) {
        return true;
    }
    // fe80::/10 — link-local. First 10 bits = 1111 1110 10.
    if addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80 {
        return true;
    }
    // ff00::/8 — multicast.
    if addr[0] == 0xff {
        return true;
    }
    // IPv4-mapped IPv6: ::ffff:a.b.c.d. Defer to the v4 bypass check on
    // the embedded address so the same set of "narrow" ranges applies.
    let is_v4_mapped = addr[..10].iter().all(|&b| b == 0) && addr[10] == 0xff && addr[11] == 0xff;
    if is_v4_mapped {
        let v4_be = u32::from_ne_bytes([addr[12], addr[13], addr[14], addr[15]]);
        return is_default_bypass(v4_be);
    }
    false
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
        assert!(is_default_bypass(be(192, 168, 0, 1))); // router
        assert!(is_default_bypass(be(192, 168, 0, 10))); // host
        assert!(is_default_bypass(be(192, 168, 0, 20))); // workstation
        assert!(is_default_bypass(be(192, 168, 255, 255)));
    }

    #[test]
    fn does_not_bypass_rfc1918_10_space() {
        // The whole point of the narrow bypass list: 10/8 and 172.16/12
        // must hit heimdall so a routing rule can send them via a
        // corp-VPN-aware connection.
        assert!(!is_default_bypass(be(10, 0, 0, 1)));
        assert!(!is_default_bypass(be(10, 50, 1, 2)));
        assert!(!is_default_bypass(be(10, 96, 0, 1)));
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
