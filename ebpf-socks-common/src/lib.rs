//! Types shared between the eBPF kernel programs and the userspace daemon.
#![cfg_attr(not(feature = "user"), no_std)]

/// Original connection destination saved by the eBPF connect4 hook.
/// All fields are in network byte order (big-endian).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OrigDst {
    /// IPv4 destination address (network byte order)
    pub ip: u32,
    /// TCP destination port (network byte order)
    pub port: u16,
    pub _pad: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OrigDst {}

/// Returns true if the given IPv4 address (network byte order) should bypass
/// the proxy.
///
/// Default bypass list covers:
///   127.0.0.0/8   loopback
///   10.0.0.0/8    RFC-1918 class A (includes pod CIDR 10.244.x.x and
///                 service CIDR 10.96.x.x for a typical k8s cluster)
///   172.16.0.0/12 RFC-1918 class B
///   192.168.0.0/16 RFC-1918 class C (LAN)
///   169.254.0.0/16 link-local
///
/// Callers can add extra CIDRs via `--bypass` CLI flags (userspace only).
pub fn is_default_bypass(ip_be: u32) -> bool {
    let ip = u32::from_be(ip_be);
    ip == 0                      // 0.0.0.0
    || ip >> 24 == 127           // 127.0.0.0/8
    || ip >> 24 == 10            // 10.0.0.0/8
    || ip >> 20 == 0xAC1         // 172.16.0.0/12
    || ip >> 16 == 0xC0A8        // 192.168.0.0/16
    || ip >> 16 == 0xA9FE        // 169.254.0.0/16
}
