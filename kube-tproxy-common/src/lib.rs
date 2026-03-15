//! Shared types between the eBPF kernel program and the userspace daemon.
#![cfg_attr(not(feature = "user"), no_std)]

/// Original connection destination, stored in BPF maps.
/// Fields are in network byte order (big-endian).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OrigDst {
    /// IPv4 destination address (network byte order)
    pub ip: u32,
    /// TCP/UDP destination port (network byte order)
    pub port: u16,
    pub _pad: u16,
}

// Safety: plain-old-data, no pointers
unsafe impl aya::Pod for OrigDst {}

/// CIDR ranges that bypass the proxy (LAN + cluster-internal).
/// Stored as (network_address_host_order, prefix_len).
pub const BYPASS_CIDRS: &[(u32, u8)] = &[
    (0x7F000000, 8),  // 127.0.0.0/8   loopback
    (0x0A000000, 8),  // 10.0.0.0/8    RFC1918 + pod CIDR (10.244.x.x) + service CIDR (10.96.x.x)
    (0xAC100000, 12), // 172.16.0.0/12 RFC1918
    (0xC0A80000, 16), // 192.168.0.0/16 RFC1918 (LAN)
];

pub fn is_bypass(ip_be: u32) -> bool {
    let ip = u32::from_be(ip_be);
    BYPASS_CIDRS.iter().any(|&(net, prefix)| {
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        ip & mask == net & mask
    })
}
