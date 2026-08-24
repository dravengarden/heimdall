//! Userspace view of the wire types shared with Heimdall's eBPF program.

#[path = "internal/common.rs"]
#[allow(
    dead_code,
    reason = "the shared eBPF ABI includes fields used only by the kernel program"
)]
mod wire;

pub use wire::*;

#[allow(
    unsafe_code,
    reason = "repr(C) contains only fixed-width Pod fields shared verbatim with eBPF"
)]
unsafe impl aya::Pod for OrigDst {}

#[allow(
    unsafe_code,
    reason = "repr(C) contains only fixed-width Pod fields shared verbatim with eBPF"
)]
unsafe impl aya::Pod for UdpFlowKey {}

#[allow(
    unsafe_code,
    reason = "repr(C) contains only fixed-width Pod fields shared verbatim with eBPF"
)]
unsafe impl aya::Pod for TapEvent {}
