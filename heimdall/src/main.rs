//! Heimdall's target-selected CLI entry point.
//!
//! Linux contains the available cgroup/eBPF implementation. macOS currently
//! exposes only portable configuration inspection and a machine-readable
//! unavailable backend contract; it never executes a command outside policy.

#[cfg(target_os = "linux")]
include!("main_linux.rs");

#[cfg(target_os = "macos")]
include!("main_macos.rs");

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("Heimdall currently builds only for Linux and macOS");
