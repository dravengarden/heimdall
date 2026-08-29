//! Heimdall's target-selected CLI entry point.
//!
//! Linux contains the available cgroup/eBPF implementation. macOS currently
//! exposes portable configuration and event-log inspection plus a
//! machine-readable unavailable backend contract; it never executes a command
//! outside policy.

mod cli;
#[cfg_attr(
    target_os = "macos",
    allow(
        dead_code,
        reason = "the portable writer compiles before a Darwin execution backend owns a run"
    )
)]
mod event_log;
mod heimdall_config;
#[cfg_attr(
    target_os = "macos",
    allow(
        dead_code,
        reason = "the shared evidence owner is compiled before a Darwin execution backend uses it"
    )
)]
mod run_evidence;

#[cfg(target_os = "linux")]
include!("main_linux.rs");

#[cfg(target_os = "macos")]
include!("main_macos.rs");

#[cfg(all(test, target_os = "linux"))]
#[path = "main_macos.rs"]
#[allow(
    dead_code,
    reason = "Linux unit tests compile the Darwin CLI contract without selecting it as the binary root"
)]
mod main_macos_contract;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("Heimdall currently builds only for Linux and macOS");
