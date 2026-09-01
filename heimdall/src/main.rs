//! Heimdall's target-selected CLI entry point.
//!
//! Linux contains the cgroup/eBPF implementation. Linux and macOS share the
//! reduced interpose and explicit frontends, portable configuration, and
//! event-log inspection; neither platform executes a command outside the
//! selected backend's declared policy boundary.

mod cli;
#[cfg_attr(
    target_os = "macos",
    allow(
        dead_code,
        reason = "the portable writer compiles before a Darwin execution backend owns a run"
    )
)]
mod event_log;
mod explicit_proxy;
mod heimdall_config;
mod interpose;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the authenticated control protocol is wired only after a signed companion passes native attribution acceptance"
    )
)]
mod macos_control;
#[cfg_attr(
    target_os = "macos",
    allow(
        dead_code,
        reason = "the shared outbound transport compiles before a Darwin backend accepts runs"
    )
)]
mod relay_transport;
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
