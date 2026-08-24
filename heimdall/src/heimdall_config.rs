//! Strict, format-independent configuration used by the Heimdall CLI.

#[path = "internal/config.rs"]
#[allow(
    dead_code,
    reason = "the embedded strict schema exposes helpers beyond the CLI's current call sites"
)]
mod schema;

pub use schema::*;
