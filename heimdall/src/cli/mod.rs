//! `heimdall <subcommand>` CLI handlers.
//!
//! These talk to the running daemon by reading the same sqlite store
//! the daemon writes (`<runtime.stateDir>/flows.db`). No IPC needed for
//! read-only queries — just open the database read-only and query.

pub mod flows;
pub mod status;
