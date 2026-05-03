//! Build helper.
//!
//! The heimdall daemon embeds the React/MUI UI bundle from
//! `../heimdall-ui/dist/`. That directory is produced by
//! `cd heimdall-ui && bun run build` (Vite + React Compiler).
//!
//! This script just nudges cargo to rebuild the daemon when the UI
//! sources change, and prints a friendly warning if the bundle is
//! missing — in that case `rust-embed` ships an empty bundle and the
//! daemon's HTTP API still works, but `/` returns 503.

use std::path::PathBuf;

fn main() {
    let dist = PathBuf::from("../heimdall-ui/dist");

    println!("cargo:rerun-if-changed=../heimdall-ui/dist/index.html");
    println!("cargo:rerun-if-changed=../heimdall-ui/src");

    if !dist.join("index.html").exists() {
        println!(
            "cargo:warning=heimdall-ui/dist/index.html not found — UI will be empty. Run: cd heimdall-ui && bun install && bun run build"
        );
    }
}
