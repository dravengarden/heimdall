//! `heimdall status` — quick health: is the daemon running, store reachable, recent flow count.
//!
//! Two output modes:
//! - default (no `--json`): aligned key/value table for humans skimming a terminal.
//! - `--json`: stable single-line JSON for AI agents and shell scripts.
//!   Same field names as the `heimdall-status` skill expects.

use std::path::Path;

use anyhow::{Context, Result};
use heimdall_config::HeimdallConfig;
use serde::Serialize;

use crate::store::{DbFileStats, ListQuery, Store};
use crate::StatusArgs;

#[derive(Serialize)]
struct StatusJson<'a> {
    config: String,
    connections: usize,
    pod_rules: usize,
    default_use: &'a str,
    default_observe: bool,
    relay_listen: &'a str,
    dns_listen: &'a str,
    fake_ip_cidr: &'a str,
    state_dir: String,
    flow_retention_secs: i64,
    /// Number of rows currently in the flow store; `null` if the store
    /// can't be opened. The CLI shells out to read directly so this field
    /// is correct even when the daemon's HTTP API is down.
    flows_in_store: Option<usize>,
    /// `true` when something is listening on `relay_listen`. `false` when
    /// the port refuses connections (daemon down or unbound).
    relay_reachable: bool,
    // ── Cleanup observability ─────────────────────────────────────
    /// Microsecond timestamp of the last cleanup pass (any tick, even a
    /// no-op one). `null` if cleanup hasn't run yet on this DB.
    last_cleanup_at_us: Option<i64>,
    /// Rows deleted on the last cleanup pass. Persists across daemon
    /// restarts via `heimdall_meta`.
    last_cleanup_deleted: Option<u64>,
    /// On-disk DB size in bytes. `null` if file_stats() failed.
    db_size_bytes: Option<i64>,
    /// Free pages in the DB (auto_vacuum=INCREMENTAL is needed for
    /// these to be reclaimed; otherwise the file just keeps the
    /// trailing freelist forever).
    db_freelist_pages: Option<i64>,
}

pub async fn run(config_path: &Path, args: StatusArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let store_path = cfg.runtime.state_dir.join("flows.db");
    let store_view = read_store_view(&store_path).await;
    let relay_reachable = tokio::net::TcpStream::connect(&cfg.runtime.listen)
        .await
        .is_ok();

    if args.json {
        let out = StatusJson {
            config: config_path.display().to_string(),
            connections: cfg.connections.len(),
            pod_rules: cfg.pod_routing.rules.len(),
            default_use: &cfg.pod_routing.default.use_,
            default_observe: cfg.pod_routing.default.observe,
            relay_listen: &cfg.runtime.listen,
            dns_listen: &cfg.runtime.dns_listen,
            fake_ip_cidr: &cfg.runtime.fake_ip_cidr,
            state_dir: cfg.runtime.state_dir.display().to_string(),
            flow_retention_secs: cfg.runtime.flow_retention_secs,
            flows_in_store: store_view.as_ref().map(|v| v.flow_count),
            relay_reachable,
            last_cleanup_at_us: store_view.as_ref().and_then(|v| v.last_cleanup_at_us),
            last_cleanup_deleted: store_view.as_ref().and_then(|v| v.last_cleanup_deleted),
            db_size_bytes: store_view.as_ref().and_then(|v| v.file_stats.map(|s| s.total_bytes())),
            db_freelist_pages: store_view.as_ref().and_then(|v| v.file_stats.map(|s| s.freelist_count)),
        };
        println!("{}", serde_json::to_string(&out)?);
        return Ok(());
    }

    println!("config         {}", config_path.display());
    println!("connections    {}", cfg.connections.len());
    println!("pod rules      {}", cfg.pod_routing.rules.len());
    println!("default use    {}", cfg.pod_routing.default.use_);
    println!("default observe {}", cfg.pod_routing.default.observe);
    println!("relay listen   {}", cfg.runtime.listen);
    println!("dns listen     {}", cfg.runtime.dns_listen);
    println!("fake-IP CIDR   {}", cfg.runtime.fake_ip_cidr);
    println!("state dir      {}", cfg.runtime.state_dir.display());
    println!("retention      {}s", cfg.runtime.flow_retention_secs);
    match &store_view {
        Some(v) => {
            println!("flows in store {}", v.flow_count);
            if let Some(s) = v.file_stats {
                println!(
                    "db size        {} ({} free)",
                    human_bytes(s.total_bytes()),
                    human_bytes(s.freelist_count * s.page_size),
                );
            }
            match (v.last_cleanup_at_us, v.last_cleanup_deleted) {
                (Some(ts), Some(n)) => {
                    println!(
                        "last cleanup   {} ago, deleted {}",
                        ago(ts),
                        n,
                    );
                }
                _ => println!("last cleanup   (none recorded yet)"),
            }
        }
        None if !store_path.exists() => {
            println!("store          (not found at {})", store_path.display());
        }
        None => println!("store          ERROR (see --json for details)"),
    }
    println!(
        "relay         {}",
        if relay_reachable { "ok (port reachable)" } else { "DOWN (port refused)" }
    );

    Ok(())
}

/// Snapshot of everything `heimdall status` wants from the flow store.
/// Bundled into one struct so we open the DB exactly once.
struct StoreView {
    flow_count: usize,
    file_stats: Option<DbFileStats>,
    last_cleanup_at_us: Option<i64>,
    last_cleanup_deleted: Option<u64>,
}

async fn read_store_view(store_path: &Path) -> Option<StoreView> {
    if !store_path.exists() {
        return None;
    }
    // Read-only handle: works as any user with read access to the file,
    // doesn't try to set pragmas or migrate. Falls back to the regular
    // open() if the read-only path fails (some FUSE filesystems reject
    // SQLITE_OPEN_READONLY explicitly).
    let s = match Store::open_read_only(store_path).await {
        Ok(s) => s,
        Err(_) => Store::open(store_path).await.ok()?,
    };
    let rows = s
        .list(ListQuery { limit: 10_000, ..Default::default() })
        .await
        .ok()?;
    let file_stats = s.file_stats().await.ok();
    let last_cleanup_at_us = s
        .get_meta("last_cleanup_at_us")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok());
    let last_cleanup_deleted = s
        .get_meta("last_cleanup_deleted")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok());
    Some(StoreView {
        flow_count: rows.len(),
        file_stats,
        last_cleanup_at_us,
        last_cleanup_deleted,
    })
}

fn human_bytes(n: i64) -> String {
    let n = n as f64;
    if n < 1024.0 { return format!("{} B", n as i64); }
    if n < 1024.0 * 1024.0 { return format!("{:.1} KB", n / 1024.0); }
    if n < 1024.0 * 1024.0 * 1024.0 { return format!("{:.1} MB", n / (1024.0 * 1024.0)); }
    format!("{:.2} GB", n / (1024.0 * 1024.0 * 1024.0))
}

fn ago(ts_us: i64) -> String {
    let now = crate::store::now_micros();
    let dur_secs = ((now - ts_us) / 1_000_000).max(0);
    if dur_secs < 60 { return format!("{dur_secs}s"); }
    if dur_secs < 3600 { return format!("{}m", dur_secs / 60); }
    if dur_secs < 86400 { return format!("{}h{}m", dur_secs / 3600, (dur_secs % 3600) / 60); }
    format!("{}d{}h", dur_secs / 86400, (dur_secs % 86400) / 3600)
}
