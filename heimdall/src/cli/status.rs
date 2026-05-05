//! `heimdall status` — quick health: is the daemon running, store reachable, recent flow count.
//!
//! Two output modes:
//! - default (no `--json`): aligned key/value table for humans skimming a terminal.
//! - `--json`: stable single-line JSON for AI agents and shell scripts.
//!   Same field names as the `--default`/`-j` skill expects.

use std::path::Path;

use anyhow::{Context, Result};
use heimdall_config::HeimdallConfig;
use serde::Serialize;

use crate::store::{ListQuery, Store};
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
}

pub async fn run(config_path: &Path, args: StatusArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let store_path = cfg.runtime.state_dir.join("flows.db");
    let flows_in_store = read_store_count(&store_path).await;
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
            flows_in_store,
            relay_reachable,
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
    match flows_in_store {
        Some(n) => println!("flows in store {n}"),
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

/// Best-effort read of the flow row count. `None` means the store either
/// doesn't exist yet or can't be opened (locked, permission error, etc.).
async fn read_store_count(store_path: &Path) -> Option<usize> {
    if !store_path.exists() {
        return None;
    }
    let s = Store::open(store_path).await.ok()?;
    let rows = s
        .list(ListQuery { limit: 10_000, ..Default::default() })
        .await
        .ok()?;
    Some(rows.len())
}
