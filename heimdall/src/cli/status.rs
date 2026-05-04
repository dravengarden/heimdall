//! `heimdall status` — quick health: is the daemon running, store reachable, recent flow count.

use std::path::Path;

use anyhow::{Context, Result};
use heimdall_config::HeimdallConfig;

use crate::store::{ListQuery, Store};

pub async fn run(config_path: &Path) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

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

    // Daemon health: check if relay listener is bound + flow store exists.
    let store_path = cfg.runtime.state_dir.join("flows.db");
    if store_path.exists() {
        match Store::open(&store_path).await {
            Ok(s) => match s.list(ListQuery { limit: 10_000, ..Default::default() }).await {
                Ok(rows) => println!("flows in store {}", rows.len()),
                Err(e) => println!("flows in store ERROR: {e:#}"),
            },
            Err(e) => println!("store          ERROR: {e:#}"),
        }
    } else {
        println!("store          (not found at {})", store_path.display());
    }

    let relay_alive = tokio::net::TcpStream::connect(&cfg.runtime.listen)
        .await
        .is_ok();
    println!(
        "relay         {}",
        if relay_alive { "ok (port reachable)" } else { "DOWN (port refused)" }
    );

    Ok(())
}
