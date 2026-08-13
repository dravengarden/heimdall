//! `heimdall status` — config and local daemon health.

use std::path::Path;

use anyhow::{Context, Result};
use heimdall_config::HeimdallConfig;
use serde::Serialize;

use crate::StatusArgs;

#[derive(Serialize)]
struct StatusJson<'a> {
    config: String,
    proxies: usize,
    default_proxy: &'a str,
    relay_listen: &'a str,
    control_listen: &'a str,
    daemon_reachable: bool,
}

pub async fn run(config_path: &Path, args: StatusArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    let daemon_reachable = tokio::net::TcpStream::connect(&cfg.runtime.api_listen)
        .await
        .is_ok();

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&StatusJson {
                config: config_path.display().to_string(),
                proxies: cfg.connections.len(),
                default_proxy: &cfg.run.proxy,
                relay_listen: &cfg.runtime.listen,
                control_listen: &cfg.runtime.api_listen,
                daemon_reachable,
            })?
        );
        return Ok(());
    }

    println!("config         {}", config_path.display());
    println!("proxies        {}", cfg.connections.len());
    println!("default proxy  {}", cfg.run.proxy);
    println!("relay listen   {}", cfg.runtime.listen);
    println!("control listen {}", cfg.runtime.api_listen);
    println!(
        "daemon         {}",
        if daemon_reachable { "ok" } else { "DOWN" }
    );
    Ok(())
}
