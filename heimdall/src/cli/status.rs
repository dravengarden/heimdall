//! `heimdall status` — config and local daemon health.

use std::path::Path;

use anyhow::Result;
use heimdall_config::HeimdallConfig;
use serde::Serialize;

use crate::StatusArgs;

#[derive(Serialize)]
struct StatusJson<'a> {
    config: String,
    outbounds: usize,
    policies: usize,
    default_policy: &'a str,
    relay_listen: &'static str,
    dns_port: u16,
    control_listen: &'a str,
    daemon_reachable: bool,
}

pub async fn run(config_path: &Path, args: StatusArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path).map_err(|error| {
        anyhow::anyhow!(
            "invalid config {}\n\n{}",
            config_path.display(),
            error.actionable_message()
        )
    })?;
    let daemon_reachable = tokio::net::TcpStream::connect(&cfg.daemon.api_listen)
        .await
        .is_ok();

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&StatusJson {
                config: config_path.display().to_string(),
                outbounds: cfg.proxy.outbounds.len(),
                policies: cfg.proxy.policies.len(),
                default_policy: &cfg.proxy.default_policy,
                relay_listen: "127.0.0.1:12345 + [::1]:12345",
                dns_port: cfg.daemon.dns_port,
                control_listen: &cfg.daemon.api_listen,
                daemon_reachable,
            })?
        );
        return Ok(());
    }

    println!("config         {}", config_path.display());
    println!("outbounds      {}", cfg.proxy.outbounds.len());
    println!("policies       {}", cfg.proxy.policies.len());
    println!("default policy {}", cfg.proxy.default_policy);
    println!("relay listen   127.0.0.1:12345 + [::1]:12345");
    println!(
        "DNS port       {} (IPv4/IPv6 loopback)",
        cfg.daemon.dns_port
    );
    println!("control listen {}", cfg.daemon.api_listen);
    println!(
        "daemon         {}",
        if daemon_reachable { "ok" } else { "DOWN" }
    );
    Ok(())
}
