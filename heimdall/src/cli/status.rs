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
    daemon_ready: Option<bool>,
    daemon_decrypt_mode: Option<&'a str>,
    daemon_config_matches: Option<bool>,
}

pub async fn run(config_path: &Path, args: StatusArgs) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path).map_err(|error| {
        anyhow::anyhow!(
            "invalid config {}\n\n{}",
            config_path.display(),
            error.actionable_message()
        )
    })?;
    let daemon_health = crate::cli::agent::fetch_daemon_health(&cfg.daemon.api_listen).await;
    let daemon_reachable = daemon_health.is_some();
    let configured_decrypt_mode = match cfg.decrypt.mode {
        heimdall_config::DecryptMode::Off => "off",
        heimdall_config::DecryptMode::Runtime => "runtime",
        heimdall_config::DecryptMode::Relay => "relay",
    };
    let daemon_ready = daemon_health.as_ref().map(|health| health.ready);
    let daemon_decrypt_mode = daemon_health
        .as_ref()
        .map(|health| health.decrypt_mode.as_str());
    let daemon_config_matches = daemon_decrypt_mode.map(|mode| mode == configured_decrypt_mode);

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
                daemon_ready,
                daemon_decrypt_mode,
                daemon_config_matches,
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
    let daemon_status = match (daemon_ready, daemon_config_matches) {
        (Some(true), Some(true)) => "ok",
        (Some(true), Some(false)) => "CONFIG MISMATCH",
        (Some(true), None) => "NOT READY",
        (Some(false), _) => "NOT READY",
        (None, _) => "DOWN",
    };
    println!("daemon         {daemon_status}");
    if let Some(mode) = daemon_decrypt_mode {
        println!("daemon decrypt {mode}");
    }
    Ok(())
}
