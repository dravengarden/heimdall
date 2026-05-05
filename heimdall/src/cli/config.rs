//! `heimdall config <subcmd>` — inspect and validate the resolved
//! config file.
//!
//! Three verbs:
//! - `validate`: parse + run schema checks; exit 0/1. CI-friendly.
//! - `show`:     print the file content (auto-discovered) so you can
//!               see what the daemon is actually reading.
//! - `path`:     just the resolved path on stdout. Useful for
//!               `cd "$(heimdall config path | xargs dirname)"`.
//!
//! Re-emitting the parsed config with defaults filled in (i.e. an
//! "effective config" view) would require `Serialize` impls across
//! `heimdall-config`. For now we surface the source file as-is —
//! `heimdall init` already documents the defaults in
//! `/etc/heimdall/README.md`.

use std::path::Path;

use anyhow::{Context, Result};
use heimdall_config::HeimdallConfig;
use serde::Serialize;

#[derive(clap::Subcommand, Debug)]
pub enum ConfigCmd {
    /// Parse the config file and run schema validation. Exit 0 on
    /// success, 1 on parse or schema error.
    Validate(ValidateArgs),

    /// Print the resolved config file's content. Add `--json` to wrap
    /// it in a stable envelope (path + format + content).
    Show(ShowArgs),

    /// Print which config file the daemon would load (auto-discovery
    /// against /etc/heimdall/heimdall.{ncl,toml,json,yaml} or the value
    /// of `--config` / `HEIMDALL_CONFIG`).
    Path,
}

#[derive(clap::Args, Debug)]
pub struct ValidateArgs {
    /// JSON output: `{"valid": bool, "path": "...", "error": null|"..."}`.
    /// Stable contract for CI / AI agents.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ShowArgs {
    /// JSON envelope: `{"path": "...", "format": "ncl"|..., "content": "..."}`.
    #[arg(long)]
    json: bool,
}

pub async fn run(config_path: &Path, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Validate(args) => validate(config_path, args).await,
        ConfigCmd::Show(args) => show(config_path, args),
        ConfigCmd::Path => {
            println!("{}", config_path.display());
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct ValidateJson<'a> {
    valid: bool,
    path: String,
    error: Option<&'a str>,
}

async fn validate(config_path: &Path, args: ValidateArgs) -> Result<()> {
    let result = HeimdallConfig::load(config_path);
    let (ok, err_msg) = match &result {
        Ok(_) => (true, None),
        Err(e) => (false, Some(format!("{e:#}"))),
    };

    if args.json {
        let out = ValidateJson {
            valid: ok,
            path: config_path.display().to_string(),
            error: err_msg.as_deref(),
        };
        println!("{}", serde_json::to_string(&out)?);
    } else if ok {
        println!("ok  {}", config_path.display());
    } else {
        eprintln!("INVALID  {}", config_path.display());
        if let Some(msg) = &err_msg {
            eprintln!("\n{msg}");
        }
    }

    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Serialize)]
struct ShowJson<'a> {
    path: String,
    format: &'a str,
    content: String,
}

fn show(config_path: &Path, args: ShowArgs) -> Result<()> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let format = config_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    if args.json {
        let out = ShowJson {
            path: config_path.display().to_string(),
            format,
            content,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        // Plain mode: just stream the file. Matches `cat` so AI agents
        // can pipe it without escaping.
        print!("{content}");
        if !content.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}
