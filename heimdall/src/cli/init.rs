//! `heimdall init` — bootstrap a config directory.
//!
//! Writes a minimal `/etc/heimdall/config.<format>` starter.
//!
//! Templates are bundled into the binary at compile time; regenerate
//! by re-running this command after upgrading heimdall.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};

#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// Target directory; created if missing.
    #[arg(long, default_value = "/etc/heimdall")]
    pub dir: PathBuf,

    /// Output syntax. Every format uses the same strict schema.
    #[arg(long, value_enum, default_value_t = InitFormat::Toml)]
    pub format: InitFormat,

    /// Overwrite the config if it already exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum InitFormat {
    Toml,
    Yaml,
    Json,
    Nickel,
}

impl InitFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Nickel => "ncl",
        }
    }

    fn template(self) -> &'static str {
        match self {
            Self::Toml => HEIMDALL_TOML,
            Self::Yaml => HEIMDALL_YAML,
            Self::Json => HEIMDALL_JSON,
            Self::Nickel => HEIMDALL_NICKEL,
        }
    }
}

// ── Embedded templates ──────────────────────────────────────────
const HEIMDALL_TOML: &str = r#"# heimdall is a proxy wrapper. System traffic is never redirected.

[proxies.default]
type = "socks5"
addr = "127.0.0.1:1080"

[run]
proxy = "default"
dns = "fake"

# Most installations do not need to change daemon settings.
# [daemon]
# listen = "127.0.0.1:12345"
# apiListen = "127.0.0.1:9999"
# dnsListen = "127.0.0.1:5358"
"#;

const HEIMDALL_YAML: &str = r#"# heimdall is a proxy wrapper. System traffic is never redirected.
proxies:
  default:
    type: socks5
    addr: 127.0.0.1:1080
run:
  proxy: default
  dns: fake
"#;

const HEIMDALL_JSON: &str = r#"{
  "proxies": {
    "default": {
      "type": "socks5",
      "addr": "127.0.0.1:1080"
    }
  },
  "run": {
    "proxy": "default",
    "dns": "fake"
  }
}
"#;

const HEIMDALL_NICKEL: &str = r#"# heimdall is a proxy wrapper. System traffic is never redirected.
{
  proxies.default = {
    type = "socks5",
    addr = "127.0.0.1:1080",
  },
  run = {
    proxy = "default",
    dns = "fake",
  },
}
"#;

pub fn run(args: InitArgs) -> Result<()> {
    fs::create_dir_all(&args.dir).with_context(|| format!("create dir {}", args.dir.display()))?;

    let main_target = args.dir.join(format!("config.{}", args.format.extension()));

    // User-owned: only write if missing or --force was passed.
    let main_existed = main_target.exists();
    let main_written = if main_existed && !args.force {
        false
    } else {
        fs::write(&main_target, args.format.template())
            .with_context(|| format!("write {}", main_target.display()))?;
        true
    };

    println!("heimdall init: wrote files in `{}`", args.dir.display());
    if main_written {
        println!("  - {} (main config)", main_target.display());
    } else {
        println!(
            "  - {} (preserved — pre-existing; pass --force to overwrite with starter)",
            main_target.display()
        );
    }
    println!();
    println!("Next steps:");
    println!(
        "  1. Edit `{}` and set your SOCKS5 proxy address.",
        main_target
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    println!(
        "  2. Start `heimdall daemon`, then use `heimdall run -- <command>`.\n     Pass --config <PATH> only if the file lives elsewhere than {}.",
        main_target.display()
    );

    Ok(())
}
