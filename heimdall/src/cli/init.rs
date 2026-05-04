//! `heimdall init` — bootstrap a config directory.
//!
//! Drops a starter `heimdall.<ext>` plus a starter
//! `routing/default.<ext>` into `--dir` (default `/etc/heimdall`).
//! For `--format nickel`, also emits `lib.ncl` containing the schema
//! contracts so user configs get type-checked at evaluation time.
//!
//! Templates are bundled into the binary at compile time; regenerate
//! by re-running this command after upgrading heimdall.

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};

#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// Target directory; created if missing.
    #[arg(long, default_value = "/etc/heimdall")]
    pub dir: PathBuf,

    /// Output format. `nickel` additionally writes `lib.ncl`.
    #[arg(long, value_enum, default_value_t = InitFormat::Yaml)]
    pub format: InitFormat,

    /// Overwrite files that already exist.
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum InitFormat {
    Yaml,
    Json,
    Toml,
    Nickel,
}

impl InitFormat {
    fn extension(&self) -> &'static str {
        match self {
            InitFormat::Yaml => "yaml",
            InitFormat::Json => "json",
            InitFormat::Toml => "toml",
            InitFormat::Nickel => "ncl",
        }
    }
}

// ── Embedded templates ──────────────────────────────────────────
const HEIMDALL_YAML: &str = include_str!("init_templates/heimdall.yaml");
const HEIMDALL_JSON: &str = include_str!("init_templates/heimdall.json");
const HEIMDALL_TOML: &str = include_str!("init_templates/heimdall.toml");
const HEIMDALL_NCL: &str = include_str!("init_templates/heimdall.ncl");

const DEFAULT_YAML: &str = include_str!("init_templates/default.yaml");
const DEFAULT_JSON: &str = include_str!("init_templates/default.json");
const DEFAULT_TOML: &str = include_str!("init_templates/default.toml");
const DEFAULT_NCL: &str = include_str!("init_templates/default.ncl");

const LIB_NCL: &str = include_str!("init_templates/lib.ncl");

pub fn run(args: InitArgs) -> Result<()> {
    let ext = args.format.extension();
    fs::create_dir_all(&args.dir)
        .with_context(|| format!("create dir {}", args.dir.display()))?;
    fs::create_dir_all(args.dir.join("routing"))
        .with_context(|| format!("create dir {}/routing", args.dir.display()))?;

    let main_target = args.dir.join(format!("heimdall.{ext}"));
    let routing_target = args.dir.join(format!("routing/default.{ext}"));
    let lib_target = args.dir.join("lib.ncl");

    let main_content = match args.format {
        InitFormat::Yaml => HEIMDALL_YAML,
        InitFormat::Json => HEIMDALL_JSON,
        InitFormat::Toml => HEIMDALL_TOML,
        InitFormat::Nickel => HEIMDALL_NCL,
    };
    let routing_content = match args.format {
        InitFormat::Yaml => DEFAULT_YAML,
        InitFormat::Json => DEFAULT_JSON,
        InitFormat::Toml => DEFAULT_TOML,
        InitFormat::Nickel => DEFAULT_NCL,
    };

    write_file(&main_target, main_content, args.force)?;
    write_file(&routing_target, routing_content, args.force)?;
    if matches!(args.format, InitFormat::Nickel) {
        write_file(&lib_target, LIB_NCL, args.force)?;
    }

    println!("heimdall init: wrote starter config in `{}`", args.dir.display());
    println!("  - {}", main_target.display());
    println!("  - {}", routing_target.display());
    if matches!(args.format, InitFormat::Nickel) {
        println!("  - {}", lib_target.display());
    }
    println!();
    println!("Next steps:");
    println!("  1. Edit the config to declare your `connections` and `podRouting.rules`.");
    println!(
        "  2. Point your systemd unit at: heimdall serve --config {}",
        main_target.display()
    );
    if matches!(args.format, InitFormat::Nickel) {
        println!("  3. Make sure `nickel` is in PATH (e.g. NixOS: `path = [pkgs.nickel];`).");
    }

    Ok(())
}

fn write_file(path: &std::path::Path, content: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
