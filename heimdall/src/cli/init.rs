//! `heimdall init` — bootstrap a config directory.
//!
//! Drops a starter `heimdall.<ext>` plus a detailed `README.md`
//! (auto-generated schema reference for AI agents) into `--dir`
//! (default `/etc/heimdall`). For `--format nickel`, also emits
//! `lib.ncl` containing the schema contracts so user configs get
//! type-checked at evaluation time.
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

    /// Output format. `nickel` additionally writes `lib.ncl`.
    #[arg(long, value_enum, default_value_t = InitFormat::Yaml)]
    pub format: InitFormat,

    /// Overwrite the user-owned main config (`heimdall.<ext>`) if it
    /// already exists. The auto-generated reference files
    /// (`lib.ncl`, `README.md`) are always refreshed regardless of
    /// this flag — they mirror the daemon binary and never carry
    /// user edits worth preserving.
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
const LIB_NCL: &str = include_str!("init_templates/lib.ncl");
const README_MD: &str = include_str!("init_templates/README.md");

pub fn run(args: InitArgs) -> Result<()> {
    let ext = args.format.extension();
    fs::create_dir_all(&args.dir)
        .with_context(|| format!("create dir {}", args.dir.display()))?;

    let main_target = args.dir.join(format!("heimdall.{ext}"));
    let lib_target = args.dir.join("lib.ncl");
    let readme_target = args.dir.join("README.md");

    let main_content = match args.format {
        InitFormat::Yaml => HEIMDALL_YAML,
        InitFormat::Json => HEIMDALL_JSON,
        InitFormat::Toml => HEIMDALL_TOML,
        InitFormat::Nickel => HEIMDALL_NCL,
    };

    // Auto-generated reference: always refreshed (mirrors the daemon
    // binary; never carries user edits worth preserving).
    fs::write(&readme_target, README_MD)
        .with_context(|| format!("write {}", readme_target.display()))?;
    if matches!(args.format, InitFormat::Nickel) {
        fs::write(&lib_target, LIB_NCL)
            .with_context(|| format!("write {}", lib_target.display()))?;
    }

    // User-owned: only write if missing or --force was passed.
    let main_existed = main_target.exists();
    let main_written = if main_existed && !args.force {
        false
    } else {
        fs::write(&main_target, main_content)
            .with_context(|| format!("write {}", main_target.display()))?;
        true
    };

    println!("heimdall init: wrote files in `{}`", args.dir.display());
    println!("  - {} (auto-generated reference)", readme_target.display());
    if matches!(args.format, InitFormat::Nickel) {
        println!("  - {} (auto-generated schema)", lib_target.display());
    }
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
    println!("  1. Read README.md — it's the AI-readable schema reference.");
    println!("  2. Edit the config to declare your `connections` and `podRouting.rules`.");
    println!(
        "  3. Run `heimdall serve` (the daemon auto-discovers {}; pass\n     --config <PATH> only if the file lives elsewhere).",
        main_target.display()
    );
    if matches!(args.format, InitFormat::Nickel) {
        println!("  4. Make sure `nickel` is in PATH (e.g. NixOS: `path = [pkgs.nickel];`).");
    }

    Ok(())
}

