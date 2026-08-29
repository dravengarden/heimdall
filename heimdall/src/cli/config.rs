//! `heimdall config <subcmd>` — inspect and validate the resolved
//! config file.
//!
//! Six verbs:
//! - `schema`: print the generated current JSON Schema without reading config.
//! - `example`: print the same starter used by `heimdall init` without writing.
//! - `validate`: parse + run schema checks; exit 0/1. CI-friendly.
//! - `explain`: evaluate one TCP or UDP destination against the ordered rules.
//! - `show`: print the file content (auto-discovered) so you can
//!   see the exact source the foreground command will read.
//! - `path`: just the resolved path on stdout. Useful for
//!   `cd "$(heimdall config path | xargs dirname)"`.
//!
//! Re-emitting the parsed config with defaults filled in (i.e. an
//! "effective config" view) would require `Serialize` impls across
//! `heimdall-config`. For now we surface the source file as-is —
//! Every supported syntax is decoded into the same strict schema.

use std::{net::IpAddr, path::Path};

use crate::heimdall_config::{Action, DnsMode, HeimdallConfig};
use anyhow::{Context, Result};
use serde::Serialize;

use super::init::InitFormat;

#[derive(clap::Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the generated current JSON Schema without network access.
    Schema(SchemaArgs),

    /// Print a complete starter configuration without writing a file.
    Example(ExampleArgs),

    /// Parse the config file and run schema validation. Exit 0 on
    /// success, 1 on parse or schema error.
    Validate(ValidateArgs),

    /// Explain which ordered rule handles one TCP or UDP destination.
    Explain(ExplainArgs),

    /// Print the resolved config file's content. Add `--json` to wrap
    /// it in a stable envelope (path + format + content).
    Show(ShowArgs),

    /// Print the canonical config path or the `--config` override.
    Path,
}

impl ConfigCmd {
    pub const fn reads_config(&self) -> bool {
        !matches!(self, Self::Schema(_) | Self::Example(_))
    }
}

#[derive(clap::Args, Debug)]
pub struct SchemaArgs {
    /// Schema version to print (currently v1).
    #[arg(long, default_value = "v1")]
    version: String,
}

#[derive(clap::Args, Debug)]
pub struct ExampleArgs {
    /// Starter syntax; every format enters the same schema.
    #[arg(long, value_enum, default_value_t = InitFormat::Toml)]
    format: InitFormat,
}

#[derive(clap::Args, Debug)]
pub struct ValidateArgs {
    /// Emit stable codes, JSON paths, messages, and repair hints.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ShowArgs {
    /// JSON envelope with path, toml|yaml|json format, and source content.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ExplainArgs {
    /// Policy to inspect; defaults to proxy.default_policy.
    #[arg(short = 'p', long)]
    policy: Option<String>,

    /// Destination domain recovered by fake-IP DNS.
    #[arg(long, conflicts_with = "ip")]
    domain: Option<String>,

    /// Destination IPv4 or IPv6 address.
    #[arg(long, conflicts_with = "domain")]
    ip: Option<IpAddr>,

    /// Transport protocol to evaluate.
    #[arg(long, value_enum, default_value_t = ExplainNetwork::Tcp)]
    network: ExplainNetwork,

    /// Destination TCP or UDP port.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    /// Emit one versioned JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ExplainNetwork {
    Tcp,
    Udp,
}

impl ExplainNetwork {
    const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

pub fn run(config_path: &Path, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Schema(args) => schema(args),
        ConfigCmd::Example(args) => example(args),
        ConfigCmd::Validate(args) => validate(config_path, args),
        ConfigCmd::Explain(args) => explain(config_path, args),
        ConfigCmd::Show(args) => show(config_path, args),
        ConfigCmd::Path => {
            println!("{}", config_path.display());
            Ok(())
        }
    }
}

fn schema(args: SchemaArgs) -> Result<()> {
    if args.version != "v1" {
        anyhow::bail!("unsupported config schema `{}`", args.version);
    }
    println!(
        "{}",
        serde_json::to_string(&crate::heimdall_config::json_schema())?
    );
    Ok(())
}

fn example(args: ExampleArgs) -> Result<()> {
    print!("{}", args.format.template());
    Ok(())
}

#[derive(Serialize)]
struct ExplainJson<'a> {
    contract: &'static str,
    policy: &'a str,
    dns: &'static str,
    target: ExplainTarget<'a>,
    matched_rule: Option<&'a str>,
    action: &'a Action,
}

#[derive(Serialize)]
struct ExplainTarget<'a> {
    network: &'static str,
    domain: Option<&'a str>,
    ip: Option<IpAddr>,
    port: u16,
}

fn explain(config_path: &Path, args: ExplainArgs) -> Result<()> {
    let config = HeimdallConfig::load(config_path).map_err(|error| {
        anyhow::anyhow!(
            "invalid config {}\n\n{}",
            config_path.display(),
            error.actionable_message()
        )
    })?;
    let policy_name = args
        .policy
        .as_deref()
        .unwrap_or(&config.proxy.default_policy);
    let policy = config.policy(policy_name).with_context(|| {
        format!(
            "unknown policy `{policy_name}`\nfix: use --policy with one of: {}",
            config
                .proxy
                .policies
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let (rule, action) = match args.network {
        ExplainNetwork::Tcp => policy.explain_tcp(args.domain.as_deref(), args.ip, args.port),
        ExplainNetwork::Udp => policy.explain_udp(args.domain.as_deref(), args.ip, args.port),
    };
    let matched_rule = rule.map(|value| value.name.as_str());

    if args.json {
        let output = ExplainJson {
            contract: "heimdall.config.explain/v1",
            policy: policy_name,
            dns: match policy.dns.mode {
                DnsMode::Fake => "fake",
                DnsMode::System => "system",
            },
            target: ExplainTarget {
                network: args.network.name(),
                domain: args.domain.as_deref(),
                ip: args.ip,
                port: args.port,
            },
            matched_rule,
            action,
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("policy: {policy_name}");
        println!("network: {}", args.network.name());
        println!("rule: {}", matched_rule.unwrap_or("<final>"));
        println!("action: {}", action_label(action));
    }
    Ok(())
}

fn action_label(action: &Action) -> String {
    match action {
        Action::Route { outbound } => format!("route:{outbound}"),
        Action::Direct => "direct".into(),
        Action::Reject { method } => format!("reject:{method:?}").to_ascii_lowercase(),
    }
}

#[derive(Serialize)]
struct ValidateJson<'a> {
    contract: &'static str,
    valid: bool,
    path: String,
    diagnostics: &'a [crate::heimdall_config::ConfigDiagnostic],
}

fn validate(config_path: &Path, args: ValidateArgs) -> Result<()> {
    let result = HeimdallConfig::load(config_path);
    let (ok, diagnostics) = match &result {
        Ok(_) => (true, Vec::new()),
        Err(error) => (false, error.diagnostics()),
    };

    if args.json {
        let out = ValidateJson {
            contract: "heimdall.config.validate/v2",
            valid: ok,
            path: config_path.display().to_string(),
            diagnostics: &diagnostics,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else if ok {
        println!("ok  {}", config_path.display());
    } else {
        eprintln!("INVALID  {}", config_path.display());
        for diagnostic in &diagnostics {
            eprintln!(
                "\n{}  {}\n  {}\n  fix: {}",
                diagnostic.code, diagnostic.path, diagnostic.message, diagnostic.hint
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_schema_accepts_the_bundled_json_example() {
        let schema = crate::heimdall_config::json_schema();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["title"], "heimdall.config/v1");
        assert_eq!(schema["properties"]["version"]["const"], 1);
        assert_eq!(schema["additionalProperties"], false);

        let validator = jsonschema::validator_for(&schema).unwrap();
        let example: serde_json::Value = serde_json::from_str(InitFormat::Json.template()).unwrap();
        assert!(validator.is_valid(&example));

        let mut unknown = example;
        unknown["unknown"] = true.into();
        assert!(!validator.is_valid(&unknown));
    }
}
