// macOS CLI surface with one cooperative explicit backend. The transparent
// Network Extension path remains unavailable.

use std::{
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{ExitCode, ExitStatus},
};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, ValueEnum};
use serde_json::json;
use tokio::process::Command;

/// Run cooperative clients through an explicit loopback proxy on macOS.
#[derive(Parser, Debug)]
#[command(
    name = "heimdall",
    version,
    about = "Command-scoped egress proxy (cooperative macOS explicit mode)",
    arg_required_else_help = true,
    disable_help_subcommand = true,
    after_help = "Tip: `heimdall agent` prints the exact reduced macOS capability set and argv."
)]
struct Cli {
    /// Config path (.toml, .yaml/.yml, or .json).
    #[arg(long, env = "HEIMDALL_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Emit the stable JSON preflight for the selected policy.
    Agent(crate::cli::agent_macos::AgentArgs),

    /// Inspect or validate the shared policy configuration.
    #[command(subcommand)]
    Config(crate::cli::config::ConfigCmd),

    /// Write a shared-format starter config.
    Init(crate::cli::init::InitArgs),

    /// Inspect or maintain portable JSONL evidence.
    #[command(subcommand)]
    Logs(crate::cli::logs::LogsCmd),

    /// Run a cooperative client through an explicitly selected backend.
    Run(MacRunArgs),

    /// Print concise help for the root or one subcommand.
    Help {
        /// Accepted for compatibility; the unavailable surface is already small.
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Subcommand path to inspect.
        #[arg(num_args = 0..)]
        path: Vec<String>,
    },
}

#[derive(clap::Args, Debug)]
struct MacRunArgs {
    /// Backend selection. macOS never selects a reduced fallback silently.
    #[arg(long, value_enum)]
    backend: Option<MacBackend>,

    /// Named policy; defaults to proxy.default_policy.
    #[arg(short = 'p', long)]
    policy: Option<String>,

    /// Command to wrap with the selected cooperative proxy environment.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 1..,
        value_name = "CMD"
    )]
    command: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum MacBackend {
    #[value(name = "macos-explicit")]
    Explicit,
}

#[tokio::main]
async fn main() -> ExitCode {
    match dispatch(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Agent(args) => {
            let ready = crate::cli::agent_macos::run(cli.config.as_deref(), args)?;
            Ok(if ready {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Cmd::Config(command) => {
            let config_path = if command.reads_config() {
                resolve_config_path(cli.config.as_deref())?
            } else {
                cli.config.unwrap_or_else(default_config_path)
            };
            crate::cli::config::run(&config_path, command)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Init(args) => {
            crate::cli::init::run(args)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Logs(command) => {
            crate::cli::logs::run(command)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run(args) => {
            if args.backend != Some(MacBackend::Explicit) {
                eprintln!(
                    "error[macos_backend_required]: macOS never selects a reduced proxy backend implicitly"
                );
                eprintln!(
                    "fix: inspect `heimdall agent`, then pass `--backend macos-explicit` only for a cooperative SOCKS-aware client"
                );
                return Ok(ExitCode::FAILURE);
            }
            let config_path = resolve_config_path(cli.config.as_deref())?;
            let exit_code = run_explicit(&config_path, args).await?;
            Ok(process_exit_code(exit_code))
        }
        Cmd::Help { path, verbose } => {
            print_help(&path, verbose)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn run_explicit(config_path: &Path, args: MacRunArgs) -> Result<i32> {
    let config = crate::heimdall_config::HeimdallConfig::load(config_path)?;
    let policy_name = args
        .policy
        .clone()
        .unwrap_or_else(|| config.proxy.default_policy.clone());
    let diagnostics = crate::explicit_proxy::diagnostics(&config, &policy_name);
    if let Some(diagnostic) = diagnostics.first() {
        anyhow::bail!(
            "{} at {}: {}; fix: {}",
            diagnostic.code,
            diagnostic.path,
            diagnostic.message,
            diagnostic.hint
        );
    }
    if let Some(diagnostic) = crate::explicit_proxy::outbound_diagnostic(&config) {
        anyhow::bail!(
            "{} at {}: {}; fix: {}",
            diagnostic.code,
            diagnostic.path,
            diagnostic.message,
            diagnostic.hint
        );
    }

    let evidence = crate::run_evidence::RunEvidence::start(
        &args.command,
        &policy_name,
        "macos-explicit",
        &config.capture,
    )?;
    let outcome = run_explicit_registered(&config, &policy_name, &args.command, &evidence).await;
    match outcome {
        Ok(exit_code) => {
            // macos-explicit owns the listener but cannot prove or clean a
            // complete descendant tree after the immediate child exits.
            evidence.finish(exit_code, false)?;
            Ok(exit_code)
        }
        Err(error) => {
            let _ = evidence.fail(
                "macos_explicit_run_failed",
                "the macos-explicit foreground run failed before completion",
            );
            Err(error)
        }
    }
}

async fn run_explicit_registered(
    config: &crate::heimdall_config::HeimdallConfig,
    policy_name: &str,
    command: &[String],
    evidence: &crate::run_evidence::RunEvidence,
) -> Result<i32> {
    let events =
        crate::event_log::EventClient::connect(evidence.event_socket_path().to_path_buf())?;
    let proxy = crate::explicit_proxy::ExplicitProxy::start(config, policy_name, events).await?;
    let proxy_url = proxy.proxy_url();
    evidence.log().emit(
        "run.warning",
        None,
        json!({
            "code": "macos_explicit_cooperative_scope",
            "message": "the wrapped client can ignore or replace the injected explicit proxy environment",
            "phase": "preflight",
            "context": {
                "backend": "macos-explicit",
                "scope": "cooperative_environment",
                "environment": ["ALL_PROXY", "all_proxy"],
                "proxy": proxy_url
            }
        }),
    )?;
    if let Err(error) = evidence.ready("heimdall-run", None, &["transport"]) {
        proxy.shutdown().await?;
        return Err(error);
    }

    eprintln!(
        "heimdall run: backend=macos-explicit scope=cooperative_environment ALL_PROXY={proxy_url} all_proxy={proxy_url}"
    );
    let mut child_command = Command::new(&command[0]);
    child_command.args(&command[1..]).kill_on_drop(true);
    for variable in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
        "ftp_proxy",
        "FTP_PROXY",
    ] {
        child_command.env_remove(variable);
    }
    child_command
        .env("ALL_PROXY", &proxy_url)
        .env("all_proxy", &proxy_url);
    let mut child = match child_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            proxy.shutdown().await?;
            return Err(error).with_context(|| format!("execute {}", command[0]));
        }
    };
    let child_pid = child.id().context("wrapped command has no process ID")?;
    evidence.log().emit(
        "run.exec",
        Some(child_pid),
        json!({
            "child_pid": child_pid,
            "executable": command[0],
            "argv_count": command.len()
        }),
    )?;

    let status = child.wait().await;
    let shutdown = proxy.shutdown().await;
    let status = status.context("wait for macos-explicit command")?;
    shutdown?;
    Ok(status_exit_code(status))
}

fn status_exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

fn process_exit_code(code: i32) -> ExitCode {
    u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
}

fn resolve_config_path(explicit: Option<&std::path::Path>) -> Result<PathBuf> {
    explicit.map(PathBuf::from).map_or_else(
        || {
            crate::heimdall_config::discover_config_path(crate::heimdall_config::DEFAULT_DIR)
                .map_err(Into::into)
        },
        Ok,
    )
}

fn default_config_path() -> PathBuf {
    PathBuf::from(crate::heimdall_config::DEFAULT_DIR).join("config.toml")
}

fn print_help(path: &[String], _verbose: bool) -> Result<()> {
    let mut command = Cli::command();
    command.build();
    let mut selected = &mut command;
    for (index, name) in path.iter().enumerate() {
        selected = selected.find_subcommand_mut(name).ok_or_else(|| {
            let parent = if index == 0 {
                "heimdall".into()
            } else {
                format!("heimdall {}", path[..index].join(" "))
            };
            anyhow::anyhow!("`{name}` is not a subcommand of `{parent}`")
        })?;
    }
    selected.print_long_help()?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn logs_are_inspectable_while_run_requires_an_explicit_backend() {
        let parsed = Cli::try_parse_from(["heimdall", "logs", "schema", "--event", "v1"]).unwrap();
        assert!(matches!(parsed.cmd, Cmd::Logs(_)));

        let marker = std::env::temp_dir().join(format!(
            "heimdall-macos-refusal-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        let command = vec![
            "sh".into(),
            "-c".into(),
            format!("touch {}", marker.display()),
        ];
        let code = dispatch(Cli {
            config: None,
            cmd: Cmd::Run(MacRunArgs {
                backend: None,
                policy: None,
                command,
            }),
        })
        .await
        .unwrap();

        assert_eq!(code, ExitCode::FAILURE);
        assert!(!marker.exists());
    }
}
