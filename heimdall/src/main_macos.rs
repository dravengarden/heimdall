// macOS CLI surface with reduced interpose and explicit backends. The
// transparent Network Extension path remains unavailable.

use std::{path::PathBuf, process::ExitCode};

use anyhow::Result;
use clap::{CommandFactory, Parser};

/// Run cooperative clients through an explicit loopback proxy on macOS.
#[derive(Parser, Debug)]
#[command(
    name = "heimdall",
    version,
    about = "Daemonless command egress proxy for compatible macOS clients",
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

    /// Run a command through the backend selected by config or this invocation.
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
    /// Execution backend. Overrides execution.backend for this command.
    #[arg(long, value_enum)]
    backend: Option<crate::cli::backend::BackendArg>,

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
            let config_path = resolve_config_path(cli.config.as_deref())?;
            let config = crate::heimdall_config::HeimdallConfig::load(&config_path)?;
            let backend = crate::cli::backend::selected(config.execution.backend, args.backend);
            let exit_code = match backend {
                crate::heimdall_config::ExecutionBackend::Explicit => {
                    run_explicit(&config, args).await?
                }
                crate::heimdall_config::ExecutionBackend::Interpose => {
                    run_interpose(&config, args).await?
                }
                crate::heimdall_config::ExecutionBackend::Ebpf => {
                    eprintln!("error[macos_ebpf_unavailable]: the eBPF backend is Linux-only");
                    eprintln!(
                        "fix: set execution.backend to `interpose` or `explicit`, then inspect `heimdall agent`"
                    );
                    return Ok(ExitCode::FAILURE);
                }
            };
            Ok(process_exit_code(exit_code))
        }
        Cmd::Help { path, verbose } => {
            print_help(&path, verbose)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn run_explicit(
    config: &crate::heimdall_config::HeimdallConfig,
    args: MacRunArgs,
) -> Result<i32> {
    let policy_name = args
        .policy
        .clone()
        .unwrap_or_else(|| config.proxy.default_policy.clone());
    crate::explicit_proxy::run(config, &policy_name, &args.command).await
}

async fn run_interpose(
    config: &crate::heimdall_config::HeimdallConfig,
    args: MacRunArgs,
) -> Result<i32> {
    let policy_name = args
        .policy
        .clone()
        .unwrap_or_else(|| config.proxy.default_policy.clone());
    let evidence = crate::run_evidence::RunEvidence::start(
        &args.command,
        &policy_name,
        "interpose",
        &config.capture,
    )?;
    let outcome = crate::interpose::run(config, &policy_name, &args.command, &evidence).await;
    match outcome {
        Ok(exit_code) => {
            evidence.finish(exit_code, false)?;
            Ok(exit_code)
        }
        Err(error) => {
            let _ = evidence.fail(
                "interpose_run_failed",
                "the interpose foreground run failed before completion",
            );
            Err(error)
        }
    }
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
    async fn logs_are_inspectable_while_run_rejects_the_linux_backend() {
        let parsed = Cli::try_parse_from(["heimdall", "logs", "schema", "--event", "v1"]).unwrap();
        assert!(matches!(parsed.cmd, Cmd::Logs(_)));
        assert!(
            Cli::try_parse_from([
                "heimdall",
                "run",
                "--backend",
                "macos-transparent",
                "--",
                "true"
            ])
            .is_err()
        );

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
        let config = std::env::temp_dir().join(format!(
            "heimdall-macos-ebpf-{}-{}.toml",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::write(&config, crate::cli::init::InitFormat::Toml.template()).unwrap();
        let code = dispatch(Cli {
            config: Some(config.clone()),
            cmd: Cmd::Run(MacRunArgs {
                backend: None,
                policy: None,
                command,
            }),
        })
        .await
        .unwrap();
        std::fs::remove_file(config).unwrap();

        assert_eq!(code, ExitCode::FAILURE);
        assert!(!marker.exists());
    }
}
