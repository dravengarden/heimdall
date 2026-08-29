// macOS CLI surface while both native backends remain unavailable.

use std::{path::PathBuf, process::ExitCode};

use anyhow::Result;
use clap::{CommandFactory, Parser};

/// Inspect Heimdall configuration without claiming a working macOS backend.
#[derive(Parser, Debug)]
#[command(
    name = "heimdall",
    version,
    about = "Command-scoped egress proxy (macOS backends are not available yet)",
    arg_required_else_help = true,
    disable_help_subcommand = true,
    after_help = "Tip: `heimdall agent` prints the machine-readable macOS backend status."
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
    /// Emit the stable JSON preflight. It exits 1 while no backend is available.
    Agent(crate::cli::agent_macos::AgentArgs),

    /// Inspect or validate the shared policy configuration.
    #[command(subcommand)]
    Config(crate::cli::config::ConfigCmd),

    /// Write a shared-format starter config without enabling a backend.
    Init(crate::cli::init::InitArgs),

    /// Inspect or maintain portable JSONL evidence without enabling a backend.
    #[command(subcommand)]
    Logs(crate::cli::logs::LogsCmd),

    /// Refuse command execution until a macOS backend passes native acceptance.
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
    /// Named policy to use after a backend becomes available.
    #[arg(short = 'p', long)]
    policy: Option<String>,

    /// Command that would be wrapped. It is never executed by this build.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 1..,
        value_name = "CMD"
    )]
    command: Vec<String>,
}

fn main() -> ExitCode {
    match dispatch(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
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
            let _ = (args.policy, args.command);
            eprintln!(
                "error[macos_backend_unavailable]: macOS backends are in development and not available"
            );
            eprintln!(
                "fix: run `heimdall agent` for exact backend status; use Linux for execution"
            );
            Ok(ExitCode::FAILURE)
        }
        Cmd::Help { path, verbose } => {
            print_help(&path, verbose)?;
            Ok(ExitCode::SUCCESS)
        }
    }
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

    #[test]
    fn logs_are_inspectable_while_run_still_refuses_before_exec() {
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
                policy: None,
                command,
            }),
        })
        .unwrap();

        assert_eq!(code, ExitCode::FAILURE);
        assert!(!marker.exists());
    }
}
