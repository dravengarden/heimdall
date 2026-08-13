//! `heimdall <subcommand>` CLI handlers.
//!
//! The handlers share the same strict configuration loader and the daemon's
//! small loopback registration API.

pub mod agent {
    //! Stable, side-effect-free machine contract for AI agents and automation.

    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::{Path, PathBuf},
    };

    use anyhow::Result;
    use heimdall_config::{ConfigError, ConfigFormat, DnsStrategy, HeimdallConfig};
    use serde::Serialize;

    const CONTRACT_VERSION: &str = "heimdall.agent/v1";

    #[derive(clap::Args, Debug)]
    pub struct AgentArgs {
        /// Preview a named proxy instead of the configured run.proxy.
        #[arg(short = 'p', long)]
        proxy: Option<String>,

        /// Preview a DNS strategy instead of the configured run.dns.
        #[arg(long, value_parser = ["fake", "system"])]
        dns: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct AgentReport {
        contract: &'static str,
        version: &'static str,
        ready: bool,
        config: ConfigReport,
        daemon: DaemonReport,
        decision: Option<DecisionReport>,
        proxies: Vec<String>,
        actions: Actions,
        exit_codes: ExitCodes,
    }

    #[derive(Debug, Serialize)]
    struct ConfigReport {
        path: String,
        format: Option<&'static str>,
        valid: bool,
        error: Option<MachineError>,
    }

    #[derive(Debug, Serialize)]
    struct DaemonReport {
        reachable: Option<bool>,
        control: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct DecisionReport {
        proxy: String,
        dns: String,
        error: Option<MachineError>,
    }

    #[derive(Debug, Serialize)]
    struct MachineError {
        code: &'static str,
        message: String,
    }

    #[derive(Debug, Serialize)]
    struct Actions {
        validate: Vec<String>,
        status: Vec<String>,
        execute_prefix: Option<Vec<String>>,
    }

    #[derive(Debug, Serialize)]
    struct ExitCodes {
        ready: u8,
        not_ready: u8,
        usage: u8,
    }

    /// Print one JSON document and report whether execution is ready.
    ///
    /// This command never starts the daemon, changes config, registers a cgroup,
    /// or executes the wrapped command.
    pub async fn run(explicit_path: Option<&Path>, args: AgentArgs) -> Result<bool> {
        let path_result = explicit_path.map(PathBuf::from).map_or_else(
            || heimdall_config::discover_config_path(heimdall_config::DEFAULT_DIR),
            Ok,
        );

        let (path, discovery_error) = match path_result {
            Ok(path) => (path, None),
            Err(error) => (
                Path::new(heimdall_config::DEFAULT_DIR).join("config.toml"),
                Some(error),
            ),
        };
        let format = ConfigFormat::detect(&path).map(ConfigFormat::name);
        let validate_argv = argv_for(&path, &["config", "validate", "--json"]);
        let status_argv = argv_for(&path, &["status", "--json"]);

        let config_result = discovery_error.map_or_else(
            || HeimdallConfig::load(&path),
            Err::<HeimdallConfig, ConfigError>,
        );

        let report = match config_result {
            Err(error) => AgentReport {
                contract: CONTRACT_VERSION,
                version: env!("CARGO_PKG_VERSION"),
                ready: false,
                config: ConfigReport {
                    path: path.display().to_string(),
                    format,
                    valid: false,
                    error: Some(config_error(error)),
                },
                daemon: DaemonReport {
                    reachable: None,
                    control: None,
                },
                decision: None,
                proxies: Vec::new(),
                actions: Actions {
                    validate: validate_argv,
                    status: status_argv,
                    execute_prefix: None,
                },
                exit_codes: exit_codes(),
            },
            Ok(config) => report_for_valid_config(path, format, config, args).await,
        };

        let ready = report.ready;
        println!("{}", serde_json::to_string(&report)?);
        Ok(ready)
    }

    async fn report_for_valid_config(
        path: PathBuf,
        format: Option<&'static str>,
        config: HeimdallConfig,
        args: AgentArgs,
    ) -> AgentReport {
        let proxy = args.proxy.unwrap_or_else(|| config.run.proxy.clone());
        let dns = args
            .dns
            .unwrap_or_else(|| dns_name(config.run.dns).to_string());
        let decision_error = (!config.connections.contains_key(&proxy)).then(|| MachineError {
            code: "unknown_proxy",
            message: format!("proxy `{proxy}` is not declared"),
        });
        let control = config.runtime.api_listen.clone();
        let reachable = tokio::net::TcpStream::connect(loopback_socket(&control))
            .await
            .is_ok();
        let ready = reachable && decision_error.is_none();
        let execute_prefix = decision_error.is_none().then(|| {
            let mut argv = argv_for(&path, &["run", "--proxy", &proxy, "--dns", &dns]);
            argv.push("--".into());
            argv
        });
        let proxies = config.connections.keys().cloned().collect();

        AgentReport {
            contract: CONTRACT_VERSION,
            version: env!("CARGO_PKG_VERSION"),
            ready,
            config: ConfigReport {
                path: path.display().to_string(),
                format,
                valid: true,
                error: None,
            },
            daemon: DaemonReport {
                reachable: Some(reachable),
                control: Some(control),
            },
            decision: Some(DecisionReport {
                proxy,
                dns,
                error: decision_error,
            }),
            proxies,
            actions: Actions {
                validate: argv_for(&path, &["config", "validate", "--json"]),
                status: argv_for(&path, &["status", "--json"]),
                execute_prefix,
            },
            exit_codes: exit_codes(),
        }
    }

    fn loopback_socket(value: &str) -> SocketAddr {
        let configured: SocketAddr = value
            .parse()
            .expect("strict config validation accepted the listener");
        let ip = match configured.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        SocketAddr::new(ip, configured.port())
    }

    fn argv_for(path: &Path, suffix: &[&str]) -> Vec<String> {
        let mut argv = vec![
            "heimdall".into(),
            "--config".into(),
            path.display().to_string(),
        ];
        argv.extend(suffix.iter().map(|value| (*value).to_string()));
        argv
    }

    const fn dns_name(strategy: DnsStrategy) -> &'static str {
        match strategy {
            DnsStrategy::Fake => "fake",
            DnsStrategy::System => "system",
        }
    }

    fn config_error(error: ConfigError) -> MachineError {
        MachineError {
            code: error.code(),
            message: error.to_string(),
        }
    }

    const fn exit_codes() -> ExitCodes {
        ExitCodes {
            ready: 0,
            not_ready: 1,
            usage: 2,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn argv_is_an_array_and_preserves_paths() {
            assert_eq!(
                argv_for(
                    Path::new("/tmp/config with spaces.toml"),
                    &["status", "--json"]
                ),
                [
                    "heimdall",
                    "--config",
                    "/tmp/config with spaces.toml",
                    "status",
                    "--json"
                ]
            );
        }
    }
}
pub mod config;
pub mod init;
pub mod run;
pub mod status;
