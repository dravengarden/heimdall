//! `heimdall <subcommand>` CLI handlers.
//!
//! The handlers share the same strict configuration loader and the daemon's
//! small loopback registration API.

pub mod ebpf;

pub mod agent {
    //! Stable, side-effect-free machine contract for AI agents and automation.

    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::{Path, PathBuf},
    };

    use anyhow::Result;
    use heimdall_config::{
        Action, ConfigDiagnostic, ConfigError, ConfigFormat, DnsMode, HeimdallConfig,
    };
    use serde::Serialize;

    const CONTRACT_VERSION: &str = "heimdall.agent/v2";

    #[derive(clap::Args, Debug)]
    pub struct AgentArgs {
        /// Preview a named policy instead of proxy.default_policy.
        #[arg(short = 'p', long)]
        policy: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct AgentReport {
        contract: &'static str,
        version: &'static str,
        ready: bool,
        config: ConfigReport,
        daemon: DaemonReport,
        capabilities: Capabilities,
        decision: Option<DecisionReport>,
        policies: Vec<String>,
        outbounds: Vec<String>,
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
    struct Capabilities {
        udp: UdpCapabilities,
        runtime_acceptance: RuntimeAcceptance,
        cli_acceptance: CliAcceptance,
        lifecycle: LifecycleCapabilities,
    }

    #[derive(Debug, Serialize)]
    struct RuntimeAcceptance {
        tcp_fake_dns: &'static [&'static str],
        udp_ipv4: &'static [&'static str],
        udp_ipv6: &'static [&'static str],
    }

    #[derive(Debug, Serialize)]
    struct CliAcceptance {
        tcp_fake_dns: &'static [&'static str],
    }

    #[derive(Debug, Serialize)]
    struct LifecycleCapabilities {
        descendant_cgroup_lifetime: bool,
        exit_code_passthrough: bool,
        signal_exit_code: &'static str,
        upstream_unreachable_fail_closed: bool,
        daemon_unreachable_prevents_exec: bool,
        daemon_restart_continuity: bool,
        daemon_restart_enforcement_continuity: bool,
        daemon_restart_policy_recovery: bool,
        daemon_restart_fake_dns_recovery: bool,
        daemon_restart_existing_connections: bool,
        pinned_state_schema: u32,
        transactional_program_upgrade: bool,
        cleanup_requires_no_active_workloads: bool,
    }

    #[derive(Debug, Serialize)]
    struct UdpCapabilities {
        connected: bool,
        connectionless: bool,
        connectionless_ipv4: bool,
        connectionless_ipv6: bool,
        connectionless_ipv6_single_peer: bool,
        ipv4_mapped_ipv6_socket: bool,
        concurrent_shared_source_port: bool,
        concurrent_shared_source_port_ipv4: bool,
        concurrent_shared_source_port_ipv6: bool,
        association_reuse: bool,
        multi_response: bool,
        max_socks5_payload_bytes: usize,
        quic: &'static str,
        quic_ipv4: bool,
        quic_ipv6: bool,
        quic_address_family_migration: bool,
        exchange: &'static str,
    }

    #[derive(Debug, Serialize)]
    struct DecisionReport {
        policy: String,
        dns: String,
        tcp_final: String,
        udp_final: String,
        error: Option<MachineError>,
    }

    #[derive(Debug, Serialize)]
    struct MachineError {
        code: &'static str,
        message: String,
        diagnostics: Vec<ConfigDiagnostic>,
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
                capabilities: capabilities(),
                decision: None,
                policies: Vec::new(),
                outbounds: Vec::new(),
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
        let policy = args
            .policy
            .unwrap_or_else(|| config.proxy.default_policy.clone());
        let selected = config.policy(&policy);
        let known_policies = config
            .proxy
            .policies
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let decision_error = selected.is_none().then(|| MachineError {
            code: "unknown_policy",
            message: format!("policy `{policy}` is not declared"),
            diagnostics: vec![ConfigDiagnostic {
                code: "unknown_policy".into(),
                path: "$.cli.policy".into(),
                message: format!("policy `{policy}` is not declared"),
                hint: format!("Use --policy with one of: {known_policies}."),
            }],
        });
        let control = config.daemon.api_listen.clone();
        let reachable = tokio::net::TcpStream::connect(loopback_socket(&control))
            .await
            .is_ok();
        let ready = reachable && decision_error.is_none();
        let execute_prefix = decision_error.is_none().then(|| {
            let mut argv = argv_for(&path, &["run", "--policy", &policy]);
            argv.push("--".into());
            argv
        });
        let policies = config.proxy.policies.keys().cloned().collect();
        let outbounds = config.proxy.outbounds.keys().cloned().collect();
        let (dns, tcp_final, udp_final) = selected.map_or_else(
            || ("unknown".into(), "unknown".into(), "unknown".into()),
            |selected| {
                (
                    dns_name(selected.dns.mode).into(),
                    action_name(&selected.final_.tcp),
                    action_name(&selected.final_.udp),
                )
            },
        );

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
            capabilities: capabilities(),
            decision: Some(DecisionReport {
                policy,
                dns,
                tcp_final,
                udp_final,
                error: decision_error,
            }),
            policies,
            outbounds,
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

    const fn dns_name(strategy: DnsMode) -> &'static str {
        match strategy {
            DnsMode::Fake => "fake",
            DnsMode::System => "system",
        }
    }

    fn action_name(action: &Action) -> String {
        match action {
            Action::Route { outbound } => format!("route:{outbound}"),
            Action::Direct => "direct".into(),
            Action::Reject { method } => format!("reject:{method:?}").to_ascii_lowercase(),
        }
    }

    fn config_error(error: ConfigError) -> MachineError {
        let diagnostics = error.diagnostics();
        MachineError {
            code: error.code(),
            message: error.to_string(),
            diagnostics,
        }
    }

    const fn exit_codes() -> ExitCodes {
        ExitCodes {
            ready: 0,
            not_ready: 1,
            usage: 2,
        }
    }

    const fn capabilities() -> Capabilities {
        Capabilities {
            udp: UdpCapabilities {
                connected: true,
                connectionless: false,
                connectionless_ipv4: true,
                connectionless_ipv6: false,
                connectionless_ipv6_single_peer: true,
                ipv4_mapped_ipv6_socket: true,
                concurrent_shared_source_port: false,
                concurrent_shared_source_port_ipv4: true,
                concurrent_shared_source_port_ipv6: false,
                association_reuse: true,
                multi_response: true,
                max_socks5_payload_bytes: 65_245,
                quic: "ipv4+ipv6-single-path",
                quic_ipv4: true,
                quic_ipv6: true,
                quic_address_family_migration: false,
                exchange: "bidirectional-session",
            },
            runtime_acceptance: RuntimeAcceptance {
                tcp_fake_dns: &["curl", "go-netgo", "java", "nodejs", "rust"],
                udp_ipv4: &["c", "go-netgo", "java", "nodejs", "python", "rust"],
                udp_ipv6: &["go-netgo", "java", "nodejs", "python", "rust"],
            },
            cli_acceptance: CliAcceptance {
                tcp_fake_dns: &["git"],
            },
            lifecycle: LifecycleCapabilities {
                descendant_cgroup_lifetime: true,
                exit_code_passthrough: true,
                signal_exit_code: "128+signal",
                upstream_unreachable_fail_closed: true,
                daemon_unreachable_prevents_exec: true,
                daemon_restart_continuity: false,
                daemon_restart_enforcement_continuity: true,
                daemon_restart_policy_recovery: true,
                daemon_restart_fake_dns_recovery: true,
                daemon_restart_existing_connections: false,
                pinned_state_schema: crate::ebpf::STATE_SCHEMA,
                transactional_program_upgrade: true,
                cleanup_requires_no_active_workloads: true,
            },
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

        #[test]
        fn udp_capabilities_distinguish_family_specific_support() {
            let udp = capabilities().udp;
            assert!(udp.connected);
            assert!(!udp.connectionless);
            assert!(udp.connectionless_ipv4);
            assert!(!udp.connectionless_ipv6);
            assert!(udp.connectionless_ipv6_single_peer);
            assert!(udp.ipv4_mapped_ipv6_socket);
            assert!(!udp.concurrent_shared_source_port);
            assert!(udp.concurrent_shared_source_port_ipv4);
            assert!(!udp.concurrent_shared_source_port_ipv6);
            assert!(udp.quic_ipv4);
            assert!(udp.quic_ipv6);
            assert!(!udp.quic_address_family_migration);
        }

        #[test]
        fn runtime_acceptance_is_machine_readable() {
            let capabilities = capabilities();
            let runtimes = capabilities.runtime_acceptance;
            assert!(runtimes.tcp_fake_dns.contains(&"go-netgo"));
            assert!(runtimes.udp_ipv4.contains(&"nodejs"));
            assert!(runtimes.udp_ipv6.contains(&"java"));
            assert!(capabilities.cli_acceptance.tcp_fake_dns.contains(&"git"));
        }

        #[test]
        fn lifecycle_capabilities_expose_restart_boundary() {
            let lifecycle = capabilities().lifecycle;
            assert!(lifecycle.descendant_cgroup_lifetime);
            assert!(lifecycle.upstream_unreachable_fail_closed);
            assert!(lifecycle.daemon_unreachable_prevents_exec);
            assert!(!lifecycle.daemon_restart_continuity);
            assert!(lifecycle.daemon_restart_enforcement_continuity);
            assert!(lifecycle.daemon_restart_policy_recovery);
            assert!(lifecycle.daemon_restart_fake_dns_recovery);
            assert!(!lifecycle.daemon_restart_existing_connections);
        }
    }
}
pub mod config;
pub mod init;
pub mod run;
pub mod status;
