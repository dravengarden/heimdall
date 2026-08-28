//! `heimdall <subcommand>` CLI handlers.
//!
//! The handlers share the same strict configuration loader. `heimdall run`
//! owns its complete data plane and persistent services are out of scope.

pub mod logs;
pub mod tls;

pub mod agent {
    //! Stable, side-effect-free machine contract for AI agents and automation.

    use std::path::{Path, PathBuf};

    use crate::heimdall_config::{
        Action, CaptureMode, ConfigDiagnostic, ConfigError, ConfigFormat, DecryptConfig, DnsMode,
        HeimdallConfig,
    };
    use anyhow::Result;
    use serde::Serialize;

    const CONTRACT_VERSION: &str = "heimdall.agent/v8";

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
        execution: Option<ExecutionReport>,
        capabilities: Capabilities,
        decision: Option<DecisionReport>,
        policies: Vec<String>,
        outbounds: Vec<String>,
        actions: Actions,
        exit_codes: ExitCodes,
    }

    #[derive(Debug, Serialize)]
    struct ExecutionReport {
        backend: &'static str,
        owner: &'static str,
        privilege_setup: &'static str,
        daemon_required: bool,
        web_ui_required: bool,
    }

    #[derive(Debug, Serialize)]
    struct ConfigReport {
        path: String,
        format: Option<&'static str>,
        valid: bool,
        capture: Option<CaptureConfigReport>,
        decrypt: Option<DecryptConfigReport>,
        error: Option<MachineError>,
    }

    #[derive(Debug, Serialize)]
    struct CaptureConfigReport {
        mode: &'static str,
        max_bytes_per_flow: u64,
        block_max_bytes: u64,
        flush_interval_ms: u64,
        boundaries: Vec<&'static str>,
        directions: Vec<&'static str>,
        redact_env: Vec<String>,
        redaction_values_ready: bool,
        redaction_error: Option<MachineError>,
    }

    #[derive(Debug, Serialize)]
    struct DecryptConfigReport {
        mode: &'static str,
        ca_cert: Option<String>,
        ca_cert_sha256: Option<String>,
        ca_key: Option<String>,
        ca_material_ready: bool,
    }

    #[derive(Debug, Serialize)]
    struct Capabilities {
        capture: CaptureCapabilities,
        logs: LogsCapabilities,
        decrypt: DecryptCapabilities,
        udp: UdpCapabilities,
        runtime_acceptance: RuntimeAcceptance,
        cli_acceptance: CliAcceptance,
        lifecycle: LifecycleCapabilities,
    }

    #[derive(Debug, Serialize)]
    struct CaptureCapabilities {
        contract: &'static str,
        format: &'static str,
        tcp: bool,
        udp: bool,
        payload: &'static str,
        tls_plaintext: bool,
        boundary_allowlist: bool,
        direction_allowlist: bool,
        environment_redaction: bool,
    }

    #[derive(Debug, Serialize)]
    struct LogsCapabilities {
        event_contract: &'static str,
        run_contract: &'static str,
        summary_contract: &'static str,
        format: &'static str,
        lifecycle_events: bool,
        flow_events: &'static str,
        dns_events: &'static str,
        policy_decision_events: bool,
        tls_events: &'static str,
        client_hello_events: bool,
        derived_http_records: &'static str,
        offline_schema_validation: bool,
        writer_owned_rotation: bool,
        content_addressed_blobs: bool,
        bounded_block_coalescing: bool,
        incomplete_run_recovery: bool,
    }

    #[derive(Debug, Serialize)]
    struct DecryptCapabilities {
        modes: &'static [&'static str],
        runtime_libraries: &'static [&'static str],
        runtime_apis: &'static [&'static str],
        runtime_evidence: &'static str,
        runtime_discovery: &'static str,
        runtime_max_bytes_per_event: usize,
        runtime_requires_attached_image: bool,
        runtime_requires_ca_trust: bool,
        runtime_supports_pinning_and_mtls: bool,
        relay_library_independent: bool,
        relay_requires_ca_trust: bool,
        relay_supports_pinning_and_mtls: bool,
        upstream_certificate_verification: bool,
        non_tls_passthrough: bool,
    }

    #[derive(Debug, Serialize)]
    struct RuntimeAcceptance {
        tcp_fake_dns: &'static [&'static str],
        udp_ipv4: &'static [&'static str],
        udp_ipv6: &'static [&'static str],
        tls_runtime: &'static [&'static str],
        tls_relay: &'static [&'static str],
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
        foreground_signal_forwarding: &'static [&'static str],
        upstream_unreachable_fail_closed: bool,
        foreground_modes: &'static [&'static str],
        foreground_owned_resources: bool,
        resources_close_when_run_exits: bool,
        setup_helper_session_scoped: bool,
        setup_helper_drops_privileges: bool,
        web_ui_optional: bool,
        concurrent_runs_isolated: bool,
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
        config_schema: Vec<String>,
        config_example_toml: Vec<String>,
        execute_prefix: Option<Vec<String>>,
        tls_ca_init: Option<Vec<String>>,
        logs_schema_event: Vec<String>,
        logs_schema_run: Vec<String>,
        logs_schema_summary: Vec<String>,
        logs_list: Vec<String>,
        logs_summary: Vec<String>,
        logs_query_prefix: Vec<String>,
        logs_tail_prefix: Vec<String>,
        logs_rotate: Vec<String>,
        logs_verify: Vec<String>,
        logs_recover_preview: Vec<String>,
        logs_prune_preview: Vec<String>,
    }

    #[derive(Debug, Serialize)]
    struct ExitCodes {
        ready: u8,
        not_ready: u8,
        usage: u8,
    }

    /// Print one JSON document and report whether execution is ready.
    ///
    /// This command never starts a daemon, changes config, attaches a cgroup,
    /// or executes the wrapped command.
    pub async fn run(explicit_path: Option<&Path>, args: AgentArgs) -> Result<bool> {
        let path_result = explicit_path.map(PathBuf::from).map_or_else(
            || crate::heimdall_config::discover_config_path(crate::heimdall_config::DEFAULT_DIR),
            Ok,
        );

        let (path, discovery_error) = match path_result {
            Ok(path) => (path, None),
            Err(error) => (
                Path::new(crate::heimdall_config::DEFAULT_DIR).join("config.toml"),
                Some(error),
            ),
        };
        let format = ConfigFormat::detect(&path).map(ConfigFormat::name);
        let validate_argv = argv_for(&path, &["config", "validate", "--json"]);
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
                    capture: None,
                    decrypt: None,
                    error: Some(config_error(error)),
                },
                execution: None,
                capabilities: capabilities(),
                decision: None,
                policies: Vec::new(),
                outbounds: Vec::new(),
                actions: Actions {
                    validate: validate_argv,
                    config_schema: config_argv(&["schema", "--version", "v1"]),
                    config_example_toml: config_argv(&["example", "--format", "toml"]),
                    execute_prefix: None,
                    tls_ca_init: None,
                    logs_schema_event: vec![
                        "heimdall".into(),
                        "logs".into(),
                        "schema".into(),
                        "--event".into(),
                        "v1".into(),
                    ],
                    logs_schema_run: vec![
                        "heimdall".into(),
                        "logs".into(),
                        "schema".into(),
                        "--run".into(),
                        "v1".into(),
                    ],
                    logs_schema_summary: vec![
                        "heimdall".into(),
                        "logs".into(),
                        "schema".into(),
                        "--summary".into(),
                        "v1".into(),
                    ],
                    logs_list: vec![
                        "heimdall".into(),
                        "logs".into(),
                        "list".into(),
                        "--json".into(),
                    ],
                    logs_summary: logs_argv(&["summary", "--run", "<RUN_ID>", "--json"]),
                    logs_query_prefix: logs_argv(&["query", "--run", "<RUN_ID>", "--jsonl"]),
                    logs_tail_prefix: logs_argv(&["tail", "--run", "<RUN_ID>", "--jsonl"]),
                    logs_rotate: logs_argv(&["rotate", "--run", "<RUN_ID>", "--json"]),
                    logs_verify: logs_argv(&["verify", "--run", "<RUN_ID>", "--json"]),
                    logs_recover_preview: logs_argv(&["recover", "--run", "<RUN_ID>", "--json"]),
                    logs_prune_preview: logs_argv(&[
                        "prune",
                        "--older-than",
                        "30d",
                        "--keep-last",
                        "20",
                        "--json",
                    ]),
                },
                exit_codes: exit_codes(),
            },
            Ok(config) => report_for_valid_config(path, format, config, args),
        };

        let ready = report.ready;
        println!("{}", serde_json::to_string(&report)?);
        Ok(ready)
    }

    fn report_for_valid_config(
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
        let daemon_required = false;
        let redaction_error = capture_redaction_error(&config.capture.redact_env);
        let ready = decision_error.is_none() && redaction_error.is_none();
        let execute_prefix = ready.then(|| {
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
                capture: Some(CaptureConfigReport {
                    mode: match config.capture.mode {
                        CaptureMode::Off => "off",
                        CaptureMode::On => "on",
                    },
                    max_bytes_per_flow: config.capture.max_bytes_per_flow,
                    block_max_bytes: config.capture.block_max_bytes,
                    flush_interval_ms: config.capture.flush_interval_ms,
                    boundaries: config
                        .capture
                        .boundaries
                        .iter()
                        .map(|boundary| boundary.name())
                        .collect(),
                    directions: config
                        .capture
                        .directions
                        .iter()
                        .map(|direction| direction.name())
                        .collect(),
                    redact_env: config.capture.redact_env.clone(),
                    redaction_values_ready: redaction_error.is_none(),
                    redaction_error,
                }),
                decrypt: Some(decrypt_report(&config.decrypt)),
                error: None,
            },
            execution: Some(ExecutionReport {
                backend: "linux-ebpf-foreground",
                owner: "heimdall-run",
                privilege_setup: "sudo-then-unprivileged-session-helper",
                daemon_required,
                web_ui_required: false,
            }),
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
                config_schema: config_argv(&["schema", "--version", "v1"]),
                config_example_toml: config_argv(&["example", "--format", "toml"]),
                execute_prefix,
                tls_ca_init: relay_ca_init_argv(&config.decrypt),
                logs_schema_event: vec![
                    "heimdall".into(),
                    "logs".into(),
                    "schema".into(),
                    "--event".into(),
                    "v1".into(),
                ],
                logs_schema_run: vec![
                    "heimdall".into(),
                    "logs".into(),
                    "schema".into(),
                    "--run".into(),
                    "v1".into(),
                ],
                logs_schema_summary: vec![
                    "heimdall".into(),
                    "logs".into(),
                    "schema".into(),
                    "--summary".into(),
                    "v1".into(),
                ],
                logs_list: vec![
                    "heimdall".into(),
                    "logs".into(),
                    "list".into(),
                    "--json".into(),
                ],
                logs_summary: logs_argv(&["summary", "--run", "<RUN_ID>", "--json"]),
                logs_query_prefix: logs_argv(&["query", "--run", "<RUN_ID>", "--jsonl"]),
                logs_tail_prefix: logs_argv(&["tail", "--run", "<RUN_ID>", "--jsonl"]),
                logs_rotate: logs_argv(&["rotate", "--run", "<RUN_ID>", "--json"]),
                logs_verify: logs_argv(&["verify", "--run", "<RUN_ID>", "--json"]),
                logs_recover_preview: logs_argv(&["recover", "--run", "<RUN_ID>", "--json"]),
                logs_prune_preview: logs_argv(&[
                    "prune",
                    "--older-than",
                    "30d",
                    "--keep-last",
                    "20",
                    "--json",
                ]),
            },
            exit_codes: exit_codes(),
        }
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

    fn logs_argv(suffix: &[&str]) -> Vec<String> {
        let mut argv = vec!["heimdall".into(), "logs".into()];
        argv.extend(suffix.iter().map(|value| (*value).to_string()));
        argv
    }

    fn config_argv(suffix: &[&str]) -> Vec<String> {
        let mut argv = vec!["heimdall".into(), "config".into()];
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

    fn capture_redaction_error(names: &[String]) -> Option<MachineError> {
        let mut diagnostics = Vec::new();
        let mut total = 0usize;
        for (index, name) in names.iter().enumerate() {
            match std::env::var_os(name) {
                None => diagnostics.push(ConfigDiagnostic {
                    code: "capture_redaction_env_unset".into(),
                    path: format!("$.capture.redact_env[{index}]"),
                    message: format!("environment variable `{name}` is unset"),
                    hint: format!("Export `{name}` with the secret value before running Heimdall."),
                }),
                Some(value) if value.is_empty() => diagnostics.push(ConfigDiagnostic {
                    code: "capture_redaction_env_empty".into(),
                    path: format!("$.capture.redact_env[{index}]"),
                    message: format!("environment variable `{name}` is empty"),
                    hint: format!(
                        "Set `{name}` to a non-empty value or remove it from redact_env."
                    ),
                }),
                Some(value) => {
                    let length = value.as_encoded_bytes().len();
                    total = total.saturating_add(length);
                    if length > 4096 {
                        diagnostics.push(ConfigDiagnostic {
                            code: "capture_redaction_env_too_large".into(),
                            path: format!("$.capture.redact_env[{index}]"),
                            message: format!(
                                "environment variable `{name}` exceeds the 4096-byte redaction limit"
                            ),
                            hint: "Use a bounded secret value of 4096 bytes or fewer.".into(),
                        });
                    }
                }
            }
        }
        if total > 65_536 {
            diagnostics.push(ConfigDiagnostic {
                code: "capture_redaction_values_too_large".into(),
                path: "$.capture.redact_env".into(),
                message: "capture redaction values exceed the 65536-byte aggregate limit".into(),
                hint: "Reduce the number or size of secret values used for capture redaction."
                    .into(),
            });
        }
        (!diagnostics.is_empty()).then(|| MachineError {
            code: "capture_redaction_not_ready",
            message: "capture redaction values are not ready".into(),
            diagnostics,
        })
    }

    fn decrypt_report(config: &DecryptConfig) -> DecryptConfigReport {
        match config.mode {
            crate::heimdall_config::DecryptMode::Off => DecryptConfigReport {
                mode: "off",
                ca_cert: None,
                ca_cert_sha256: None,
                ca_key: None,
                ca_material_ready: true,
            },
            crate::heimdall_config::DecryptMode::Runtime => DecryptConfigReport {
                mode: "runtime",
                ca_cert: None,
                ca_cert_sha256: None,
                ca_key: None,
                ca_material_ready: true,
            },
            crate::heimdall_config::DecryptMode::Relay => DecryptConfigReport {
                mode: "relay",
                ca_cert: config
                    .ca_cert
                    .as_ref()
                    .map(|path| path.display().to_string()),
                ca_cert_sha256: config
                    .ca_cert
                    .as_deref()
                    .and_then(super::tls::certificate_sha256),
                ca_key: config
                    .ca_key
                    .as_ref()
                    .map(|path| path.display().to_string()),
                ca_material_ready: config.ca_cert.as_ref().is_some_and(|path| path.is_file())
                    && config.ca_key.as_ref().is_some_and(|path| path.is_file()),
            },
        }
    }

    fn relay_ca_init_argv(config: &DecryptConfig) -> Option<Vec<String>> {
        if config.mode != crate::heimdall_config::DecryptMode::Relay {
            return None;
        }
        let ca_cert = config.ca_cert.as_ref()?;
        let ca_key = config.ca_key.as_ref()?;
        let directory = ca_cert.parent()?;
        (ca_key.parent() == Some(directory)
            && ca_cert.file_name().is_some_and(|name| name == "ca.pem")
            && ca_key.file_name().is_some_and(|name| name == "ca-key.pem"))
        .then(|| {
            vec![
                "heimdall".into(),
                "tls".into(),
                "init-ca".into(),
                "--dir".into(),
                directory.display().to_string(),
                "--json".into(),
            ]
        })
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
            capture: CaptureCapabilities {
                contract: crate::event_log::EVENT_CONTRACT,
                format: "content-addressed-blobs",
                tcp: true,
                udp: true,
                payload: "mode_dependent",
                tls_plaintext: true,
                boundary_allowlist: true,
                direction_allowlist: true,
                environment_redaction: true,
            },
            logs: LogsCapabilities {
                event_contract: crate::event_log::EVENT_CONTRACT,
                run_contract: crate::event_log::RUN_CONTRACT,
                summary_contract: crate::event_log::SUMMARY_CONTRACT,
                format: "jsonl",
                lifecycle_events: true,
                flow_events: "tcp+udp+payload",
                dns_events: "fake",
                policy_decision_events: true,
                tls_events: "runtime+relay",
                client_hello_events: true,
                derived_http_records: "http1_headers_from_tls_plaintext",
                offline_schema_validation: true,
                writer_owned_rotation: true,
                content_addressed_blobs: true,
                bounded_block_coalescing: true,
                incomplete_run_recovery: true,
            },
            decrypt: DecryptCapabilities {
                modes: &["off", "runtime", "relay"],
                runtime_libraries: &["openssl"],
                runtime_apis: &["SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex"],
                runtime_evidence: "tls.runtime+flow.data",
                runtime_discovery: "loaded_images_at_run_start",
                runtime_max_bytes_per_event: crate::heimdall_common::TAP_DATA_LEN,
                runtime_requires_attached_image: true,
                runtime_requires_ca_trust: false,
                runtime_supports_pinning_and_mtls: true,
                relay_library_independent: true,
                relay_requires_ca_trust: true,
                relay_supports_pinning_and_mtls: false,
                upstream_certificate_verification: true,
                non_tls_passthrough: true,
            },
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
                tls_runtime: &["curl-openssl"],
                tls_relay: &["curl"],
            },
            cli_acceptance: CliAcceptance {
                tcp_fake_dns: &["git"],
            },
            lifecycle: LifecycleCapabilities {
                descendant_cgroup_lifetime: true,
                exit_code_passthrough: true,
                signal_exit_code: "128+signal",
                foreground_signal_forwarding: &["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"],
                upstream_unreachable_fail_closed: true,
                foreground_modes: &["off", "runtime", "relay"],
                foreground_owned_resources: true,
                resources_close_when_run_exits: true,
                setup_helper_session_scoped: true,
                setup_helper_drops_privileges: true,
                web_ui_optional: true,
                concurrent_runs_isolated: true,
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
                    &["config", "validate", "--json"]
                ),
                [
                    "heimdall",
                    "--config",
                    "/tmp/config with spaces.toml",
                    "config",
                    "validate",
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
            assert!(runtimes.tls_runtime.contains(&"curl-openssl"));
            assert!(runtimes.tls_relay.contains(&"curl"));
            assert!(capabilities.cli_acceptance.tcp_fake_dns.contains(&"git"));
        }

        #[test]
        fn capture_capabilities_expose_plaintext_boundary() {
            let capture = capabilities().capture;
            assert_eq!(capture.contract, "heimdall.event/v1");
            assert_eq!(capture.format, "content-addressed-blobs");
            assert!(capture.tcp);
            assert!(capture.udp);
            assert_eq!(capture.payload, "mode_dependent");
            assert!(capture.tls_plaintext);
            assert!(capture.boundary_allowlist);
            assert!(capture.direction_allowlist);
            assert!(capture.environment_redaction);
            assert_eq!(capabilities().decrypt.modes, ["off", "runtime", "relay"]);
            assert_eq!(
                capabilities().decrypt.runtime_discovery,
                "loaded_images_at_run_start"
            );
            assert_eq!(
                capabilities().decrypt.runtime_apis,
                ["SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex"]
            );
            assert_eq!(
                capabilities().decrypt.runtime_evidence,
                "tls.runtime+flow.data"
            );
            assert_eq!(
                capabilities().decrypt.runtime_max_bytes_per_event,
                crate::heimdall_common::TAP_DATA_LEN
            );
            assert!(capabilities().decrypt.runtime_requires_attached_image);
        }

        #[test]
        fn missing_capture_redaction_environment_is_not_ready() {
            let names = vec!["HEIMDALL_TEST_VALUE_THAT_MUST_NOT_EXIST_7E1B".into()];
            let error = capture_redaction_error(&names).unwrap();
            assert_eq!(error.code, "capture_redaction_not_ready");
            assert_eq!(error.diagnostics[0].code, "capture_redaction_env_unset");
        }

        #[test]
        fn logs_capabilities_expose_agent_contracts() {
            let logs = capabilities().logs;
            assert_eq!(logs.event_contract, "heimdall.event/v1");
            assert_eq!(logs.run_contract, "heimdall.run/v1");
            assert_eq!(logs.summary_contract, "heimdall.logs.summary/v1");
            assert_eq!(logs.format, "jsonl");
            assert!(logs.lifecycle_events);
            assert_eq!(logs.flow_events, "tcp+udp+payload");
            assert_eq!(logs.dns_events, "fake");
            assert!(logs.policy_decision_events);
            assert_eq!(logs.tls_events, "runtime+relay");
            assert!(logs.client_hello_events);
            assert_eq!(
                logs.derived_http_records,
                "http1_headers_from_tls_plaintext"
            );
            assert!(logs.offline_schema_validation);
            assert!(logs.writer_owned_rotation);
            assert!(logs.content_addressed_blobs);
            assert!(logs.bounded_block_coalescing);
            assert!(logs.incomplete_run_recovery);
        }

        #[test]
        fn lifecycle_capabilities_expose_restart_boundary() {
            let lifecycle = capabilities().lifecycle;
            assert!(lifecycle.descendant_cgroup_lifetime);
            assert_eq!(
                lifecycle.foreground_signal_forwarding,
                ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"]
            );
            assert!(lifecycle.upstream_unreachable_fail_closed);
            assert_eq!(lifecycle.foreground_modes, ["off", "runtime", "relay"]);
            assert!(lifecycle.foreground_owned_resources);
            assert!(lifecycle.resources_close_when_run_exits);
            assert!(lifecycle.setup_helper_session_scoped);
            assert!(lifecycle.setup_helper_drops_privileges);
            assert!(lifecycle.web_ui_optional);
            assert!(lifecycle.concurrent_runs_isolated);
        }
    }
}
pub mod config;
pub mod init;
pub mod run;
