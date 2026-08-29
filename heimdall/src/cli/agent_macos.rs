//! Stable unavailable-backend contract for the in-development macOS target.

use std::path::{Path, PathBuf};

use crate::heimdall_config::{
    Action, CaptureMode, ConfigDiagnostic, ConfigFormat, DecryptConfig, DecryptMode, DnsMode,
};
use anyhow::Result;
use serde_json::{Value, json};

const CONTRACT_VERSION: &str = "heimdall.agent/v8";

#[derive(clap::Args, Debug)]
pub struct AgentArgs {
    /// Preview a named policy while reporting backend unavailability.
    #[arg(short = 'p', long)]
    policy: Option<String>,
}

/// Print one JSON document and always report execution as not ready.
#[cfg_attr(
    all(test, not(target_os = "macos")),
    allow(
        dead_code,
        reason = "Linux tests compile the portable macOS report builder without dispatching its target entry point"
    )
)]
pub fn run(explicit_path: Option<&Path>, args: AgentArgs) -> Result<bool> {
    let report = build_report(explicit_path, args);
    println!("{}", serde_json::to_string(&report)?);
    Ok(false)
}

fn build_report(explicit_path: Option<&Path>, args: AgentArgs) -> Value {
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
    let config_result =
        discovery_error.map_or_else(|| crate::heimdall_config::HeimdallConfig::load(&path), Err);

    let (config, decision, policies, outbounds) = match config_result {
        Err(error) => (
            json!({
                "path": path.display().to_string(),
                "format": format,
                "valid": false,
                "capture": null,
                "decrypt": null,
                "error": {
                    "code": error.code(),
                    "message": error.to_string(),
                    "diagnostics": error.diagnostics(),
                },
            }),
            Value::Null,
            Vec::new(),
            Vec::new(),
        ),
        Ok(config) => {
            let policy_name = args
                .policy
                .unwrap_or_else(|| config.proxy.default_policy.clone());
            let decision = config.policy(&policy_name).map_or_else(
                || {
                    json!({
                        "policy": policy_name,
                        "dns": "unknown",
                        "resolver": null,
                        "tcp_final": "unknown",
                        "udp_final": "unknown",
                        "error": {
                            "code": "unknown_policy",
                            "message": "the requested policy is not declared",
                            "diagnostics": [],
                        },
                    })
                },
                |policy| {
                    json!({
                        "policy": policy_name,
                        "dns": dns_name(policy.dns.mode),
                        "resolver": null,
                        "tcp_final": action_name(&policy.final_.tcp),
                        "udp_final": action_name(&policy.final_.udp),
                        "error": null,
                    })
                },
            );
            let policies = config.proxy.policies.keys().cloned().collect();
            let outbounds = config.proxy.outbounds.keys().cloned().collect();
            let redaction_error = capture_redaction_error(&config.capture.redact_env);
            let redaction_values_ready = redaction_error.is_none();
            let config_report = json!({
                "path": path.display().to_string(),
                "format": format,
                "valid": true,
                "capture": {
                    "mode": match config.capture.mode {
                        CaptureMode::Off => "off",
                        CaptureMode::On => "on",
                    },
                    "max_bytes_per_flow": config.capture.max_bytes_per_flow,
                    "block_max_bytes": config.capture.block_max_bytes,
                    "flush_interval_ms": config.capture.flush_interval_ms,
                    "boundaries": config.capture.boundaries.iter()
                        .map(|value| value.name()).collect::<Vec<_>>(),
                    "directions": config.capture.directions.iter()
                        .map(|value| value.name()).collect::<Vec<_>>(),
                    "redact_env": config.capture.redact_env,
                    "redaction_values_ready": redaction_values_ready,
                    "redaction_error": redaction_error,
                },
                "decrypt": decrypt_report(&config.decrypt),
                "error": null,
            });
            (config_report, decision, policies, outbounds)
        }
    };

    json!({
        "contract": CONTRACT_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "ready": false,
        "platform": {
            "os": "macos",
            "architecture": std::env::consts::ARCH,
        },
        "backends": [
            {
                "backend": "macos-explicit",
                "status": "in_development",
                "available": false,
                "transparent": false,
                "persistent_daemon_required": false,
                "reason_code": "macos_explicit_backend_unavailable",
            },
            {
                "backend": "macos-transparent",
                "status": "in_development",
                "available": false,
                "transparent": true,
                "provider": "NETransparentProxyProvider",
                "companion_required": true,
                "persistent_daemon_required": false,
                "reason_code": "macos_transparent_backend_unavailable",
            },
        ],
        "diagnostics": [{
            "code": "macos_backend_unavailable",
            "path": "$.execution",
            "message": "macOS backends are in development and not available",
            "hint": "Use a supported Linux host for execution; do not substitute a system-wide proxy.",
        }],
        "config": config,
        "execution": null,
        "capabilities": unavailable_capabilities(),
        "decision": decision,
        "policies": policies,
        "outbounds": outbounds,
        "actions": {
            "validate": argv_for(&path, &["config", "validate", "--json"]),
            "config_schema": ["heimdall", "config", "schema", "--version", "v1"],
            "config_example_toml": ["heimdall", "config", "example", "--format", "toml"],
            "execute_prefix": null,
            "resolver_inspect": [],
            "tls_ca_init": null,
            "logs_schema_event": logs_argv(&["schema", "--event", "v1"]),
            "logs_schema_run": logs_argv(&["schema", "--run", "v1"]),
            "logs_schema_summary": logs_argv(&["schema", "--summary", "v1"]),
            "logs_schema_flow": logs_argv(&["schema", "--flow", "v1"]),
            "logs_list": logs_argv(&["list", "--json"]),
            "logs_summary": logs_argv(&["summary", "--run", "<RUN_ID>", "--json"]),
            "logs_flow": logs_argv(&[
                "flow", "--run", "<RUN_ID>", "--flow", "<FLOW_ID>", "--json",
            ]),
            "logs_query_prefix": logs_argv(&["query", "--run", "<RUN_ID>", "--jsonl"]),
            "logs_tail_prefix": logs_argv(&["tail", "--run", "<RUN_ID>", "--jsonl"]),
            "logs_rotate": logs_argv(&["rotate", "--run", "<RUN_ID>", "--json"]),
            "logs_verify": logs_argv(&["verify", "--run", "<RUN_ID>", "--json"]),
            "logs_recover_preview": logs_argv(&["recover", "--run", "<RUN_ID>", "--json"]),
            "logs_prune_preview": logs_argv(&[
                "prune", "--older-than", "30d", "--keep-last", "20", "--json",
            ]),
        },
        "exit_codes": {"ready": 0, "not_ready": 1, "usage": 2},
    })
}

fn unavailable_capabilities() -> Value {
    json!({
        "capture": {
            "contract": "heimdall.event/v1",
            "format": "unavailable",
            "tcp": false,
            "udp": false,
            "payload": "unavailable",
            "tls_plaintext": false,
            "boundary_allowlist": false,
            "direction_allowlist": false,
            "environment_redaction": false,
        },
        "logs": {
            "event_contract": "heimdall.event/v1",
            "run_contract": "heimdall.run/v1",
            "summary_contract": "heimdall.logs.summary/v1",
            "flow_summary_contract": "heimdall.logs.flow/v1",
            "format": "jsonl",
            "lifecycle_events": false,
            "flow_events": "unavailable",
            "dns_events": "unavailable",
            "policy_decision_events": false,
            "tls_events": "unavailable",
            "client_hello_events": false,
            "derived_http_records": "unavailable",
            "offline_schema_validation": true,
            "writer_owned_rotation": false,
            "content_addressed_blobs": false,
            "bounded_block_coalescing": false,
            "incomplete_run_recovery": true,
        },
        "decrypt": {
            "modes": [],
            "runtime_libraries": [],
            "runtime_apis": [],
            "runtime_evidence": "unavailable",
            "runtime_discovery": "unavailable",
            "runtime_loader_discovery": "unavailable",
            "runtime_loader_images_can_map_after_exec": false,
            "runtime_privileged_dynamic_attachment": false,
            "runtime_max_bytes_per_event": 0,
            "runtime_requires_attached_image": false,
            "runtime_requires_ca_trust": false,
            "runtime_supports_pinning_and_mtls": false,
            "relay_library_independent": false,
            "relay_requires_ca_trust": false,
            "relay_supports_pinning_and_mtls": false,
            "upstream_certificate_verification": false,
            "non_tls_passthrough": false,
        },
        "udp": {
            "connected": false,
            "connectionless": false,
            "connectionless_ipv4": false,
            "connectionless_ipv6": false,
            "connectionless_ipv6_single_peer": false,
            "ipv4_mapped_ipv6_socket": false,
            "concurrent_shared_source_port": false,
            "concurrent_shared_source_port_ipv4": false,
            "concurrent_shared_source_port_ipv6": false,
            "association_reuse": false,
            "multi_response": false,
            "max_socks5_payload_bytes": 0,
            "quic": "unavailable",
            "quic_ipv4": false,
            "quic_ipv6": false,
            "quic_address_family_migration": false,
            "exchange": "unavailable",
        },
        "runtime_acceptance": {
            "tcp_fake_dns": [],
            "udp_ipv4": [],
            "udp_ipv6": [],
            "tls_runtime": [],
            "tls_relay": [],
        },
        "cli_acceptance": {"tcp_fake_dns": []},
        "lifecycle": {
            "descendant_cgroup_lifetime": false,
            "exit_code_passthrough": false,
            "signal_exit_code": "unavailable",
            "foreground_signal_forwarding": [],
            "upstream_unreachable_fail_closed": false,
            "foreground_modes": [],
            "foreground_owned_resources": false,
            "resources_close_when_run_exits": false,
            "setup_helper_session_scoped": false,
            "setup_helper_drops_privileges": false,
            "web_ui_optional": true,
            "concurrent_runs_isolated": false,
        },
    })
}

fn capture_redaction_error(names: &[String]) -> Option<Value> {
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
                hint: format!("Set `{name}` to a non-empty value or remove it from redact_env."),
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
            hint: "Reduce the number or size of secret values used for capture redaction.".into(),
        });
    }
    (!diagnostics.is_empty()).then(|| {
        json!({
            "code": "capture_redaction_not_ready",
            "message": "capture redaction values are not ready",
            "diagnostics": diagnostics,
        })
    })
}

fn decrypt_report(config: &DecryptConfig) -> Value {
    let (ca_material_ready, ca_material_error) = match config.mode {
        DecryptMode::Off | DecryptMode::Runtime => (true, Value::Null),
        DecryptMode::Relay => (
            false,
            json!({
                "code": "macos_relay_tls_unavailable",
                "message": "relay TLS cannot run until the transparent macOS backend is available",
                "diagnostics": [],
            }),
        ),
    };
    json!({
        "mode": decrypt_name(config.mode),
        "ca_cert": config.ca_cert.as_ref().map(|value| value.display().to_string()),
        "ca_cert_sha256": null,
        "ca_key": config.ca_key.as_ref().map(|value| value.display().to_string()),
        "ca_material_ready": ca_material_ready,
        "ca_material_error": ca_material_error,
    })
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

const fn dns_name(mode: DnsMode) -> &'static str {
    match mode {
        DnsMode::Fake => "fake",
        DnsMode::System => "system",
    }
}

const fn decrypt_name(mode: DecryptMode) -> &'static str {
    match mode {
        DecryptMode::Off => "off",
        DecryptMode::Runtime => "runtime",
        DecryptMode::Relay => "relay",
    }
}

fn action_name(action: &Action) -> String {
    match action {
        Action::Route { outbound } => format!("route:{outbound}"),
        Action::Direct => "direct".into(),
        Action::Reject { method } => format!("reject:{method:?}").to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_report_never_exposes_an_execution_prefix() {
        let report = build_report(
            Some(Path::new("/definitely/missing/heimdall-config.toml")),
            AgentArgs { policy: None },
        );

        assert_eq!(report["contract"], "heimdall.agent/v8");
        assert_eq!(report["ready"], false);
        assert_eq!(report["platform"]["os"], "macos");
        assert!(report["execution"].is_null());
        assert!(report["actions"]["execute_prefix"].is_null());
        assert_eq!(
            report["diagnostics"][0]["code"],
            "macos_backend_unavailable"
        );
        assert_eq!(report["backends"][0]["available"], false);
        assert_eq!(report["backends"][1]["available"], false);
        assert_eq!(
            report["backends"][1]["provider"],
            "NETransparentProxyProvider"
        );
        assert_eq!(report["capabilities"]["udp"]["connected"], false);
        assert_eq!(report["capabilities"]["decrypt"]["modes"], json!([]));
        assert_eq!(report["capabilities"]["capture"]["format"], "unavailable");
        assert_eq!(report["capabilities"]["logs"]["format"], "jsonl");
        assert_eq!(
            report["capabilities"]["logs"]["offline_schema_validation"],
            true
        );
        assert_eq!(
            report["actions"]["logs_schema_event"],
            json!(["heimdall", "logs", "schema", "--event", "v1"])
        );
        assert_eq!(
            report["actions"]["logs_recover_preview"],
            json!(["heimdall", "logs", "recover", "--run", "<RUN_ID>", "--json"])
        );
    }

    #[test]
    fn valid_shared_config_remains_inspectable_without_enabling_execution() {
        let path = std::env::temp_dir().join(format!(
            "heimdall-macos-agent-config-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, crate::cli::init::InitFormat::Toml.template()).unwrap();

        let report = build_report(Some(&path), AgentArgs { policy: None });
        std::fs::remove_file(path).unwrap();

        assert_eq!(report["config"]["valid"], true);
        assert_eq!(report["config"]["capture"]["redaction_values_ready"], true);
        assert_eq!(report["config"]["decrypt"]["ca_material_ready"], true);
        assert_eq!(report["decision"]["policy"], "default");
        assert_eq!(report["decision"]["tcp_final"], "route:default");
        assert!(report["execution"].is_null());
        assert!(report["actions"]["execute_prefix"].is_null());
    }
}
