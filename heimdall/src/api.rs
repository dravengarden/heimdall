//! Loopback-only control API used by `heimdall run`.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use heimdall_config::{Decision, DnsMode, ProxyPolicy};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    CliOverrides, PolicyEngineSlot, UdpSessions, close_udp_sessions_for_cgroup,
    policy::PolicyEngine,
    state::{self, Registration},
};

#[derive(Clone)]
pub struct AppState {
    pub policies: BTreeMap<String, ProxyPolicy>,
    pub cli_overrides: CliOverrides,
    pub policy_engine: PolicyEngineSlot,
    pub udp_sessions: UdpSessions,
    pub health: Arc<parking_lot::RwLock<HealthReport>>,
    pub event_clients: crate::EventClients,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HealthReport {
    pub contract: String,
    pub ready: bool,
    pub decrypt_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<crate::tls_runtime::StartReport>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/cli/register", post(register_cli))
        .route("/api/cli/deregister", post(deregister_cli))
        .with_state(state)
}

pub async fn serve(state: AppState, listener: tokio::net::TcpListener) -> Result<()> {
    let addr = listener.local_addr().context("read control API address")?;
    info!(addr = %addr, "control API listening");
    axum::serve(listener, router(state))
        .await
        .context("serve control API")
}

async fn health(State(state): State<AppState>) -> Json<HealthReport> {
    Json(state.health.read().clone())
}

#[derive(Debug, Deserialize)]
pub struct CliRegisterReq {
    pub cgroup_id: u64,
    pub policy: String,
    pub run_id: uuid::Uuid,
    pub event_socket: std::path::PathBuf,
}

#[derive(Debug, Serialize)]
pub struct CliOverrideEntry {
    pub cgroup_id: u64,
    pub policy: String,
    pub run_id: uuid::Uuid,
}

async fn register_cli(
    State(state): State<AppState>,
    Json(request): Json<CliRegisterReq>,
) -> Result<Json<CliOverrideEntry>, ApiError> {
    let policy = state.policies.get(&request.policy).ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("unknown policy `{}`", request.policy),
        )
    })?;
    let expected_socket = crate::event_log::event_socket_filename(request.run_id);
    if request
        .event_socket
        .file_name()
        .and_then(|value| value.to_str())
        != Some(expected_socket.as_str())
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "event socket filename does not match run_id".into(),
        ));
    }
    let event_client =
        crate::event_log::EventClient::connect(request.event_socket.clone()).map_err(internal)?;
    let reject_udp = policy.rejects_all_udp();
    let engine = engine(&state)?;
    state::persist_registration(&Registration {
        cgroup_id: request.cgroup_id,
        policy: request.policy.clone(),
        run_id: request.run_id,
        event_socket: request.event_socket,
    })
    .map_err(internal)?;
    if let Err(error) = engine
        .register_external(
            request.cgroup_id,
            policy.dns_hijack(),
            matches!(policy.dns.mode, DnsMode::System),
            reject_udp,
        )
        .await
    {
        let _ = state::remove_registration(request.cgroup_id);
        return Err(internal(error));
    }
    state.cli_overrides.write().insert(
        request.cgroup_id,
        Decision {
            policy: request.policy.clone(),
        },
    );
    state
        .event_clients
        .write()
        .insert(request.cgroup_id, event_client);
    info!(cgroup_id = request.cgroup_id, policy = %request.policy, "CLI cgroup registered");
    Ok(Json(CliOverrideEntry {
        cgroup_id: request.cgroup_id,
        policy: request.policy,
        run_id: request.run_id,
    }))
}

#[derive(Debug, Deserialize)]
struct DeregisterParams {
    cgroup_id: u64,
}

async fn deregister_cli(
    State(state): State<AppState>,
    Query(params): Query<DeregisterParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.cli_overrides.write().remove(&params.cgroup_id);
    let event_client = state.event_clients.write().remove(&params.cgroup_id);
    close_udp_sessions_for_cgroup(&state.udp_sessions, params.cgroup_id).await;
    let events_drained = if let Some(event_client) = event_client {
        tokio::task::spawn_blocking(move || event_client.wait_for_flows(Duration::from_secs(5)))
            .await
            .map_err(|error| internal(error.into()))?
    } else {
        true
    };
    engine(&state)?
        .deregister_external(params.cgroup_id)
        .await
        .map_err(internal)?;
    state::remove_registration(params.cgroup_id).map_err(internal)?;
    if !events_drained {
        return Err(ApiError(
            StatusCode::GATEWAY_TIMEOUT,
            "timed out draining run flow events".into(),
        ));
    }
    info!(cgroup_id = params.cgroup_id, "CLI cgroup deregistered");
    Ok(Json(serde_json::json!({"ok": true})))
}

fn engine(state: &AppState) -> Result<Arc<PolicyEngine>, ApiError> {
    state.policy_engine.lock().clone().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "eBPF policy registry is not ready".into(),
        )
    })
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

fn internal(error: anyhow::Error) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"))
}
