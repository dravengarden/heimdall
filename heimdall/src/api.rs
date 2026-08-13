//! Loopback-only control API used by `heimdall run`.

use std::{collections::BTreeMap, sync::Arc};

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

async fn health() -> &'static str {
    "ok"
}

#[derive(Debug, Deserialize)]
pub struct CliRegisterReq {
    pub cgroup_id: u64,
    pub policy: String,
}

#[derive(Debug, Serialize)]
pub struct CliOverrideEntry {
    pub cgroup_id: u64,
    pub policy: String,
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
    let reject_udp = policy.rejects_all_udp();
    let engine = engine(&state)?;
    state::persist_registration(&Registration {
        cgroup_id: request.cgroup_id,
        policy: request.policy.clone(),
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
    info!(cgroup_id = request.cgroup_id, policy = %request.policy, "CLI cgroup registered");
    Ok(Json(CliOverrideEntry {
        cgroup_id: request.cgroup_id,
        policy: request.policy,
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
    close_udp_sessions_for_cgroup(&state.udp_sessions, params.cgroup_id).await;
    engine(&state)?
        .deregister_external(params.cgroup_id)
        .await
        .map_err(internal)?;
    state::remove_registration(params.cgroup_id).map_err(internal)?;
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
