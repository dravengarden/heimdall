//! Loopback-only control API used by `heimdall run`.

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use heimdall_config::{Connection, Decision};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{CliOverrides, PolicyEngineSlot, policy::PolicyEngine};

#[derive(Clone)]
pub struct AppState {
    pub connections: BTreeMap<String, Connection>,
    pub cli_overrides: CliOverrides,
    pub policy_engine: PolicyEngineSlot,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/cli/register", post(register_cli))
        .route("/api/cli/deregister", post(deregister_cli))
        .with_state(state)
}

pub async fn serve(state: AppState, addr: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind control API on {addr}"))?;
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
    pub connection: String,
    #[serde(default = "default_dns_strategy")]
    pub dns: String,
}

fn default_dns_strategy() -> String {
    "fake".into()
}

#[derive(Debug, Serialize)]
pub struct CliOverrideEntry {
    pub cgroup_id: u64,
    pub connection: String,
}

async fn register_cli(
    State(state): State<AppState>,
    Json(request): Json<CliRegisterReq>,
) -> Result<Json<CliOverrideEntry>, ApiError> {
    if !state.connections.contains_key(&request.connection) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("unknown proxy `{}`", request.connection),
        ));
    }
    let dns_hijack = match request.dns.as_str() {
        "fake" => true,
        "system" => false,
        other => {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("invalid dns `{other}`; expected `fake` or `system`"),
            ));
        }
    };
    let engine = engine(&state)?;
    engine
        .register_external(request.cgroup_id, dns_hijack)
        .await
        .map_err(internal)?;
    state.cli_overrides.write().insert(
        request.cgroup_id,
        Decision {
            use_: request.connection.clone(),
        },
    );
    info!(cgroup_id = request.cgroup_id, proxy = %request.connection, dns = %request.dns, "CLI cgroup registered");
    Ok(Json(CliOverrideEntry {
        cgroup_id: request.cgroup_id,
        connection: request.connection,
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
    engine(&state)?
        .deregister_external(params.cgroup_id)
        .await
        .map_err(internal)?;
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
