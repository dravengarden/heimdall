//! HTTP API for the heimdall daemon.
//!
//! - `GET  /api/health`            — daemon liveness
//! - `GET  /api/status`            — config summary + counts
//! - `GET  /api/flows`             — list with filters (limit, conn, pod, host)
//! - `GET  /api/flows/:id`         — single flow detail
//! - `GET  /api/ws/flows`          — WebSocket pushing every new flow
//!
//! For Phase A.3, the same axum app will mount the Dioxus Web UI at `/`.
//!
//! The server listens on `runtime.apiListen` (default `127.0.0.1:9999`).
//! Set to `0.0.0.0:9999` to expose for LAN browser access; firewall is
//! managed in NixOS.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use heimdall_config::HeimdallConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::store::{Flow, ListQuery, Store};

// ---------------------------------------------------------------------------
// Live flow event bus — relay → broadcast → WebSocket subscribers
// ---------------------------------------------------------------------------

/// Event published by the relay each time a flow finishes (success or error).
/// Subscribers see only the post-finish state with full byte counts.
#[derive(Debug, Clone, Serialize)]
pub struct FlowEvent {
    pub flow_id: i64,
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<FlowEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Best-effort publish. If no subscribers, lost.
    pub fn publish(&self, ev: FlowEvent) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FlowEvent> {
        self.tx.subscribe()
    }
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub events: EventBus,
    pub cfg_path: std::path::PathBuf,
}

// ---------------------------------------------------------------------------
// Router + entry point
// ---------------------------------------------------------------------------

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/flows", get(list_flows))
        .route("/api/flows/{id}", get(show_flow))
        .route("/api/ws/flows", get(ws_flows))
        .layer(
            // Allow any origin while we develop the Dioxus UI side-by-side.
            // Once the UI is bundled into the same binary at `/`, same-origin
            // makes this unnecessary, but harmless.
            CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any),
        )
        .with_state(state)
}

pub async fn serve(state: AppState, addr: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind API on {addr}"))?;
    info!(addr = %addr, "HTTP API listening");
    axum::serve(listener, router(state))
        .await
        .context("axum serve")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct StatusResp {
    version: &'static str,
    config: String,
    connections: usize,
    rules: usize,
    default_connection: String,
    relay_listen: String,
    dns_listen: String,
    fake_ip_cidr: String,
    state_dir: String,
    flow_retention_secs: i64,
    flows_count: i64,
}

async fn status(State(s): State<AppState>) -> Result<Json<StatusResp>, ApiError> {
    // Read config fresh — picks up any reload that happened.
    let cfg = HeimdallConfig::load(&s.cfg_path)
        .with_context(|| format!("load {}", s.cfg_path.display()))
        .map_err(internal)?;
    let count = s
        .store
        .list(ListQuery { limit: 10_000_000, ..Default::default() })
        .await
        .map_err(internal)?
        .len() as i64;
    Ok(Json(StatusResp {
        version: env!("CARGO_PKG_VERSION"),
        config: s.cfg_path.display().to_string(),
        connections: cfg.connections.len(),
        rules: cfg.routing.rules.len(),
        default_connection: cfg.routing.default,
        relay_listen: cfg.runtime.listen,
        dns_listen: cfg.runtime.dns_listen,
        fake_ip_cidr: cfg.runtime.fake_ip_cidr,
        state_dir: cfg.runtime.state_dir.display().to_string(),
        flow_retention_secs: cfg.runtime.flow_retention_secs,
        flows_count: count,
    }))
}

#[derive(Deserialize, Default)]
struct ListParams {
    #[serde(default = "default_limit")]
    limit: u32,
    connection: Option<String>,
    pod: Option<String>,
    host: Option<String>,
    since_us: Option<i64>,
}

fn default_limit() -> u32 { 100 }

async fn list_flows(
    State(s): State<AppState>,
    Query(p): Query<ListParams>,
) -> Result<Json<Vec<Flow>>, ApiError> {
    let q = ListQuery {
        limit: p.limit,
        since_us: p.since_us,
        pod_substr: p.pod,
        connection: p.connection,
        host_substr: p.host,
    };
    let rows = s.store.list(q).await.map_err(internal)?;
    Ok(Json(rows))
}

async fn show_flow(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Flow>, ApiError> {
    let f = s
        .store
        .get(id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("no flow with id {id}")))?;
    Ok(Json(f))
}

// WebSocket: pushes a JSON line for every new flow recorded by the relay.
async fn ws_flows(ws: WebSocketUpgrade, State(s): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| ws_flows_loop(socket, s))
}

async fn ws_flows_loop(mut socket: WebSocket, s: AppState) {
    let mut rx = s.events.subscribe();
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    // Fetch the just-finished flow so the client gets full data.
                    match s.store.get(ev.flow_id).await {
                        Ok(Some(f)) => {
                            let payload = match serde_json::to_string(&f) {
                                Ok(s) => s,
                                Err(e) => { warn!(?e, "ws: serialize"); continue; }
                            };
                            if socket.send(Message::Text(payload.into())).await.is_err() {
                                return; // peer gone
                            }
                        }
                        Ok(None) => {} // race: row missing, skip
                        Err(e) => warn!(error = %e, "ws: store.get"),
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "ws: subscriber lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None => return,
                Some(Ok(_)) => {} // ignore client messages
                Some(Err(_)) => return,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Error wrapper — converts anyhow to JSON {error: "..."}
// ---------------------------------------------------------------------------

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

fn internal(e: anyhow::Error) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
}
