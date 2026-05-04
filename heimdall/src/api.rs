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
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rust_embed::Embed;
use heimdall_config::HeimdallConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::pod::{CgroupResolver, PodInformer};
use crate::store::{Flow, ListQuery, Message as StoreMessage, MessageQuery, Store};

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
    /// Optional pod-identity resolvers — mirror the relay's runtime
    /// state. When either is None (e.g. --no-k8s, or the informer
    /// failed at startup) the API returns messages with the pod_label
    /// fields left null.
    pub cgroup_resolver: Option<Arc<CgroupResolver>>,
    pub informer: Option<Arc<PodInformer>>,
}

impl AppState {
    /// Look up the pod identity for a cgroup_id. Returns None when
    /// either resolver is unavailable, the cgroup is not a pod, or
    /// the pod isn't in the informer's snapshot yet.
    fn pod_for_cgroup(&self, cgroup_id: i64) -> Option<crate::pod::PodInfo> {
        let cr = self.cgroup_resolver.as_ref()?;
        let inf = self.informer.as_ref()?;
        let uid = cr.resolve(cgroup_id as u64)?;
        inf.lookup(&uid)
    }
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
        .route("/api/flows/{id}/messages", get(flow_messages))
        .route("/api/messages", get(list_messages))
        .route("/api/ws/flows", get(ws_flows))
        // Embedded Dioxus UI bundle. Order matters: API first, then the
        // catch-all static handler so it doesn't shadow API paths.
        .route("/", get(serve_index))
        .route("/{*path}", get(serve_static))
        .layer(
            // Allow any origin while we develop the Dioxus UI side-by-side.
            // Once the UI is bundled into the same binary at `/`, same-origin
            // makes this unnecessary, but harmless.
            CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Embedded UI bundle — populated by `dx build --platform web --release`
// in heimdall-ui, plus DaisyUI vendored CSS copied in by build.rs.
// ---------------------------------------------------------------------------

#[derive(Embed)]
#[folder = "../heimdall-ui/dist/"]
struct UiAssets;

async fn serve_index() -> Response {
    embedded_response("index.html")
}

async fn serve_static(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        return embedded_response("index.html");
    }
    // Try exact match first.
    if let Some(file) = UiAssets::get(path) {
        return file_response(path, file);
    }
    // SPA fallback: client-side routes (no extension) get index.html so
    // Dioxus router can take over. File-like requests get a real 404.
    if !path.contains('.') {
        return embedded_response("index.html");
    }
    (StatusCode::NOT_FOUND, format!("not found: /{path}")).into_response()
}

fn embedded_response(path: &str) -> Response {
    match UiAssets::get(path) {
        Some(file) => file_response(path, file),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("UI bundle missing ({path}). Run: cd heimdall-ui && dx build --platform web --release"),
        )
            .into_response(),
    }
}

fn file_response(path: &str, file: rust_embed::EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        [(header::CONTENT_TYPE, mime.essence_str())],
        file.data.into_owned(),
    )
        .into_response()
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
    default_observe: bool,
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
        default_connection: cfg.routing.default.use_,
        default_observe: cfg.routing.default.observe,
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

// ─── Phase B: messages endpoints ────────────────────────────────────────

#[derive(Deserialize, Default)]
struct MessageParams {
    #[serde(default = "default_msg_limit")]
    limit: u32,
    cgroup_id: Option<i64>,
    since_us: Option<i64>,
}

fn default_msg_limit() -> u32 { 200 }

/// Wire shape for messages — pass-through of the stored row plus
/// pod identity resolved at API time. The DB schema deliberately
/// stores cgroup_id only; pods can change identity (rolling update,
/// restart) and recomputing on read avoids stale labels.
#[derive(Serialize)]
struct ApiMessage {
    id: i64,
    flow_id: Option<i64>,
    ts_us: i64,
    cgroup_id: i64,
    tgid: i64,
    dir: i64,
    total_len: i64,
    captured_len: i64,
    body: Vec<u8>,
    pod_namespace: Option<String>,
    pod_name: Option<String>,
}

fn enrich_messages(rows: Vec<StoreMessage>, s: &AppState) -> Vec<ApiMessage> {
    // Cache cgroup → pod within the response so a flood of messages
    // from the same pod doesn't redo the cgroup walk per row.
    let mut cache: std::collections::HashMap<i64, Option<crate::pod::PodInfo>> =
        std::collections::HashMap::new();
    rows.into_iter()
        .map(|m| {
            let pod = cache
                .entry(m.cgroup_id)
                .or_insert_with(|| s.pod_for_cgroup(m.cgroup_id))
                .clone();
            ApiMessage {
                id: m.id,
                flow_id: m.flow_id,
                ts_us: m.ts_us,
                cgroup_id: m.cgroup_id,
                tgid: m.tgid,
                dir: m.dir,
                total_len: m.total_len,
                captured_len: m.captured_len,
                body: m.body,
                pod_namespace: pod.as_ref().map(|p| p.namespace.clone()),
                pod_name: pod.as_ref().map(|p| p.name.clone()),
            }
        })
        .collect()
}

/// Messages for a specific flow, ordered ASC by ts_us. Returns [] when
/// the flow has no captured plaintext yet (or tap is disabled).
async fn flow_messages(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Query(p): Query<MessageParams>,
) -> Result<Json<Vec<ApiMessage>>, ApiError> {
    let rows = s
        .store
        .list_messages(MessageQuery {
            limit: p.limit,
            flow_id: Some(id),
            cgroup_id: None,
            since_us: p.since_us,
        })
        .await
        .map_err(internal)?;
    Ok(Json(enrich_messages(rows, &s)))
}

/// Free-form messages query — useful for the "all plaintext for this
/// pod" view, or for host-side libssl events with no flow correlation.
async fn list_messages(
    State(s): State<AppState>,
    Query(p): Query<MessageParams>,
) -> Result<Json<Vec<ApiMessage>>, ApiError> {
    let rows = s
        .store
        .list_messages(MessageQuery {
            limit: p.limit,
            flow_id: None,
            cgroup_id: p.cgroup_id,
            since_us: p.since_us,
        })
        .await
        .map_err(internal)?;
    Ok(Json(enrich_messages(rows, &s)))
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
