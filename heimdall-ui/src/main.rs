//! Heimdall Web UI — Dioxus 0.6 (WASM, single-page) + DaisyUI styling.
//!
//! Talks to the heimdall daemon at the same origin:
//!   GET  /api/status, /api/flows, /api/flows/:id
//!   WS   /api/ws/flows  — pushes new flows in real time
//!
//! No build-time tailwind / daisyui generation — DaisyUI's full-class
//! CSS is loaded via CDN from `Dioxus.toml`. We can vendor + tree-shake
//! later if size becomes an issue.

#![allow(non_snake_case)]

use chrono::{DateTime, Local, TimeZone};
use dioxus::prelude::*;
use futures::StreamExt;
use gloo_net::{http::Request, websocket::futures::WebSocket};
use gloo_net::websocket::Message;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Wire types — must match heimdall::store::Flow
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Flow {
    pub id: i64,
    #[serde(default)]
    pub socket_cookie: Option<i64>,
    #[serde(default)]
    pub cgroup_id: Option<i64>,
    #[serde(default)]
    pub pod_uid: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub pod_name: Option<String>,
    pub connection_name: String,
    #[serde(default)]
    pub dst_host: Option<String>,
    pub dst_ip: String,
    pub dst_port: i64,
    pub ts_start_us: i64,
    #[serde(default)]
    pub ts_end_us: Option<i64>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    #[serde(default)]
    pub upstream_addr: Option<String>,
    #[serde(default)]
    pub atyp: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    pub version: String,
    pub connections: u64,
    pub default_connection: String,
    pub relay_listen: String,
    pub dns_listen: String,
    pub fake_ip_cidr: String,
    pub flows_count: i64,
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

fn main() {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        div { class: "min-h-screen bg-base-200",
            Navbar {}
            div { class: "container mx-auto p-4",
                StatusBar {}
                FlowList {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Navbar
// ---------------------------------------------------------------------------

#[component]
fn Navbar() -> Element {
    rsx! {
        div { class: "navbar bg-base-100 shadow",
            div { class: "flex-1",
                a { class: "btn btn-ghost text-xl", "🛡️ Heimdall" }
            }
            div { class: "flex-none gap-2",
                a { class: "link link-hover", href: "/api/status", "API status" }
                a { class: "link link-hover", href: "https://github.com/dravengarden/heimdall", "GitHub" }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Status bar (top)
// ---------------------------------------------------------------------------

#[component]
fn StatusBar() -> Element {
    let mut status = use_signal(|| None::<Status>);

    use_effect(move || {
        spawn(async move {
            if let Ok(s) = fetch_status().await {
                status.set(Some(s));
            }
        });
    });

    rsx! {
        div { class: "stats shadow w-full bg-base-100 mb-4",
            div { class: "stat",
                div { class: "stat-title", "Heimdall" }
                div { class: "stat-value text-primary text-2xl",
                    {status.read().as_ref().map(|s| format!("v{}", s.version)).unwrap_or_else(|| "—".to_string())}
                }
                div { class: "stat-desc",
                    {status.read().as_ref().map(|s| s.relay_listen.clone()).unwrap_or_else(|| "loading…".to_string())}
                }
            }
            div { class: "stat",
                div { class: "stat-title", "Flows recorded" }
                div { class: "stat-value text-2xl",
                    {status.read().as_ref().map(|s| s.flows_count.to_string()).unwrap_or_else(|| "—".to_string())}
                }
                div { class: "stat-desc",
                    {status.read().as_ref().map(|s| format!("default → {}", s.default_connection)).unwrap_or_default()}
                }
            }
            div { class: "stat",
                div { class: "stat-title", "DNS / fake-IP" }
                div { class: "stat-value text-base font-mono",
                    {status.read().as_ref().map(|s| s.dns_listen.clone()).unwrap_or_default()}
                }
                div { class: "stat-desc font-mono",
                    {status.read().as_ref().map(|s| s.fake_ip_cidr.clone()).unwrap_or_default()}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Flow list — initial fetch + WebSocket live updates
// ---------------------------------------------------------------------------

#[component]
fn FlowList() -> Element {
    let mut flows = use_signal::<Vec<Flow>>(Vec::new);
    let mut filter = use_signal(String::new);
    let mut connection_filter = use_signal(|| String::from(""));

    // Initial load
    use_effect(move || {
        spawn(async move {
            if let Ok(rows) = fetch_flows(200).await {
                flows.set(rows);
            }
        });
    });

    // Live WebSocket
    use_effect(move || {
        spawn(async move {
            loop {
                match WebSocket::open(&ws_url("/api/ws/flows")) {
                    Ok(ws) => {
                        let (_sink, mut stream) = ws.split();
                        while let Some(Ok(msg)) = stream.next().await {
                            if let Message::Text(text) = msg {
                                if let Ok(f) = serde_json::from_str::<Flow>(&text) {
                                    flows.with_mut(|v| {
                                        v.insert(0, f);
                                        if v.len() > 500 {
                                            v.truncate(500);
                                        }
                                    });
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
                gloo_timers::future::TimeoutFuture::new(2_000).await;
            }
        });
    });

    let visible: Vec<Flow> = flows
        .read()
        .iter()
        .filter(|f| {
            let q = filter.read().to_lowercase();
            let cf = connection_filter.read().clone();
            let q_ok = q.is_empty()
                || matches_str(&f.dst_host, &q)
                || matches_str(&Some(f.dst_ip.clone()), &q)
                || matches_str(&f.pod_name, &q)
                || matches_str(&f.namespace, &q)
                || f.connection_name.to_lowercase().contains(&q);
            let c_ok = cf.is_empty() || f.connection_name == cf;
            q_ok && c_ok
        })
        .cloned()
        .collect();

    rsx! {
        // Filter bar
        div { class: "flex gap-2 mb-4",
            input {
                class: "input input-bordered flex-1",
                r#type: "text",
                placeholder: "search hostname / pod / IP / connection…",
                value: "{filter}",
                oninput: move |e| filter.set(e.value()),
            }
            select {
                class: "select select-bordered",
                value: "{connection_filter}",
                oninput: move |e| connection_filter.set(e.value()),
                option { value: "", "all connections" }
                option { value: "default", "default" }
                option { value: "conviva", "conviva" }
                option { value: "bypass", "bypass" }
            }
            div { class: "badge badge-lg badge-neutral self-center",
                "{visible.len()} / {flows.read().len()}"
            }
        }

        // Table
        div { class: "overflow-x-auto bg-base-100 rounded-lg shadow",
            table { class: "table table-zebra table-pin-rows",
                thead {
                    tr {
                        th { "id" }
                        th { "time" }
                        th { "pod" }
                        th { "conn" }
                        th { "dst" }
                        th { "port" }
                        th { class: "text-right", "↑" }
                        th { class: "text-right", "↓" }
                        th { "via" }
                    }
                }
                tbody {
                    for f in visible.iter() {
                        FlowRow { key: "{f.id}", flow: f.clone() }
                    }
                }
            }
        }
    }
}

#[component]
fn FlowRow(flow: Flow) -> Element {
    let pod = match (&flow.namespace, &flow.pod_name) {
        (Some(ns), Some(n)) => format!("{ns}/{n}"),
        _ => "-".to_string(),
    };
    let dst = flow.dst_host.clone().unwrap_or_else(|| flow.dst_ip.clone());
    let conn_class = match flow.connection_name.as_str() {
        "default" => "badge badge-success",
        "conviva" => "badge badge-info",
        "bypass" => "badge badge-warning",
        _ => "badge",
    };
    let row_class = if flow.error.is_some() { "text-error" } else { "" };

    rsx! {
        tr { class: "{row_class}",
            td { "{flow.id}" }
            td { class: "font-mono text-xs", { format_us_short(flow.ts_start_us) } }
            td { class: "text-xs", "{pod}" }
            td { span { class: "{conn_class}", "{flow.connection_name}" } }
            td { class: "max-w-md truncate", title: "{dst}", "{dst}" }
            td { class: "font-mono", "{flow.dst_port}" }
            td { class: "text-right font-mono", { human_bytes(flow.bytes_up) } }
            td { class: "text-right font-mono", { human_bytes(flow.bytes_down) } }
            td { class: "font-mono text-xs",
                {flow.upstream_addr.clone().unwrap_or_else(|| "-".to_string())}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fetch_flows(limit: u32) -> Result<Vec<Flow>, gloo_net::Error> {
    let url = format!("/api/flows?limit={limit}");
    Request::get(&url).send().await?.json::<Vec<Flow>>().await
}

async fn fetch_status() -> Result<Status, gloo_net::Error> {
    Request::get("/api/status").send().await?.json::<Status>().await
}

fn ws_url(path: &str) -> String {
    let loc = web_sys::window().unwrap().location();
    let proto = if loc.protocol().unwrap_or_default() == "https:" { "wss" } else { "ws" };
    let host = loc.host().unwrap_or_default();
    format!("{proto}://{host}{path}")
}

fn matches_str(s: &Option<String>, q: &str) -> bool {
    s.as_ref().map(|v| v.to_lowercase().contains(q)).unwrap_or(false)
}

fn human_bytes(n: i64) -> String {
    const K: f64 = 1024.0;
    let n = n as f64;
    if n < K {
        format!("{n:.0}B")
    } else if n < K * K {
        format!("{:.1}KB", n / K)
    } else if n < K * K * K {
        format!("{:.1}MB", n / (K * K))
    } else {
        format!("{:.1}GB", n / (K * K * K))
    }
}

fn format_us_short(us: i64) -> String {
    let secs = us / 1_000_000;
    let nanos = ((us % 1_000_000) * 1_000) as u32;
    let dt: DateTime<Local> = Local
        .timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(|| Local.timestamp_opt(0, 0).unwrap());
    dt.format("%H:%M:%S").to_string()
}

