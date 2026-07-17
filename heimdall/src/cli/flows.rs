//! `heimdall flows ...` — list, show, tail.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use heimdall_config::HeimdallConfig;
use serde::Serialize;

use crate::store::{Flow, ListQuery, Store};

#[derive(clap::Subcommand, Debug)]
pub enum FlowsCmd {
    /// List recent flows (most recent first).
    List(ListArgs),
    /// Show a single flow by id.
    Show(ShowArgs),
    /// Search flows by hostname / unit / connection.
    Search(SearchArgs),
}

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Maximum rows to return.
    #[arg(long, short = 'n', default_value = "50")]
    limit: u32,

    /// Filter by connection name (e.g. `default`, `corp`).
    #[arg(long, short = 'c')]
    connection: Option<String>,

    /// Filter by unit / slice substring (e.g. `nginx`, `system.slice`).
    #[arg(long, short = 'u')]
    unit: Option<String>,

    /// Filter by destination hostname substring.
    #[arg(long, short = 'H')]
    host: Option<String>,

    /// Filter by SOCKS5 ATYP class. One of `ip` (v4 literal),
    /// `ip6` (v6 literal), or `domain` (hostname recovered via fake-IP DNS).
    #[arg(long, value_parser = ["ip", "ip6", "domain"])]
    atyp: Option<String>,

    /// Output JSON Lines (one flow per line). Useful for `jq` and AI tools.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ShowArgs {
    id: i64,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct SearchArgs {
    query: String,
    #[arg(long, short = 'n', default_value = "100")]
    limit: u32,
    #[arg(long)]
    json: bool,
}

pub async fn run(config_path: &Path, cmd: FlowsCmd) -> Result<()> {
    let cfg = HeimdallConfig::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    let store = open_store(&cfg.runtime.state_dir.join("flows.db")).await?;

    match cmd {
        FlowsCmd::List(args) => list(&store, args).await,
        FlowsCmd::Show(args) => show(&store, args).await,
        FlowsCmd::Search(args) => search(&store, args).await,
    }
}

async fn open_store(path: &Path) -> Result<Store> {
    Store::open(path)
        .await
        .with_context(|| format!("open flow store at {}", path.display()))
}

// ---------------------------------------------------------------------------
// flows list
// ---------------------------------------------------------------------------

async fn list(store: &Store, args: ListArgs) -> Result<()> {
    let q = ListQuery {
        limit: args.limit,
        connection: args.connection,
        unit_substr: args.unit,
        host_substr: args.host,
        atyp: args.atyp,
        ..Default::default()
    };
    let rows = store.list(q).await?;
    if args.json {
        for f in rows {
            println!("{}", serde_json::to_string(&FlowJson::from(&f))?);
        }
    } else {
        print_table(&rows);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// flows show
// ---------------------------------------------------------------------------

async fn show(store: &Store, args: ShowArgs) -> Result<()> {
    let f = store
        .get(args.id)
        .await?
        .with_context(|| format!("no flow with id {}", args.id))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&FlowJson::from(&f))?);
    } else {
        print_detail(&f);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// flows search
// ---------------------------------------------------------------------------

async fn search(store: &Store, args: SearchArgs) -> Result<()> {
    let q = ListQuery {
        limit: args.limit,
        host_substr: Some(args.query.clone()),
        ..Default::default()
    };
    let rows = store.list(q).await?;
    if args.json {
        for f in rows {
            println!("{}", serde_json::to_string(&FlowJson::from(&f))?);
        }
    } else {
        print_table(&rows);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON shape (stable contract for AI / Warp skills)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct FlowJson<'a> {
    id: i64,
    ts: String, // RFC3339
    duration_ms: Option<i64>,
    unit: Option<String>, // "slice/unit"
    connection: &'a str,
    dst_host: Option<&'a str>,
    dst_ip: &'a str,
    dst_port: i64,
    bytes_up: i64,
    bytes_down: i64,
    upstream: Option<&'a str>,
    atyp: Option<&'a str>,
    error: Option<&'a str>,
}

impl<'a> From<&'a Flow> for FlowJson<'a> {
    fn from(f: &'a Flow) -> Self {
        let unit = unit_label(f);
        Self {
            id: f.id,
            ts: format_us(f.ts_start_us),
            duration_ms: f.ts_end_us.map(|e| (e - f.ts_start_us) / 1000),
            unit,
            connection: &f.connection_name,
            dst_host: f.dst_host.as_deref(),
            dst_ip: &f.dst_ip,
            dst_port: f.dst_port,
            bytes_up: f.bytes_up,
            bytes_down: f.bytes_down,
            upstream: f.upstream_addr.as_deref(),
            atyp: f.atyp.as_deref(),
            error: f.error.as_deref(),
        }
    }
}

/// Render a flow's systemd identity as `slice/unit`, or whichever half
/// is present. None when neither was resolved.
fn unit_label(f: &Flow) -> Option<String> {
    match (&f.slice, &f.unit) {
        (Some(s), Some(u)) => Some(format!("{s}/{u}")),
        (_, Some(u)) => Some(u.clone()),
        (Some(s), None) => Some(s.clone()),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

fn print_table(rows: &[Flow]) {
    if rows.is_empty() {
        eprintln!("(no flows)");
        return;
    }

    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "id", "time", "unit", "conn", "atyp", "dst", "port", "↑", "↓", "via",
        ]);

    for f in rows {
        let unit = unit_label(f).unwrap_or_else(|| "-".to_string());
        // dst column shows the hostname when fake-IP DNS produced one,
        // otherwise the literal IP — bracketed for IPv6 so it parses
        // unambiguously when the reader pastes it into curl etc.
        let dst = f.dst_host.clone().unwrap_or_else(|| {
            if f.dst_ip.contains(':') {
                format!("[{}]", f.dst_ip)
            } else {
                f.dst_ip.clone()
            }
        });
        t.add_row(vec![
            Cell::new(f.id),
            Cell::new(format_short_us(f.ts_start_us)),
            Cell::new(unit),
            color_cell(&f.connection_name),
            atyp_cell(f.atyp.as_deref()),
            Cell::new(truncate(&dst, 50)),
            Cell::new(f.dst_port),
            Cell::new(human_bytes(f.bytes_up)),
            Cell::new(human_bytes(f.bytes_down)),
            Cell::new(f.upstream_addr.as_deref().unwrap_or("-")),
        ]);
    }
    println!("{t}");
}

fn atyp_cell(atyp: Option<&str>) -> Cell {
    match atyp {
        Some("ip6") => Cell::new("ip6").fg(Color::Magenta),
        Some("domain") => Cell::new("dns").fg(Color::Blue),
        Some(other) => Cell::new(other).fg(Color::DarkGrey),
        None => Cell::new("-").fg(Color::DarkGrey),
    }
}

fn print_detail(f: &Flow) {
    println!("flow #{}", f.id);
    println!("  ts_start    {}", format_us(f.ts_start_us));
    if let Some(e) = f.ts_end_us {
        println!(
            "  ts_end      {}  ({} ms)",
            format_us(e),
            (e - f.ts_start_us) / 1000
        );
    } else {
        println!("  ts_end      (open)");
    }
    if let Some(label) = unit_label(f) {
        println!("  unit        {label}");
    }
    println!("  connection  {}", f.connection_name);
    if let Some(h) = &f.dst_host {
        println!("  dst_host    {h}");
    }
    println!("  dst         {}", format_addr_port(&f.dst_ip, f.dst_port));
    println!(
        "  bytes ↑↓    {} / {}",
        human_bytes(f.bytes_up),
        human_bytes(f.bytes_down)
    );
    if let Some(u) = &f.upstream_addr {
        println!("  via         {u}");
    }
    if let Some(a) = &f.atyp {
        println!("  socks5 atyp {a}");
    }
    if let Some(e) = &f.error {
        println!("  error       {e}");
    }
}

fn color_cell(connection: &str) -> Cell {
    let c = match connection {
        "default" => Color::Green,
        "corp" => Color::Cyan,
        "bypass" => Color::Yellow,
        _ => Color::White,
    };
    Cell::new(connection).fg(c)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

/// Render `ip:port` with IPv6 wrapped in `[...]:port`. We treat any IP
/// containing a `:` as v6 — the only other place a colon shows up in
/// `dst_ip` is inside an `Ipv6Addr::to_string()` output.
fn format_addr_port(ip: &str, port: i64) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
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

fn format_us(us: i64) -> String {
    let dt = DateTime::<Local>::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_micros(us as u64),
    );
    dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn format_short_us(us: i64) -> String {
    let dt = DateTime::<Local>::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_micros(us as u64),
    );
    dt.format("%H:%M:%S").to_string()
}
