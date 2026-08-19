//! Agent-first access to per-run event logs.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::event_log::{
    BlobSummary, EVENT_CONTRACT, EVENT_SCHEMA, Event, RUN_SCHEMA, RunManifest, RunResult,
    SegmentManifest, persist_manifest, read_manifest, request_rotation, run_is_active, runs_root,
};

#[derive(Subcommand, Debug)]
pub enum LogsCmd {
    /// Print a bundled JSON Schema without network access.
    Schema(SchemaArgs),
    /// List discovered runs as one JSON document.
    List(JsonArgs),
    /// Resolve one run ID to its absolute directory.
    Path(RunJsonArgs),
    /// Summarize low-cardinality health and evidence counters for one run.
    Summary(RunJsonArgs),
    /// Stream matching event objects as JSONL.
    Query(QueryArgs),
    /// Read a run and optionally follow it across segment rotation.
    Tail(TailArgs),
    /// Ask an active run to close its current segment and open the next.
    Rotate(RunJsonArgs),
    /// Verify event sequence, segment digests, and manifest consistency.
    Verify(RunJsonArgs),
    /// Preview or recover an orphaned run's last committed JSONL prefix.
    Recover(RecoverArgs),
    /// Preview or remove closed run directories according to retention limits.
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct SchemaArgs {
    /// Print the heimdall.event schema version (currently v1).
    #[arg(
        long,
        value_name = "VERSION",
        conflicts_with = "run",
        required_unless_present = "run"
    )]
    event: Option<String>,
    /// Print the heimdall.run schema version (currently v1).
    #[arg(
        long,
        value_name = "VERSION",
        conflicts_with = "event",
        required_unless_present = "event"
    )]
    run: Option<String>,
}

#[derive(Args, Debug)]
pub struct JsonArgs {
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct RunJsonArgs {
    /// UUIDv7 run identifier.
    #[arg(long)]
    run: Uuid,
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct QueryArgs {
    /// UUIDv7 run identifier.
    #[arg(long)]
    run: Uuid,
    /// Match an event kind. Repeat to select multiple kinds.
    #[arg(long)]
    kind: Vec<String>,
    /// Match one flow UUIDv7.
    #[arg(long)]
    flow: Option<Uuid>,
    /// Include records at or after this sequence.
    #[arg(long)]
    since_seq: Option<u64>,
    /// Include records at or before this sequence.
    #[arg(long)]
    until_seq: Option<u64>,
    /// Match flow.data records with this direction. Repeat to select both.
    #[arg(long, value_parser = ["client_to_remote", "remote_to_client"])]
    direction: Vec<String>,
    /// Match an explicit observation boundary. Repeat to select multiple boundaries.
    #[arg(
        long,
        value_parser = ["transport", "tls_plaintext.runtime", "tls_plaintext.relay"]
    )]
    boundary: Vec<String>,
    /// Match a stable error code in event data. Repeat to select multiple codes.
    #[arg(long)]
    error_code: Vec<String>,
    /// Match records by whether data contains a content-addressed blob reference.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    has_blob: Option<bool>,
    /// Stream raw heimdall.event/v1 objects, one per line.
    #[arg(long)]
    jsonl: bool,
}

#[derive(Args, Debug)]
pub struct TailArgs {
    #[command(flatten)]
    query: QueryArgs,
    /// Continue reading new records and numbered segments until the run closes.
    #[arg(long)]
    follow: bool,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Select closed runs older than this duration, for example 30d or 12h.
    #[arg(long)]
    older_than: Option<String>,
    /// Always retain this many newest runs.
    #[arg(long, default_value_t = 20)]
    keep_last: usize,
    /// Reduce total run storage to this many bytes by selecting oldest closed runs.
    #[arg(long)]
    max_total_bytes: Option<u64>,
    /// Actually delete selected run directories. Without this flag, only preview.
    #[arg(long)]
    apply: bool,
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct RecoverArgs {
    /// UUIDv7 run identifier.
    #[arg(long)]
    run: Uuid,
    /// Finalize the recoverable prefix and preserve discarded evidence.
    #[arg(long)]
    apply: bool,
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct RunSummary {
    run_id: Uuid,
    state: String,
    started_at: String,
    closed_at: Option<String>,
    policy: String,
    backend: String,
    run_dir: String,
}

pub fn run(command: LogsCmd) -> Result<()> {
    match command {
        LogsCmd::Schema(args) => schema(args),
        LogsCmd::List(args) => list(args),
        LogsCmd::Path(args) => path(args),
        LogsCmd::Summary(args) => summary(args),
        LogsCmd::Query(args) => query(&args, 0).map(|_| ()),
        LogsCmd::Tail(args) => tail(args),
        LogsCmd::Rotate(args) => rotate(args),
        LogsCmd::Verify(args) => verify(args),
        LogsCmd::Recover(args) => recover(args),
        LogsCmd::Prune(args) => prune(args),
    }
}

fn schema(args: SchemaArgs) -> Result<()> {
    let raw = match (args.event.as_deref(), args.run.as_deref()) {
        (Some("v1"), None) => EVENT_SCHEMA,
        (None, Some("v1")) => RUN_SCHEMA,
        (Some(version), None) => anyhow::bail!("unsupported event schema `{version}`"),
        (None, Some(version)) => anyhow::bail!("unsupported run schema `{version}`"),
        _ => anyhow::bail!("select exactly one of --event v1 or --run v1"),
    };
    let value: Value = serde_json::from_str(raw).context("decode bundled JSON Schema")?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

fn list(args: JsonArgs) -> Result<()> {
    let runs = discover_runs()?;
    let summaries = runs
        .into_iter()
        .map(|(run_dir, manifest)| RunSummary {
            run_id: manifest.run_id,
            state: manifest.state,
            started_at: manifest.started_at,
            closed_at: manifest.closed_at,
            policy: manifest.policy,
            backend: manifest.backend,
            run_dir: absolute(&run_dir).display().to_string(),
        })
        .collect::<Vec<_>>();
    let value = json!({
        "contract": "heimdall.logs.list/v1",
        "runs_root": absolute(&runs_root()?).display().to_string(),
        "runs": summaries
    });
    print_document(&value, args.json)
}

fn path(args: RunJsonArgs) -> Result<()> {
    let (run_dir, manifest) = find_run(args.run)?;
    let value = json!({
        "contract": "heimdall.logs.path/v1",
        "run_id": manifest.run_id,
        "state": manifest.state,
        "run_dir": absolute(&run_dir).display().to_string(),
        "manifest": absolute(&run_dir.join("run.json")).display().to_string()
    });
    print_document(&value, args.json)
}

fn summary(args: RunJsonArgs) -> Result<()> {
    let (run_dir, manifest) = find_run(args.run)?;
    let value = summarize_run(&run_dir, &manifest)?;
    print_document(&value, args.json)
}

#[derive(Default)]
struct RunCounters {
    records: u64,
    first_seq: Option<u64>,
    last_seq: u64,
    next_seq: u64,
    missing_records: u64,
    out_of_order_records: u64,
    duration_ns: u64,
    by_kind: BTreeMap<String, u64>,
    open_flows: BTreeSet<Uuid>,
    closed_flows: BTreeSet<Uuid>,
    flows_by_network: BTreeMap<String, u64>,
    flows_by_status: BTreeMap<String, u64>,
    flow_failures_by_code: BTreeMap<String, u64>,
    flow_duration_us_total: u64,
    flow_duration_us_max: u64,
    client_to_remote_bytes: u64,
    remote_to_client_bytes: u64,
    capture_records: u64,
    captured_original_bytes: u64,
    captured_stored_bytes: u64,
    truncated_capture_records: u64,
    capture_by_boundary: BTreeMap<String, u64>,
    error_events_by_code: BTreeMap<String, u64>,
}

impl RunCounters {
    fn observe(&mut self, event: &Event) {
        self.records = self.records.saturating_add(1);
        self.first_seq.get_or_insert(event.seq);
        if self.next_seq == 0 {
            self.next_seq = 1;
        }
        if event.seq > self.next_seq {
            self.missing_records = self
                .missing_records
                .saturating_add(event.seq - self.next_seq);
        } else if event.seq < self.next_seq {
            self.out_of_order_records = self.out_of_order_records.saturating_add(1);
        }
        self.next_seq = self.next_seq.max(event.seq.saturating_add(1));
        self.last_seq = self.last_seq.max(event.seq);
        self.duration_ns = self.duration_ns.max(event.monotonic_ns);
        increment(&mut self.by_kind, &event.kind);

        match event.kind.as_str() {
            "flow.open" => {
                if let Some(flow_id) = event.flow_id {
                    self.open_flows.insert(flow_id);
                }
                increment_value(&mut self.flows_by_network, &event.data, "network");
            }
            "flow.close" => {
                if let Some(flow_id) = event.flow_id {
                    self.closed_flows.insert(flow_id);
                }
                increment_value(&mut self.flows_by_status, &event.data, "status");
                if let Some(code) = event.data.get("error_code").and_then(Value::as_str) {
                    increment(&mut self.flow_failures_by_code, code);
                }
                let duration = value_u64(&event.data, "duration_us");
                self.flow_duration_us_total = self.flow_duration_us_total.saturating_add(duration);
                self.flow_duration_us_max = self.flow_duration_us_max.max(duration);
                self.client_to_remote_bytes = self
                    .client_to_remote_bytes
                    .saturating_add(value_u64(&event.data, "client_to_remote_bytes"));
                self.remote_to_client_bytes = self
                    .remote_to_client_bytes
                    .saturating_add(value_u64(&event.data, "remote_to_client_bytes"));
            }
            "flow.data" => {
                self.capture_records = self.capture_records.saturating_add(1);
                self.captured_original_bytes = self
                    .captured_original_bytes
                    .saturating_add(value_u64(&event.data, "original_bytes"));
                self.captured_stored_bytes = self
                    .captured_stored_bytes
                    .saturating_add(value_u64(&event.data, "stored_bytes"));
                if event.data.get("truncated").and_then(Value::as_bool) == Some(true) {
                    self.truncated_capture_records =
                        self.truncated_capture_records.saturating_add(1);
                }
                increment_value(&mut self.capture_by_boundary, &event.data, "boundary");
            }
            "run.error" | "tls.error" => {
                increment_value(&mut self.error_events_by_code, &event.data, "code");
            }
            _ => {}
        }
    }
}

fn summarize_run(run_dir: &Path, manifest: &RunManifest) -> Result<Value> {
    let mut counters = RunCounters::default();
    for segment in segment_paths(run_dir)? {
        let file = File::open(&segment).with_context(|| format!("open {}", segment.display()))?;
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = line
                .with_context(|| format!("read {} line {}", segment.display(), line_number + 1))?;
            let event: Event = serde_json::from_str(&line).with_context(|| {
                format!("decode {} line {}", segment.display(), line_number + 1)
            })?;
            counters.observe(&event);
        }
    }
    let active_flows = counters
        .open_flows
        .difference(&counters.closed_flows)
        .count() as u64;
    let dns_queries = counters.by_kind.get("dns.query").copied().unwrap_or(0);
    let dns_answers = counters.by_kind.get("dns.answer").copied().unwrap_or(0);
    let policy_decisions = counters
        .by_kind
        .get("policy.decision")
        .copied()
        .unwrap_or(0);
    let tls_runtime = counters.by_kind.get("tls.runtime").copied().unwrap_or(0);
    let tls_client_hellos = counters
        .by_kind
        .get("tls.client_hello")
        .copied()
        .unwrap_or(0);
    let tls_handshakes = counters.by_kind.get("tls.handshake").copied().unwrap_or(0);
    let tls_errors = counters.by_kind.get("tls.error").copied().unwrap_or(0);
    let http_requests = counters.by_kind.get("http.request").copied().unwrap_or(0);
    let http_responses = counters.by_kind.get("http.response").copied().unwrap_or(0);
    let run_errors = counters.by_kind.get("run.error").copied().unwrap_or(0);
    Ok(json!({
        "contract": "heimdall.logs.summary/v1",
        "run_id": manifest.run_id,
        "state": manifest.state,
        "complete": manifest.result.as_ref().is_some_and(|result| result.complete),
        "duration_ns": counters.duration_ns,
        "sequence": {
            "first": counters.first_seq,
            "last": counters.last_seq,
            "records": counters.records,
            "missing_records": counters.missing_records,
            "out_of_order_records": counters.out_of_order_records,
            "contiguous": counters.missing_records == 0 && counters.out_of_order_records == 0
        },
        "events": {"by_kind": counters.by_kind},
        "flows": {
            "opened": counters.open_flows.len(),
            "closed": counters.closed_flows.len(),
            "active": active_flows,
            "by_network": counters.flows_by_network,
            "by_status": counters.flows_by_status,
            "failures_by_code": counters.flow_failures_by_code,
            "duration_us": {"total": counters.flow_duration_us_total, "max": counters.flow_duration_us_max},
            "bytes": {
                "client_to_remote": counters.client_to_remote_bytes,
                "remote_to_client": counters.remote_to_client_bytes
            }
        },
        "capture": {
            "records": counters.capture_records,
            "original_bytes": counters.captured_original_bytes,
            "stored_bytes": counters.captured_stored_bytes,
            "truncated_records": counters.truncated_capture_records,
            "by_boundary": counters.capture_by_boundary
        },
        "dns": {"queries": dns_queries, "answers": dns_answers},
        "policy": {"decisions": policy_decisions},
        "tls": {
            "runtime_records": tls_runtime,
            "client_hellos": tls_client_hellos,
            "handshakes": tls_handshakes,
            "errors": tls_errors
        },
        "http": {"requests": http_requests, "responses": http_responses},
        "error_events": {"total": run_errors + tls_errors, "by_code": counters.error_events_by_code},
        "storage": {"segments": manifest.segments.len(), "blobs": manifest.blobs.count, "blob_bytes": manifest.blobs.bytes}
    }))
}

fn increment(counts: &mut BTreeMap<String, u64>, key: &str) {
    let value = counts.entry(key.to_owned()).or_default();
    *value = value.saturating_add(1);
}

fn increment_value(counts: &mut BTreeMap<String, u64>, data: &Value, key: &str) {
    if let Some(value) = data.get(key).and_then(Value::as_str) {
        increment(counts, value);
    }
}

fn value_u64(data: &Value, key: &str) -> u64 {
    data.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn rotate(args: RunJsonArgs) -> Result<()> {
    let response = match request_rotation(args.run) {
        Ok(response) => response,
        Err(error) => json!({
            "contract": "heimdall.logs.control/v1",
            "ok": false,
            "code": "run_not_active",
            "message": error.to_string()
        }),
    };
    let ok = response["ok"].as_bool() == Some(true);
    print_document(&response, args.json)?;
    anyhow::ensure!(ok, "log rotation request failed");
    Ok(())
}

fn tail(args: TailArgs) -> Result<()> {
    let mut last_seq = 0;
    loop {
        last_seq = query(&args.query, last_seq)?;
        if !args.follow {
            return Ok(());
        }
        let (_, manifest) = find_run(args.query.run)?;
        if matches!(manifest.state.as_str(), "closed" | "failed") {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn query(args: &QueryArgs, after_seq: u64) -> Result<u64> {
    anyhow::ensure!(args.jsonl, "only --jsonl output is supported");
    let (run_dir, _) = find_run(args.run)?;
    let mut last_seq = after_seq;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for segment in segment_paths(&run_dir)? {
        let file = File::open(&segment).with_context(|| format!("open {}", segment.display()))?;
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = line
                .with_context(|| format!("read {} line {}", segment.display(), line_number + 1))?;
            let event: Event = serde_json::from_str(&line).with_context(|| {
                format!("decode {} line {}", segment.display(), line_number + 1)
            })?;
            if event.seq <= after_seq {
                continue;
            }
            last_seq = last_seq.max(event.seq);
            if !matches_query(&event, args) {
                continue;
            }
            output
                .write_all(line.as_bytes())
                .context("write queried event")?;
            output.write_all(b"\n").context("write event newline")?;
        }
    }
    output.flush().context("flush queried events")?;
    Ok(last_seq)
}

fn matches_query(event: &Event, args: &QueryArgs) -> bool {
    (args.kind.is_empty() || args.kind.iter().any(|kind| kind == &event.kind))
        && args.flow.is_none_or(|flow| event.flow_id == Some(flow))
        && args.since_seq.is_none_or(|seq| event.seq >= seq)
        && args.until_seq.is_none_or(|seq| event.seq <= seq)
        && matches_data_string(&event.data, "direction", &args.direction)
        && matches_data_string(&event.data, "boundary", &args.boundary)
        && matches_data_string(&event.data, "error_code", &args.error_code)
        && args
            .has_blob
            .is_none_or(|expected| event.data.get("blob").is_some() == expected)
}

fn matches_data_string(data: &Value, key: &str, selected: &[String]) -> bool {
    selected.is_empty()
        || data
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| selected.iter().any(|selected| selected == value))
}

fn verify(args: RunJsonArgs) -> Result<()> {
    let (run_dir, manifest) = find_run(args.run)?;
    let value = verify_run(&run_dir, &manifest)?;
    let valid = value["valid"] == true;
    print_document(&value, args.json)?;
    anyhow::ensure!(valid, "event log verification failed");
    Ok(())
}

#[derive(Debug)]
struct RecoveryAnalysis {
    segments: Vec<SegmentManifest>,
    blobs: BlobSummary,
    events: u64,
    last_valid_seq: u64,
    tail: Option<RecoveryTail>,
    empty_segment: Option<PathBuf>,
}

#[derive(Debug)]
struct RecoveryTail {
    segment: PathBuf,
    valid_bytes: u64,
    bytes: Vec<u8>,
}

fn recover(args: RecoverArgs) -> Result<()> {
    let (run_dir, mut manifest) = find_run(args.run)?;
    if matches!(manifest.state.as_str(), "closed" | "failed") {
        return recovery_failure(
            &manifest,
            args.apply,
            args.json,
            "run_already_finalized",
            "closed and failed runs are immutable",
        );
    }
    if run_is_active(args.run)? {
        return recovery_failure(
            &manifest,
            args.apply,
            args.json,
            "run_active",
            "the run still has an active foreground owner",
        );
    }
    let analysis = match analyze_recovery(&run_dir, &manifest) {
        Ok(analysis) => analysis,
        Err(error) => {
            return recovery_failure(
                &manifest,
                args.apply,
                args.json,
                "recovery_not_safe",
                &error.to_string(),
            );
        }
    };
    let state_before = manifest.state.clone();
    let discarded_tail_bytes = analysis
        .tail
        .as_ref()
        .map_or(0, |tail| tail.bytes.len() as u64);
    let discarded_tail_sha256 = analysis
        .tail
        .as_ref()
        .map(|tail| hex::encode(Sha256::digest(&tail.bytes)));
    let mut recovery_dir = None;
    if args.apply {
        recovery_dir = Some(apply_recovery(
            &run_dir,
            &mut manifest,
            &analysis,
            discarded_tail_sha256.as_deref(),
        )?);
    }
    let value = json!({
        "contract": "heimdall.logs.recover/v1",
        "run_id": manifest.run_id,
        "applicable": true,
        "applied": args.apply,
        "code": if args.apply { "recovered_incomplete_run" } else { "recovery_available" },
        "state_before": state_before,
        "state_after": if args.apply { "failed" } else { manifest.state.as_str() },
        "projected_state": "failed",
        "events": analysis.events,
        "segments": analysis.segments.len(),
        "last_valid_seq": analysis.last_valid_seq,
        "discarded_tail_bytes": discarded_tail_bytes,
        "discarded_tail_sha256": discarded_tail_sha256,
        "removed_empty_segment": analysis.empty_segment.as_ref().and_then(|path| path.file_name()).and_then(|name| name.to_str()),
        "recovery_dir": recovery_dir.map(|path| absolute(&path).display().to_string()),
    });
    print_document(&value, args.json)
}

fn recovery_failure(
    manifest: &RunManifest,
    apply: bool,
    json_output: bool,
    code: &str,
    message: &str,
) -> Result<()> {
    let value = json!({
        "contract": "heimdall.logs.recover/v1",
        "run_id": manifest.run_id,
        "applicable": false,
        "applied": false,
        "requested_apply": apply,
        "code": code,
        "message": message,
        "state_before": manifest.state,
    });
    print_document(&value, json_output)?;
    anyhow::bail!("{code}: {message}")
}

fn analyze_recovery(run_dir: &Path, manifest: &RunManifest) -> Result<RecoveryAnalysis> {
    let event_schema: Value =
        serde_json::from_str(EVENT_SCHEMA).context("decode bundled event schema")?;
    let event_validator =
        jsonschema::validator_for(&event_schema).context("compile bundled event schema")?;
    let paths = segment_paths(run_dir)?;
    anyhow::ensure!(!paths.is_empty(), "run has no event segments");
    let mut segments = Vec::new();
    let mut expected_seq = 1u64;
    let mut events = 0u64;
    let mut observed_blobs = BTreeMap::<String, (String, u64)>::new();
    let mut tail = None;
    let mut empty_segment = None;

    for (index, path) in paths.iter().enumerate() {
        let expected_name = format!("events-{:06}.jsonl", index + 1);
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .context("event segment filename is not UTF-8")?;
        anyhow::ensure!(name == expected_name, "unexpected event segment `{name}`");
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let mut offset = 0usize;
        let mut first_seq = None;
        let mut last_seq = None;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') else {
                anyhow::ensure!(
                    index + 1 == paths.len(),
                    "non-final segment `{name}` has an incomplete tail"
                );
                tail = Some(RecoveryTail {
                    segment: path.clone(),
                    valid_bytes: offset as u64,
                    bytes: remaining.to_vec(),
                });
                break;
            };
            let end = offset + newline + 1;
            let event_value: Value = serde_json::from_slice(&bytes[offset..end])
                .with_context(|| format!("complete record in `{name}` is not valid JSON"))?;
            if let Some(error) = event_validator.iter_errors(&event_value).next() {
                anyhow::bail!(
                    "complete record in `{name}` fails schema {}: {error}",
                    error.instance_path()
                );
            }
            let event: Event = serde_json::from_value(event_value)
                .with_context(|| format!("decode complete record in `{name}`"))?;
            anyhow::ensure!(event.schema == EVENT_CONTRACT, "unsupported event contract");
            anyhow::ensure!(event.run_id == manifest.run_id, "event run_id mismatch");
            anyhow::ensure!(
                event.seq == expected_seq,
                "expected sequence {expected_seq}, found {}",
                event.seq
            );
            if let Some(blob) = event.data.get("blob").filter(|blob| !blob.is_null()) {
                let digest = blob
                    .get("digest")
                    .and_then(Value::as_str)
                    .context("blob digest is absent")?;
                let relative = blob
                    .get("path")
                    .and_then(Value::as_str)
                    .context("blob path is absent")?;
                let blob_bytes = blob
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .context("blob byte count is absent")?;
                verify_blob(run_dir, relative, digest, blob_bytes)
                    .with_context(|| format!("sequence {} blob", event.seq))?;
                observed_blobs.insert(digest.into(), (relative.into(), blob_bytes));
            }
            first_seq.get_or_insert(event.seq);
            last_seq = Some(event.seq);
            expected_seq += 1;
            events += 1;
            offset = end;
        }
        if let (Some(first_seq), Some(last_seq)) = (first_seq, last_seq) {
            let committed = tail
                .as_ref()
                .filter(|item| item.segment == *path)
                .map_or(bytes.len(), |item| item.valid_bytes as usize);
            segments.push(SegmentManifest {
                file: name.into(),
                first_seq,
                last_seq,
                bytes: committed as u64,
                sha256: hex::encode(Sha256::digest(&bytes[..committed])),
                final_: true,
            });
        } else {
            anyhow::ensure!(
                index + 1 == paths.len(),
                "non-final event segment `{name}` is empty"
            );
            if tail.is_none() {
                empty_segment = Some(path.clone());
            }
        }
    }

    anyhow::ensure!(
        manifest.segments.len() <= segments.len(),
        "manifest references segments outside the recoverable prefix"
    );
    for (expected, observed) in manifest.segments.iter().zip(&segments) {
        anyhow::ensure!(
            serde_json::to_value(expected)? == serde_json::to_value(observed)?,
            "finalized segment `{}` no longer matches its manifest",
            expected.file
        );
    }
    let blob_bytes = observed_blobs
        .values()
        .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes));
    Ok(RecoveryAnalysis {
        segments,
        blobs: BlobSummary {
            count: observed_blobs.len() as u64,
            bytes: blob_bytes,
        },
        events,
        last_valid_seq: expected_seq - 1,
        tail,
        empty_segment,
    })
}

fn apply_recovery(
    run_dir: &Path,
    manifest: &mut RunManifest,
    analysis: &RecoveryAnalysis,
    discarded_tail_sha256: Option<&str>,
) -> Result<PathBuf> {
    let recovery_id = Uuid::now_v7();
    let recovery_root = run_dir.join("recovery");
    fs::create_dir_all(&recovery_root)
        .with_context(|| format!("create {}", recovery_root.display()))?;
    fs::set_permissions(&recovery_root, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure {}", recovery_root.display()))?;
    let recovery_dir = recovery_root.join(recovery_id.to_string());
    fs::create_dir_all(&recovery_dir)
        .with_context(|| format!("create {}", recovery_dir.display()))?;
    fs::set_permissions(&recovery_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure {}", recovery_dir.display()))?;
    let manifest_before =
        fs::read(run_dir.join("run.json")).context("read original run manifest")?;
    let manifest_before_sha256 = hex::encode(Sha256::digest(&manifest_before));
    write_private_file(&recovery_dir.join("manifest-before.json"), &manifest_before)?;
    if let Some(tail) = &analysis.tail {
        write_private_file(&recovery_dir.join("discarded-tail.bin"), &tail.bytes)?;
    }
    let report_path = recovery_dir.join("recovery.json");
    let run_id = manifest.run_id;
    let original_state = manifest.state.clone();
    let report = |status: &str| {
        json!({
            "contract": "heimdall.logs.recovery-record/v1",
            "recovery_id": recovery_id,
            "run_id": run_id,
            "status": status,
            "original_state": original_state,
            "manifest_before_sha256": manifest_before_sha256,
            "events": analysis.events,
            "segments": analysis.segments.len(),
            "last_valid_seq": analysis.last_valid_seq,
            "discarded_tail_bytes": analysis.tail.as_ref().map_or(0, |tail| tail.bytes.len()),
            "discarded_tail_sha256": discarded_tail_sha256,
            "removed_empty_segment": analysis.empty_segment.as_ref().and_then(|path| path.file_name()).and_then(|name| name.to_str()),
        })
    };
    write_private_file(&report_path, &serde_json::to_vec(&report("prepared"))?)?;

    if let Some(tail) = &analysis.tail {
        if tail.valid_bytes == 0 {
            fs::remove_file(&tail.segment)
                .with_context(|| format!("remove {}", tail.segment.display()))?;
        } else {
            let file = OpenOptions::new()
                .write(true)
                .open(&tail.segment)
                .with_context(|| format!("open {}", tail.segment.display()))?;
            file.set_len(tail.valid_bytes)
                .with_context(|| format!("truncate {}", tail.segment.display()))?;
            file.sync_all()
                .with_context(|| format!("sync {}", tail.segment.display()))?;
        }
    } else if let Some(empty) = &analysis.empty_segment {
        fs::remove_file(empty).with_context(|| format!("remove {}", empty.display()))?;
    }

    manifest.state = "failed".into();
    manifest.closed_at = Some(
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format recovery timestamp")?,
    );
    manifest.segments = analysis.segments.clone();
    manifest.blobs = analysis.blobs.clone();
    manifest.result = Some(RunResult {
        exit_code: None,
        signal: None,
        error_code: Some("recovered_incomplete_run".into()),
        complete: false,
    });
    persist_manifest(run_dir, manifest)?;
    write_private_file(&report_path, &serde_json::to_vec(&report("applied"))?)?;
    Ok(recovery_dir)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

fn verify_run(run_dir: &Path, manifest: &RunManifest) -> Result<Value> {
    let mut errors = Vec::new();
    let event_schema: Value =
        serde_json::from_str(EVENT_SCHEMA).context("decode bundled event schema")?;
    let event_validator =
        jsonschema::validator_for(&event_schema).context("compile bundled event schema")?;
    let run_schema: Value =
        serde_json::from_str(RUN_SCHEMA).context("decode bundled run schema")?;
    let run_validator =
        jsonschema::validator_for(&run_schema).context("compile bundled run schema")?;
    let manifest_value = serde_json::to_value(manifest).context("encode run manifest")?;
    for error in run_validator.iter_errors(&manifest_value) {
        errors.push(format!(
            "run.json schema {}: {error}",
            error.instance_path()
        ));
    }
    let mut expected_seq = 1u64;
    let mut event_count = 0u64;
    let segment_paths = segment_paths(run_dir)?;
    let mut observed_ranges = BTreeMap::new();
    let mut observed_blobs = BTreeMap::<String, (String, u64)>::new();
    for segment in &segment_paths {
        let segment_name = segment
            .file_name()
            .and_then(|value| value.to_str())
            .context("event segment filename is not UTF-8")?
            .to_owned();
        let mut first_seq = None;
        let mut last_seq = None;
        let file = match File::open(segment) {
            Ok(file) => file,
            Err(error) => {
                errors.push(format!("open {}: {error}", segment.display()));
                continue;
            }
        };
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    errors.push(format!(
                        "read {} line {}: {error}",
                        segment.display(),
                        line_number + 1
                    ));
                    break;
                }
            };
            let event_value: Value = match serde_json::from_str(&line) {
                Ok(event) => event,
                Err(error) => {
                    errors.push(format!(
                        "decode {} line {}: {error}",
                        segment.display(),
                        line_number + 1
                    ));
                    break;
                }
            };
            for error in event_validator.iter_errors(&event_value) {
                errors.push(format!(
                    "{} line {} schema {}: {error}",
                    segment.display(),
                    line_number + 1,
                    error.instance_path()
                ));
            }
            let event: Event = match serde_json::from_value(event_value) {
                Ok(event) => event,
                Err(error) => {
                    errors.push(format!(
                        "decode {} line {}: {error}",
                        segment.display(),
                        line_number + 1
                    ));
                    break;
                }
            };
            if event.schema != EVENT_CONTRACT {
                errors.push(format!("sequence {} has unsupported schema", event.seq));
            }
            if event.run_id != manifest.run_id {
                errors.push(format!("sequence {} has mismatched run_id", event.seq));
            }
            if event.seq != expected_seq {
                errors.push(format!(
                    "expected sequence {expected_seq}, found {}",
                    event.seq
                ));
                expected_seq = event.seq;
            }
            if let Some(blob) = event.data.get("blob").filter(|blob| !blob.is_null()) {
                let digest = blob
                    .get("digest")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let relative = blob.get("path").and_then(Value::as_str).unwrap_or_default();
                let bytes = blob
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX);
                if let Err(error) = verify_blob(run_dir, relative, digest, bytes) {
                    errors.push(format!("sequence {} blob: {error}", event.seq));
                } else {
                    observed_blobs.insert(digest.into(), (relative.into(), bytes));
                }
            }
            first_seq.get_or_insert(event.seq);
            last_seq = Some(event.seq);
            expected_seq += 1;
            event_count += 1;
        }
        observed_ranges.insert(segment_name, (first_seq, last_seq));
    }
    for segment in &manifest.segments {
        let path = safe_segment_path(run_dir, &segment.file)?;
        match observed_ranges.get(&segment.file) {
            Some((Some(first_seq), Some(last_seq))) => {
                if *first_seq != segment.first_seq || *last_seq != segment.last_seq {
                    errors.push(format!(
                        "{} sequence range mismatch: expected {}-{}, found {first_seq}-{last_seq}",
                        segment.file, segment.first_seq, segment.last_seq
                    ));
                }
            }
            Some((None, None)) => errors.push(format!("{} is empty", segment.file)),
            Some(_) => errors.push(format!("{} has an incomplete sequence range", segment.file)),
            None => errors.push(format!("{} is missing", segment.file)),
        }
        match fs::metadata(&path) {
            Ok(metadata) if metadata.len() == segment.bytes => {}
            Ok(metadata) => errors.push(format!(
                "{} byte count mismatch: expected {}, found {}",
                segment.file,
                segment.bytes,
                metadata.len()
            )),
            Err(error) => errors.push(format!("inspect {}: {error}", segment.file)),
        }
        match sha256_file(&path) {
            Ok(digest) if digest == segment.sha256 => {}
            Ok(digest) => errors.push(format!(
                "{} digest mismatch: expected {}, found {digest}",
                segment.file, segment.sha256
            )),
            Err(error) => errors.push(format!("verify {}: {error}", segment.file)),
        }
    }
    if matches!(manifest.state.as_str(), "closed" | "failed")
        && segment_paths.len() != manifest.segments.len()
    {
        errors.push(format!(
            "final manifest lists {} segments but {} files exist",
            manifest.segments.len(),
            segment_paths.len()
        ));
    }
    if manifest.state == "closed"
        && manifest
            .segments
            .last()
            .is_none_or(|segment| segment.last_seq + 1 != expected_seq)
    {
        errors.push("closed manifest does not finalize the last event".into());
    }
    let observed_blob_bytes = observed_blobs
        .values()
        .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes));
    if manifest.blobs.count != observed_blobs.len() as u64
        || manifest.blobs.bytes != observed_blob_bytes
    {
        errors.push(format!(
            "blob summary mismatch: manifest count/bytes {}/{}, observed {}/{}",
            manifest.blobs.count,
            manifest.blobs.bytes,
            observed_blobs.len(),
            observed_blob_bytes
        ));
    }
    Ok(json!({
        "contract": "heimdall.logs.verify/v1",
        "run_id": manifest.run_id,
        "valid": errors.is_empty(),
        "state": manifest.state,
        "events": event_count,
        "segments": manifest.segments.len(),
        "blobs": observed_blobs.len(),
        "errors": errors
    }))
}

fn verify_blob(run_dir: &Path, relative: &str, digest: &str, bytes: u64) -> Result<()> {
    let expected = format!(
        "blobs/sha256/{}/{}/{}",
        digest.get(..2).unwrap_or_default(),
        digest.get(2..4).unwrap_or_default(),
        digest
    );
    anyhow::ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && relative == expected,
        "unsafe or inconsistent blob reference `{relative}`"
    );
    let path = run_dir.join(relative);
    let metadata =
        fs::symlink_metadata(&path).with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(metadata.file_type().is_file(), "blob is not a regular file");
    anyhow::ensure!(metadata.len() == bytes, "blob byte count mismatch");
    anyhow::ensure!(sha256_file(&path)? == digest, "blob digest mismatch");
    Ok(())
}

fn prune(args: PruneArgs) -> Result<()> {
    let cutoff = args
        .older_than
        .as_deref()
        .map(parse_age)
        .transpose()?
        .map(|age| OffsetDateTime::now_utc() - age);
    let mut runs = discover_runs()?;
    runs.sort_by(|left, right| right.1.started_at.cmp(&left.1.started_at));
    let run_sizes = runs
        .iter()
        .map(|(run_dir, _)| directory_bytes(run_dir))
        .collect::<Result<Vec<_>>>()?;
    let total_before = run_sizes
        .iter()
        .fold(0u64, |total, bytes| total.saturating_add(*bytes));
    let mut total_after = total_before;
    let mut candidates = Vec::new();
    for index in (0..runs.len()).rev() {
        let (run_dir, manifest) = &runs[index];
        if index < args.keep_last || !matches!(manifest.state.as_str(), "closed" | "failed") {
            continue;
        }
        let age_match = if let Some(cutoff) = cutoff {
            let closed = manifest
                .closed_at
                .as_deref()
                .context("closed run is missing closed_at")?;
            let closed = OffsetDateTime::parse(closed, &Rfc3339)
                .with_context(|| format!("parse closed_at for {}", manifest.run_id))?;
            closed < cutoff
        } else {
            args.max_total_bytes.is_none()
        };
        let size_match = args
            .max_total_bytes
            .is_some_and(|maximum| total_after > maximum);
        if !age_match && !size_match {
            continue;
        }
        let bytes = run_sizes[index];
        total_after = total_after.saturating_sub(bytes);
        let reason = match (age_match, size_match) {
            (true, true) => "age_and_max_total_bytes",
            (true, false) => "age",
            (false, true) => "max_total_bytes",
            (false, false) => unreachable!(),
        };
        candidates.push((run_dir.clone(), manifest.run_id, bytes, reason));
    }
    if args.apply {
        for (run_dir, _, _, _) in &candidates {
            fs::remove_dir_all(run_dir)
                .with_context(|| format!("remove run directory {}", run_dir.display()))?;
        }
    }
    let value = json!({
        "contract": "heimdall.logs.prune/v1",
        "applied": args.apply,
        "total_bytes_before": total_before,
        "total_bytes_after": total_after,
        "limit_satisfied": args.max_total_bytes.is_none_or(|maximum| total_after <= maximum),
        "candidates": candidates.iter().map(|(path, run_id, bytes, reason)| json!({
            "run_id": run_id,
            "run_dir": absolute(path).display().to_string(),
            "bytes": bytes,
            "reason": reason
        })).collect::<Vec<_>>()
    });
    print_document(&value, args.json)
}

fn discover_runs() -> Result<Vec<(PathBuf, RunManifest)>> {
    let root = runs_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut manifests = Vec::new();
    collect_manifests(&root, &mut manifests)?;
    let mut runs = manifests
        .into_iter()
        .map(|path| {
            let manifest = read_manifest(&path)?;
            let run_dir = path
                .parent()
                .context("run manifest has no parent")?
                .to_path_buf();
            Ok((run_dir, manifest))
        })
        .collect::<Result<Vec<_>>>()?;
    runs.sort_by(|left, right| right.1.started_at.cmp(&left.1.started_at));
    Ok(runs)
}

fn collect_manifests(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| format!("read {}", directory.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", directory.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_manifests(&entry.path(), output)?;
        } else if file_type.is_file() && entry.file_name() == "run.json" {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn find_run(run_id: Uuid) -> Result<(PathBuf, RunManifest)> {
    discover_runs()?
        .into_iter()
        .find(|(_, manifest)| manifest.run_id == run_id)
        .with_context(|| format!("run_not_found: {run_id}"))
}

fn segment_paths(run_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(run_dir).with_context(|| format!("read {}", run_dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", run_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        let matches = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("events-") && name.ends_with(".jsonl"));
        if file_type.is_file() && matches {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn safe_segment_path(run_dir: &Path, file: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        file.starts_with("events-")
            && file.ends_with(".jsonl")
            && !file.contains('/')
            && !file.contains(".."),
        "unsafe segment path `{file}`"
    );
    Ok(run_dir.join(file))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = std::io::Read::read(&mut file, &mut buffer)
            .with_context(|| format!("hash {}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn directory_bytes(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_dir() {
            total = total.saturating_add(directory_bytes(&entry.path())?);
        } else if file_type.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn parse_age(value: &str) -> Result<time::Duration> {
    let (digits, unit) = value.split_at(value.len().saturating_sub(1));
    let amount = digits
        .parse::<i64>()
        .with_context(|| format!("invalid retention duration `{value}`"))?;
    anyhow::ensure!(amount > 0, "retention duration must be positive");
    match unit {
        "d" => Ok(time::Duration::days(amount)),
        "h" => Ok(time::Duration::hours(amount)),
        "m" => Ok(time::Duration::minutes(amount)),
        _ => anyhow::bail!("retention duration must end in d, h, or m"),
    }
}

fn absolute(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn print_document(value: &impl Serialize, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::RunLog;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heimdall-logs-{name}-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ))
    }

    #[test]
    fn parses_retention_durations() {
        assert_eq!(parse_age("30d").unwrap(), time::Duration::days(30));
        assert_eq!(parse_age("12h").unwrap(), time::Duration::hours(12));
        assert!(parse_age("0d").is_err());
        assert!(parse_age("30").is_err());
    }

    #[test]
    fn segment_paths_reject_traversal() {
        assert!(safe_segment_path(Path::new("/tmp/run"), "../events-1.jsonl").is_err());
        assert!(safe_segment_path(Path::new("/tmp/run"), "events-000001.jsonl").is_ok());
    }

    #[test]
    fn payload_filters_use_explicit_event_evidence() {
        let flow_id = Uuid::now_v7();
        let event = Event {
            schema: EVENT_CONTRACT.into(),
            run_id: Uuid::now_v7(),
            seq: 3,
            ts: "2026-08-19T00:00:00.000000Z".into(),
            monotonic_ns: 1,
            kind: "flow.data".into(),
            flow_id: Some(flow_id),
            pid: None,
            data: json!({
                "direction": "client_to_remote",
                "boundary": "tls_plaintext.relay",
                "error_code": "capture_truncated",
                "blob": {"digest": "abc"}
            }),
        };
        let mut args = QueryArgs {
            run: event.run_id,
            kind: vec!["flow.data".into()],
            flow: Some(flow_id),
            since_seq: Some(3),
            until_seq: Some(3),
            direction: vec!["client_to_remote".into()],
            boundary: vec!["tls_plaintext.relay".into()],
            error_code: vec!["capture_truncated".into()],
            has_blob: Some(true),
            jsonl: true,
        };
        assert!(matches_query(&event, &args));

        args.boundary = vec!["transport".into()];
        assert!(!matches_query(&event, &args));
        args.boundary.clear();
        args.has_blob = Some(false);
        assert!(!matches_query(&event, &args));
    }

    #[test]
    fn summary_counters_are_low_cardinality_and_loss_aware() {
        let run_id = Uuid::now_v7();
        let flow_id = Uuid::now_v7();
        let event = |seq, kind: &str, flow_id, data| Event {
            schema: EVENT_CONTRACT.into(),
            run_id,
            seq,
            ts: "2026-08-20T00:00:00.000000Z".into(),
            monotonic_ns: seq * 100,
            kind: kind.into(),
            flow_id,
            pid: None,
            data,
        };
        let mut counters = RunCounters::default();
        counters.observe(&event(
            1,
            "flow.open",
            Some(flow_id),
            json!({"network": "tcp"}),
        ));
        counters.observe(&event(
            3,
            "flow.data",
            Some(flow_id),
            json!({
                "boundary": "tls_plaintext.relay",
                "original_bytes": 12,
                "stored_bytes": 8,
                "truncated": true
            }),
        ));
        counters.observe(&event(
            4,
            "flow.close",
            Some(flow_id),
            json!({
                "status": "error",
                "error_code": "relay_failed",
                "duration_us": 20,
                "client_to_remote_bytes": 12,
                "remote_to_client_bytes": 4
            }),
        ));
        assert_eq!(counters.records, 3);
        assert_eq!(counters.missing_records, 1);
        assert_eq!(counters.capture_records, 1);
        assert_eq!(counters.truncated_capture_records, 1);
        assert_eq!(counters.flow_failures_by_code["relay_failed"], 1);
        assert!(counters.open_flows.contains(&flow_id));
        assert!(counters.closed_flows.contains(&flow_id));
    }

    #[test]
    fn verification_detects_segment_tampering() {
        let root = test_root("verify");
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        log.ready("heimdall-run", None, &["transport"]).unwrap();
        log.emit(
            "run.exec",
            Some(42),
            json!({"child_pid": 42, "executable": "true", "argv_count": 1}),
        )
        .unwrap();
        log.finish(0, true).unwrap();
        let run_dir = log.run_dir().unwrap();
        let manifest = read_manifest(&run_dir.join("run.json")).unwrap();

        let valid = verify_run(&run_dir, &manifest).unwrap();
        assert_eq!(valid["valid"], true);
        assert_eq!(valid["events"], 4);

        let segment = safe_segment_path(&run_dir, &manifest.segments[0].file).unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(segment).unwrap();
        file.write_all(b" ").unwrap();
        file.sync_all().unwrap();

        let invalid = verify_run(&run_dir, &manifest).unwrap();
        assert_eq!(invalid["valid"], false);
        assert!(invalid["errors"].as_array().unwrap().iter().any(|error| {
            error
                .as_str()
                .is_some_and(|message| message.contains("digest mismatch"))
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verification_detects_schema_invalid_event_data() {
        let root = test_root("verify-schema");
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        log.ready("heimdall-run", None, &["transport"]).unwrap();
        log.emit(
            "run.exec",
            Some(42),
            json!({"child_pid": 42, "executable": "true", "argv_count": 1}),
        )
        .unwrap();
        log.finish(0, true).unwrap();
        let run_dir = log.run_dir().unwrap();
        let mut manifest = read_manifest(&run_dir.join("run.json")).unwrap();
        let segment = safe_segment_path(&run_dir, &manifest.segments[0].file).unwrap();
        let mut events = BufReader::new(File::open(&segment).unwrap())
            .lines()
            .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
            .collect::<Vec<_>>();
        let event = events
            .iter_mut()
            .find(|event| event["kind"] == "run.exec")
            .unwrap();
        event["data"]["argv_count"] = json!("one");
        let replacement = events
            .into_iter()
            .map(|event| serde_json::to_string(&event).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&segment, replacement).unwrap();
        manifest.segments[0].bytes = fs::metadata(&segment).unwrap().len();
        manifest.segments[0].sha256 = sha256_file(&segment).unwrap();

        let invalid = verify_run(&run_dir, &manifest).unwrap();
        assert_eq!(invalid["valid"], false);
        assert!(invalid["errors"].as_array().unwrap().iter().any(|error| {
            error
                .as_str()
                .is_some_and(|message| message.contains(" schema "))
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_preserves_tail_and_finalizes_only_committed_records() {
        let root = test_root("recover-tail");
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        log.ready("heimdall-run", None, &["transport"]).unwrap();
        log.emit(
            "run.exec",
            Some(42),
            json!({"child_pid": 42, "executable": "true", "argv_count": 1}),
        )
        .unwrap();
        let run_dir = log.run_dir().unwrap();
        drop(log);
        let segment = run_dir.join("events-000001.jsonl");
        OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(b"{\"schema\":\"heimdall.event/v1\"")
            .unwrap();

        let mut manifest = read_manifest(&run_dir.join("run.json")).unwrap();
        let analysis = analyze_recovery(&run_dir, &manifest).unwrap();
        assert_eq!(analysis.events, 3);
        assert_eq!(analysis.last_valid_seq, 3);
        assert_eq!(analysis.segments.len(), 1);
        assert!(
            analysis
                .tail
                .as_ref()
                .is_some_and(|tail| !tail.bytes.is_empty())
        );
        let tail_digest = analysis
            .tail
            .as_ref()
            .map(|tail| hex::encode(Sha256::digest(&tail.bytes)));
        let recovery_dir =
            apply_recovery(&run_dir, &mut manifest, &analysis, tail_digest.as_deref()).unwrap();

        let recovered = read_manifest(&run_dir.join("run.json")).unwrap();
        assert_eq!(recovered.state, "failed");
        assert_eq!(
            recovered.result.as_ref().unwrap().error_code.as_deref(),
            Some("recovered_incomplete_run")
        );
        assert!(!recovered.result.as_ref().unwrap().complete);
        assert_eq!(verify_run(&run_dir, &recovered).unwrap()["valid"], true);
        assert!(recovery_dir.join("manifest-before.json").is_file());
        assert!(recovery_dir.join("discarded-tail.bin").is_file());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(recovery_dir.join("recovery.json")).unwrap())
                .unwrap()["status"],
            "applied"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_rejects_a_complete_invalid_record() {
        let root = test_root("recover-invalid");
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        let run_dir = log.run_dir().unwrap();
        drop(log);
        OpenOptions::new()
            .append(true)
            .open(run_dir.join("events-000001.jsonl"))
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        let manifest = read_manifest(&run_dir.join("run.json")).unwrap();
        let error = analyze_recovery(&run_dir, &manifest).unwrap_err();
        assert!(error.to_string().contains("fails schema"));
        fs::remove_dir_all(root).unwrap();
    }
}
