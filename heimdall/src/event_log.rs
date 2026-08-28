//! Per-run agent-readable event storage.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::heimdall_config::{CaptureConfig, CaptureMode};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, macros::format_description};
use uuid::Uuid;

pub const EVENT_CONTRACT: &str = "heimdall.event/v1";
pub const RUN_CONTRACT: &str = "heimdall.run/v1";
pub const SUMMARY_CONTRACT: &str = "heimdall.logs.summary/v1";
pub const CONTROL_CONTRACT: &str = "heimdall.logs.control/v1";
pub const DEFAULT_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_SEGMENT_AGE: Duration = Duration::from_secs(15 * 60);

pub const EVENT_SCHEMA: &str = include_str!("../schemas/heimdall.event.v1.schema.json");
pub const RUN_SCHEMA: &str = include_str!("../schemas/heimdall.run.v1.schema.json");
pub const SUMMARY_SCHEMA: &str = include_str!("../schemas/heimdall.logs.summary.v1.schema.json");

const TIMESTAMP_FORMAT: &[time::format_description::BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");
const DATE_PATH_FORMAT: &[time::format_description::BorrowedFormatItem<'_>] =
    format_description!("[year]/[month]/[day]");

pub fn event_socket_filename(run_id: Uuid) -> String {
    format!("{}.e", run_id.simple())
}

fn control_socket_filename(run_id: Uuid) -> String {
    format!("{}.c", run_id.simple())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandManifest {
    pub executable: String,
    pub argv_count: usize,
    pub argv: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentManifest {
    pub file: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub bytes: u64,
    pub sha256: String,
    #[serde(rename = "final")]
    pub final_: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobSummary {
    pub count: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub error_code: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub schema: String,
    pub run_id: Uuid,
    pub state: String,
    pub started_at: String,
    pub closed_at: Option<String>,
    pub command: CommandManifest,
    pub policy: String,
    pub backend: String,
    pub capture: Value,
    pub segments: Vec<SegmentManifest>,
    pub blobs: BlobSummary,
    pub result: Option<RunResult>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema: String,
    pub run_id: Uuid,
    pub seq: u64,
    pub ts: String,
    pub monotonic_ns: u64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub data: Value,
}

#[derive(Clone)]
pub struct RunLog(Arc<Mutex<RunWriter>>);

struct RunWriter {
    run_dir: PathBuf,
    manifest: RunManifest,
    segment: SegmentWriter,
    next_seq: u64,
    started: Instant,
    segment_started: Instant,
    segment_max_bytes: u64,
    segment_max_age: Duration,
}

struct SegmentWriter {
    index: u32,
    file: File,
    path: PathBuf,
    first_seq: u64,
    last_seq: u64,
    bytes: u64,
    digest: Sha256,
}

impl RunLog {
    pub fn create_with_capture(
        command: &[String],
        policy: &str,
        backend: &str,
        capture: &CaptureConfig,
    ) -> Result<Self> {
        Self::create_at_profile(&runs_root()?, command, policy, backend, capture)
    }

    #[cfg(test)]
    pub(crate) fn create_at(
        runs: &Path,
        command: &[String],
        policy: &str,
        backend: &str,
    ) -> Result<Self> {
        let capture = CaptureConfig {
            max_bytes_per_flow: 0,
            ..CaptureConfig::default()
        };
        Self::create_at_profile(runs, command, policy, backend, &capture)
    }

    fn create_at_profile(
        runs: &Path,
        command: &[String],
        policy: &str,
        backend: &str,
        capture: &CaptureConfig,
    ) -> Result<Self> {
        anyhow::ensure!(!command.is_empty(), "event log command must not be empty");
        let capture_profile = match capture.mode {
            CaptureMode::Off => "metadata",
            CaptureMode::On => "payload",
        };
        let allowed_boundaries = capture
            .boundaries
            .iter()
            .map(|boundary| boundary.name())
            .collect::<Vec<_>>();
        let allowed_directions = capture
            .directions
            .iter()
            .map(|direction| direction.name())
            .collect::<Vec<_>>();
        let redaction = json!({
            "source": "environment",
            "value_count": capture.redact_env.len(),
            "replacement": "same_length_asterisk"
        });
        let now = OffsetDateTime::now_utc();
        let run_id = Uuid::now_v7();
        let date = now
            .format(DATE_PATH_FORMAT)
            .context("format event-log date path")?;
        create_private_dir(runs)?;
        let mut date_dir = runs.to_path_buf();
        for component in date.split('/') {
            date_dir.push(component);
            create_private_dir(&date_dir)?;
        }
        let run_dir = date_dir.join(run_id.to_string());
        create_private_dir(&run_dir)?;
        create_private_dir(&run_dir.join("blobs/sha256"))?;

        let manifest = RunManifest {
            schema: RUN_CONTRACT.into(),
            run_id,
            state: "starting".into(),
            started_at: format_timestamp(now)?,
            closed_at: None,
            command: CommandManifest {
                executable: command[0].clone(),
                argv_count: command.len(),
                argv: None,
            },
            policy: policy.into(),
            backend: backend.into(),
            capture: json!({
                "profile": capture_profile,
                "event_schema": EVENT_CONTRACT,
                "payload_storage": "content_addressed",
                "max_bytes_per_flow": capture.max_bytes_per_flow,
                "block_max_bytes": capture.block_max_bytes,
                "flush_interval_ms": capture.flush_interval_ms,
                "allowed_boundaries": allowed_boundaries.clone(),
                "allowed_directions": allowed_directions.clone(),
                "redaction": redaction.clone(),
                "segment_max_bytes": DEFAULT_SEGMENT_BYTES,
                "segment_max_age_ms": DEFAULT_SEGMENT_AGE.as_millis() as u64
            }),
            segments: Vec::new(),
            blobs: BlobSummary::default(),
            result: None,
        };
        let segment = SegmentWriter::create(&run_dir, 1, 1)?;
        let writer = Self(Arc::new(Mutex::new(RunWriter {
            run_dir,
            manifest,
            segment,
            next_seq: 1,
            started: Instant::now(),
            segment_started: Instant::now(),
            segment_max_bytes: DEFAULT_SEGMENT_BYTES,
            segment_max_age: DEFAULT_SEGMENT_AGE,
        })));
        writer.persist_manifest()?;
        writer.emit(
            "run.open",
            None,
            json!({
                "policy": policy,
                "backend": backend,
                "capture": {
                    "profile": capture_profile,
                    "payload_storage": "content_addressed",
                    "allowed_boundaries": allowed_boundaries,
                    "allowed_directions": allowed_directions,
                    "redaction": redaction,
                    "block_max_bytes": capture.block_max_bytes,
                    "flush_interval_ms": capture.flush_interval_ms
                },
                "schemas": {"event": EVENT_CONTRACT, "run": RUN_CONTRACT}
            }),
        )?;
        Ok(writer)
    }

    pub fn run_id(&self) -> Result<Uuid> {
        Ok(self.lock()?.manifest.run_id)
    }

    pub(crate) fn run_dir(&self) -> Result<PathBuf> {
        Ok(self.lock()?.run_dir.clone())
    }

    pub fn emit(&self, kind: &str, pid: Option<u32>, data: Value) -> Result<u64> {
        self.lock()?.emit(kind, None, pid, data)
    }

    fn emit_flow(&self, kind: &str, flow_id: Uuid, pid: Option<u32>, data: Value) -> Result<u64> {
        self.lock()?.emit(kind, Some(flow_id), pid, data)
    }

    fn emit_payload(
        &self,
        flow_id: Uuid,
        pid: Option<u32>,
        mut data: Value,
        payload: &[u8],
    ) -> Result<u64> {
        let mut writer = self.lock()?;
        let blob = writer.store_blob(payload)?;
        let object = data
            .as_object_mut()
            .context("flow.data payload metadata must be an object")?;
        anyhow::ensure!(
            !object.contains_key("blob"),
            "flow.data blob is writer-owned"
        );
        object.insert("blob".into(), blob);
        let seq = writer.emit("flow.data", Some(flow_id), pid, data)?;
        writer.persist_manifest()?;
        Ok(seq)
    }

    pub fn ready(&self, owner: &str, control: Option<&str>, boundaries: &[&str]) -> Result<()> {
        let mut writer = self.lock()?;
        writer.manifest.state = "running".into();
        writer.emit(
            "run.ready",
            None,
            None,
            json!({
                "listeners": {"owner": owner, "control": control},
                "boundaries": boundaries
            }),
        )?;
        writer.persist_manifest()
    }

    pub fn rotate(&self) -> Result<SegmentManifest> {
        self.lock()?.rotate()
    }

    pub fn finish(&self, exit_code: i32, descendants_cleaned: bool) -> Result<()> {
        let mut writer = self.lock()?;
        writer.manifest.state = "closing".into();
        writer.emit(
            "run.close",
            None,
            None,
            json!({
                "exit_code": exit_code,
                "signal": if exit_code > 128 { Some(exit_code - 128) } else { None },
                "descendants_cleaned": descendants_cleaned,
                "complete": descendants_cleaned
            }),
        )?;
        writer.finalize_segment()?;
        writer.manifest.state = "closed".into();
        writer.manifest.closed_at = Some(format_timestamp(OffsetDateTime::now_utc())?);
        writer.manifest.result = Some(RunResult {
            exit_code: Some(exit_code),
            signal: (exit_code > 128).then_some(exit_code - 128),
            error_code: None,
            complete: descendants_cleaned,
        });
        writer.persist_manifest()
    }

    pub fn fail(&self, code: &str, message: &str) -> Result<()> {
        let mut writer = self.lock()?;
        writer.emit(
            "run.error",
            None,
            None,
            json!({
                "code": code,
                "message": message,
                "phase": "run",
                "retryable": false,
                "context": {}
            }),
        )?;
        writer.finalize_segment()?;
        writer.manifest.state = "failed".into();
        writer.manifest.closed_at = Some(format_timestamp(OffsetDateTime::now_utc())?);
        writer.manifest.result = Some(RunResult {
            exit_code: None,
            signal: None,
            error_code: Some(code.into()),
            complete: false,
        });
        writer.persist_manifest()
    }

    fn persist_manifest(&self) -> Result<()> {
        self.lock()?.persist_manifest()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RunWriter>> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("event-log writer lock is poisoned"))
    }
}

impl RunWriter {
    fn store_blob(&mut self, payload: &[u8]) -> Result<Value> {
        let digest = hex::encode(Sha256::digest(payload));
        let relative = PathBuf::from("blobs/sha256")
            .join(&digest[..2])
            .join(&digest[2..4])
            .join(&digest);
        let path = self.run_dir.join(&relative);
        let parent = path.parent().context("blob path has no parent")?;
        create_private_dir(parent)?;
        let created = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_file()
                        && metadata.len() == payload.len() as u64
                        && hex::encode(Sha256::digest(
                            fs::read(&path).with_context(|| format!(
                                "read existing blob {}",
                                path.display()
                            ))?
                        )) == digest,
                    "existing blob {} does not match its digest",
                    path.display()
                );
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = parent.join(format!(".{digest}.{}.tmp", Uuid::now_v7()));
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&temporary)
                    .with_context(|| format!("create blob temporary {}", temporary.display()))?;
                let write_result = file
                    .write_all(payload)
                    .with_context(|| format!("write blob temporary {}", temporary.display()))
                    .and_then(|()| {
                        file.sync_all()
                            .with_context(|| format!("sync blob temporary {}", temporary.display()))
                    })
                    .and_then(|()| {
                        fs::hard_link(&temporary, &path)
                            .with_context(|| format!("publish blob {}", path.display()))
                    });
                drop(file);
                let _ = fs::remove_file(&temporary);
                write_result?;
                true
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect blob {}", path.display()));
            }
        };
        if created {
            self.manifest.blobs.count += 1;
            self.manifest.blobs.bytes = self
                .manifest
                .blobs
                .bytes
                .saturating_add(payload.len() as u64);
        }
        Ok(json!({
            "algorithm": "sha256",
            "digest": digest,
            "path": relative.to_string_lossy(),
            "bytes": payload.len(),
            "media_type": "application/octet-stream"
        }))
    }

    fn emit(
        &mut self,
        kind: &str,
        flow_id: Option<Uuid>,
        pid: Option<u32>,
        data: Value,
    ) -> Result<u64> {
        let event = Event {
            schema: EVENT_CONTRACT.into(),
            run_id: self.manifest.run_id,
            seq: self.next_seq,
            ts: format_timestamp(OffsetDateTime::now_utc())?,
            monotonic_ns: self
                .started
                .elapsed()
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX),
            kind: kind.into(),
            flow_id,
            pid,
            data,
        };
        let mut encoded = serde_json::to_vec(&event).context("encode event record")?;
        encoded.push(b'\n');
        if self.segment.bytes > 0
            && (self.segment.bytes.saturating_add(encoded.len() as u64) > self.segment_max_bytes
                || self.segment_started.elapsed() >= self.segment_max_age)
        {
            self.rotate()?;
        }
        self.segment
            .file
            .write_all(&encoded)
            .with_context(|| format!("write {}", self.segment.path.display()))?;
        self.segment.digest.update(&encoded);
        self.segment.bytes += encoded.len() as u64;
        self.segment.last_seq = event.seq;
        self.next_seq += 1;
        Ok(event.seq)
    }

    fn rotate(&mut self) -> Result<SegmentManifest> {
        anyhow::ensure!(self.segment.bytes > 0, "active event segment is empty");
        let finalized = self.finalize_segment()?;
        self.segment = SegmentWriter::create(&self.run_dir, self.segment.index + 1, self.next_seq)?;
        self.segment_started = Instant::now();
        self.persist_manifest()?;
        Ok(finalized)
    }

    fn finalize_segment(&mut self) -> Result<SegmentManifest> {
        anyhow::ensure!(self.segment.bytes > 0, "active event segment is empty");
        self.segment
            .file
            .sync_all()
            .with_context(|| format!("sync {}", self.segment.path.display()))?;
        let digest = hex::encode(self.segment.digest.clone().finalize());
        let segment = SegmentManifest {
            file: self
                .segment
                .path
                .file_name()
                .and_then(|value| value.to_str())
                .context("event segment filename is not UTF-8")?
                .into(),
            first_seq: self.segment.first_seq,
            last_seq: self.segment.last_seq,
            bytes: self.segment.bytes,
            sha256: digest,
            final_: true,
        };
        self.manifest.segments.push(segment.clone());
        Ok(segment)
    }

    fn persist_manifest(&self) -> Result<()> {
        persist_manifest(&self.run_dir, &self.manifest)
    }
}

impl SegmentWriter {
    fn create(run_dir: &Path, index: u32, first_seq: u64) -> Result<Self> {
        let path = run_dir.join(format!("events-{index:06}.jsonl"));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        Ok(Self {
            index,
            file,
            path,
            first_seq,
            last_seq: first_seq,
            bytes: 0,
            digest: Sha256::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    contract: String,
    action: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmitRequest {
    contract: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_base64: Option<String>,
}

#[derive(Debug, Serialize)]
struct ControlResponse {
    contract: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    segment: Option<SegmentManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

pub struct RotationServer {
    socket_path: PathBuf,
    event_socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    control_thread: Option<thread::JoinHandle<()>>,
    event_thread: Option<thread::JoinHandle<()>>,
}

impl RotationServer {
    pub fn start(log: RunLog) -> Result<Self> {
        let runtime = runtime_root()?;
        Self::start_at(log, &runtime)
    }

    pub(crate) fn start_at(log: RunLog, runtime: &Path) -> Result<Self> {
        create_private_dir(runtime)?;
        let run_id = log.run_id()?;
        let socket_path = runtime.join(control_socket_filename(run_id));
        let event_socket_path = runtime.join(event_socket_filename(run_id));
        for path in [&socket_path, &event_socket_path] {
            if path.exists() {
                fs::remove_file(path)
                    .with_context(|| format!("remove stale socket {}", path.display()))?;
            }
        }
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind {}", socket_path.display()))?;
        let event_listener = UnixListener::bind(&event_socket_path)
            .with_context(|| format!("bind {}", event_socket_path.display()))?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure {}", socket_path.display()))?;
        fs::set_permissions(&event_socket_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure {}", event_socket_path.display()))?;
        listener
            .set_nonblocking(true)
            .context("set log control socket nonblocking")?;
        event_listener
            .set_nonblocking(true)
            .context("set event socket nonblocking")?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let control_log = log.clone();
        let control_thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Err(error) = serve_control(&control_log, &mut stream) {
                            let _ = write_control_error(&mut stream, "control_failed", &error);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        let event_stop = Arc::clone(&stop);
        let event_thread = thread::spawn(move || {
            while !event_stop.load(Ordering::Acquire) {
                match event_listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Err(error) = serve_event(&log, &mut stream) {
                            let code = classify_event_error(&error);
                            let _ = write_control_error(&mut stream, code, &error);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            socket_path,
            event_socket_path,
            stop,
            control_thread: Some(control_thread),
            event_thread: Some(event_thread),
        })
    }

    pub fn event_socket_path(&self) -> &Path {
        &self.event_socket_path
    }
}

impl Drop for RotationServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket_path);
        let _ = UnixStream::connect(&self.event_socket_path);
        if let Some(thread) = self.control_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.event_thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_file(&self.event_socket_path);
    }
}

fn serve_control(log: &RunLog, stream: &mut UnixStream) -> Result<()> {
    let mut request = Vec::new();
    stream
        .read_to_end(&mut request)
        .context("read log control request")?;
    let request: ControlRequest =
        serde_json::from_slice(&request).context("decode log control request")?;
    anyhow::ensure!(
        request.contract == CONTROL_CONTRACT,
        "control contract mismatch"
    );
    anyhow::ensure!(request.action == "rotate", "unsupported control action");
    let response = ControlResponse {
        contract: CONTROL_CONTRACT,
        ok: true,
        segment: Some(log.rotate()?),
        code: None,
        message: None,
    };
    write_json_line(stream, &response)
}

fn serve_event(log: &RunLog, stream: &mut UnixStream) -> Result<()> {
    let mut request = Vec::new();
    stream
        .take(96 * 1024 * 1024 + 1)
        .read_to_end(&mut request)
        .context("read event request")?;
    anyhow::ensure!(
        request.len() <= 96 * 1024 * 1024,
        "event request is too large"
    );
    let request: EmitRequest = serde_json::from_slice(&request).context("decode event request")?;
    anyhow::ensure!(
        request.contract == "heimdall.logs.emit/v1",
        "event contract mismatch"
    );
    anyhow::ensure!(
        matches!(
            request.kind.as_str(),
            "dns.query"
                | "dns.answer"
                | "policy.decision"
                | "flow.open"
                | "flow.data"
                | "flow.close"
                | "tls.runtime"
                | "tls.client_hello"
                | "tls.handshake"
                | "tls.error"
                | "http.request"
                | "http.response"
        ),
        "unsupported external event kind"
    );
    let seq = match (request.kind.as_str(), request.payload_base64) {
        ("flow.data", Some(encoded)) => {
            let flow_id = request.flow_id.context("flow.data requires flow_id")?;
            let payload = STANDARD
                .decode(encoded)
                .context("decode flow.data payload")?;
            log.emit_payload(flow_id, request.pid, request.data, &payload)?
        }
        ("flow.data", None) => anyhow::bail!("flow.data requires payload_base64"),
        (_, Some(_)) => anyhow::bail!("payload_base64 is only valid for flow.data"),
        (_, None) => {
            if let Some(flow_id) = request.flow_id {
                log.emit_flow(&request.kind, flow_id, request.pid, request.data)?
            } else {
                anyhow::ensure!(
                    matches!(
                        request.kind.as_str(),
                        "dns.query" | "dns.answer" | "policy.decision"
                    ),
                    "{} requires flow_id",
                    request.kind
                );
                log.emit(&request.kind, request.pid, request.data)?
            }
        }
    };
    write_json_line(
        stream,
        &json!({"contract": "heimdall.logs.emit.result/v1", "ok": true, "seq": seq}),
    )
}

#[derive(Clone)]
pub struct EventClient {
    socket_path: Arc<PathBuf>,
    flows: Arc<FlowTracker>,
}

#[derive(Default)]
struct FlowTracker {
    active: Mutex<usize>,
    drained: Condvar,
}

pub struct FlowEventClient {
    client: EventClient,
}

#[derive(Clone, Copy)]
pub struct PayloadMetadata {
    pub original_bytes: u64,
    pub truncated: bool,
    pub index: u64,
    pub max_bytes: u64,
    pub flush_interval_ms: u64,
    pub flush_reason: &'static str,
}

impl EventClient {
    pub fn connect(socket_path: PathBuf) -> Result<Self> {
        anyhow::ensure!(
            socket_path.is_absolute(),
            "event socket path must be absolute"
        );
        let metadata = fs::symlink_metadata(&socket_path)
            .with_context(|| format!("inspect event socket {}", socket_path.display()))?;
        anyhow::ensure!(
            std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()),
            "event socket path is not a Unix socket"
        );
        Ok(Self {
            socket_path: Arc::new(socket_path),
            flows: Arc::new(FlowTracker::default()),
        })
    }

    pub fn start_flow(&self) -> FlowEventClient {
        *self.flows.active.lock().expect("flow tracker poisoned") += 1;
        FlowEventClient {
            client: self.clone(),
        }
    }

    pub fn wait_for_flows(&self, timeout: Duration) -> bool {
        let active = self.flows.active.lock().expect("flow tracker poisoned");
        let (active, _) = self
            .flows
            .drained
            .wait_timeout_while(active, timeout, |active| *active != 0)
            .expect("flow tracker poisoned");
        *active == 0
    }

    pub fn emit(&self, kind: &str, flow_id: Uuid, data: Value) -> Result<()> {
        self.emit_with_pid(kind, flow_id, None, data)
    }

    pub fn emit_with_pid(
        &self,
        kind: &str,
        flow_id: Uuid,
        pid: Option<u32>,
        data: Value,
    ) -> Result<()> {
        let mut stream = UnixStream::connect(self.socket_path.as_ref())
            .with_context(|| format!("connect event socket {}", self.socket_path.display()))?;
        configure_client_timeouts(&stream)?;
        write_json_line(
            &mut stream,
            &EmitRequest {
                contract: "heimdall.logs.emit/v1".into(),
                kind: kind.into(),
                flow_id: Some(flow_id),
                pid,
                data,
                payload_base64: None,
            },
        )?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("finish event request")?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("read event response")?;
        ensure_event_response(&response, "record event").map(|_| ())
    }
}

impl EventClient {
    pub fn emit_run(&self, kind: &str, data: Value) -> Result<()> {
        let mut stream = UnixStream::connect(self.socket_path.as_ref())
            .with_context(|| format!("connect event socket {}", self.socket_path.display()))?;
        configure_client_timeouts(&stream)?;
        write_json_line(
            &mut stream,
            &EmitRequest {
                contract: "heimdall.logs.emit/v1".into(),
                kind: kind.into(),
                flow_id: None,
                pid: None,
                data,
                payload_base64: None,
            },
        )?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("finish run event request")?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("read run event response")?;
        ensure_event_response(&response, "record run event").map(|_| ())
    }

    pub fn emit_payload(
        &self,
        flow_id: Uuid,
        direction: &str,
        boundary: &str,
        payload: &[u8],
        metadata: PayloadMetadata,
    ) -> Result<u64> {
        let mut stream = UnixStream::connect(self.socket_path.as_ref())
            .with_context(|| format!("connect event socket {}", self.socket_path.display()))?;
        configure_client_timeouts(&stream)?;
        write_json_line(
            &mut stream,
            &EmitRequest {
                contract: "heimdall.logs.emit/v1".into(),
                kind: "flow.data".into(),
                flow_id: Some(flow_id),
                pid: None,
                data: json!({
                    "direction": direction,
                    "boundary": boundary,
                    "original_bytes": metadata.original_bytes,
                    "stored_bytes": payload.len(),
                    "truncated": metadata.truncated,
                    "block": {
                        "index": metadata.index,
                        "max_bytes": metadata.max_bytes,
                        "flush_interval_ms": metadata.flush_interval_ms,
                        "flush_reason": metadata.flush_reason
                    }
                }),
                payload_base64: Some(STANDARD.encode(payload)),
            },
        )?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("finish payload event request")?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("read payload event response")?;
        ensure_event_response(&response, "record payload event")
    }
}

impl FlowEventClient {
    pub fn emit(&self, kind: &str, flow_id: Uuid, data: Value) -> Result<()> {
        self.client.emit(kind, flow_id, data)
    }

    pub fn emit_payload(
        &self,
        flow_id: Uuid,
        direction: &str,
        boundary: &str,
        payload: &[u8],
        metadata: PayloadMetadata,
    ) -> Result<u64> {
        self.client
            .emit_payload(flow_id, direction, boundary, payload, metadata)
    }
}

impl Drop for FlowEventClient {
    fn drop(&mut self) {
        let mut active = self
            .client
            .flows
            .active
            .lock()
            .expect("flow tracker poisoned");
        *active = active.checked_sub(1).expect("flow tracker underflow");
        if *active == 0 {
            self.client.flows.drained.notify_all();
        }
    }
}

fn write_control_error(stream: &mut UnixStream, code: &str, error: &anyhow::Error) -> Result<()> {
    write_json_line(
        stream,
        &ControlResponse {
            contract: CONTROL_CONTRACT,
            ok: false,
            segment: None,
            code: Some(code.into()),
            message: Some(error.to_string()),
        },
    )
}

fn classify_event_error(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        let Some(io_error) = cause.downcast_ref::<std::io::Error>() else {
            continue;
        };
        if io_error.raw_os_error() == Some(libc::ENOSPC) {
            return "event_store_full";
        }
        if io_error.kind() == std::io::ErrorKind::PermissionDenied {
            return "event_store_permission_denied";
        }
    }
    "event_failed"
}

fn ensure_event_response(response: &[u8], operation: &str) -> Result<u64> {
    let response: Value = serde_json::from_slice(response).context("decode event response")?;
    if response["ok"] == true {
        return response["seq"]
            .as_u64()
            .context("successful event response is missing sequence");
    }
    let code = response["code"].as_str().unwrap_or("event_failed");
    let message = response["message"]
        .as_str()
        .unwrap_or("event writer rejected request");
    anyhow::bail!("{operation} failed [{code}]: {message}")
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, value).context("encode control response")?;
    writer.write_all(b"\n").context("write control response")
}

pub fn request_rotation(run_id: Uuid) -> Result<Value> {
    request_rotation_at(run_id, &runtime_root()?)
}

fn request_rotation_at(run_id: Uuid, runtime: &Path) -> Result<Value> {
    let socket_path = runtime.join(control_socket_filename(run_id));
    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("run_not_active: connect {}", socket_path.display()))?;
    configure_client_timeouts(&stream)?;
    write_json_line(
        &mut stream,
        &json!({"contract": CONTROL_CONTRACT, "action": "rotate"}),
    )?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("finish log rotation request")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("read log rotation response")?;
    serde_json::from_slice(&response).context("decode log rotation response")
}

fn configure_client_timeouts(stream: &UnixStream) -> Result<()> {
    let timeout = Some(Duration::from_secs(1));
    stream
        .set_read_timeout(timeout)
        .context("set event-log socket read timeout")?;
    stream
        .set_write_timeout(timeout)
        .context("set event-log socket write timeout")
}

pub fn runs_root() -> Result<PathBuf> {
    Ok(state_home()?.join("heimdall/runs"))
}

pub fn runtime_root() -> Result<PathBuf> {
    if let Some(path) = absolute_env_path("XDG_RUNTIME_DIR") {
        return Ok(path.join("heimdall"));
    }
    Ok(state_home()?.join("heimdall/runtime"))
}

fn state_home() -> Result<PathBuf> {
    if let Some(path) = absolute_env_path("XDG_STATE_HOME") {
        return Ok(path);
    }
    let home = std::env::var_os("HOME").context("HOME is not set and XDG_STATE_HOME is absent")?;
    Ok(PathBuf::from(home).join(".local/state"))
}

fn absolute_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(metadata.is_dir(), "{} is not a directory", path.display());
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure {}", path.display()))
}

pub(crate) fn persist_manifest(run_dir: &Path, manifest: &RunManifest) -> Result<()> {
    let target = run_dir.join("run.json");
    let temporary = run_dir.join(format!(".run.{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(manifest).context("encode run manifest")?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("open {}", temporary.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", temporary.display()))?;
    fs::rename(&temporary, &target).with_context(|| format!("publish {}", target.display()))
}

fn format_timestamp(value: OffsetDateTime) -> Result<String> {
    value
        .format(TIMESTAMP_FORMAT)
        .context("format RFC 3339 event timestamp")
}

pub fn read_manifest(path: &Path) -> Result<RunManifest> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let manifest: RunManifest =
        serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))?;
    anyhow::ensure!(manifest.schema == RUN_CONTRACT, "unsupported run contract");
    Ok(manifest)
}

pub fn run_is_active(run_id: Uuid) -> Result<bool> {
    let socket_path = runtime_root()?.join(control_socket_filename(run_id));
    match UnixStream::connect(&socket_path) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error).with_context(|| format!("probe {}", socket_path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heimdall-events-{name}-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ))
    }

    #[test]
    fn writes_rotates_and_finalizes_a_run() {
        let root = test_state("lifecycle");
        let log = RunLog::create_at(
            &root,
            &["curl".into(), "https://example.com".into()],
            "default",
            "foreground",
        )
        .unwrap();
        log.ready("heimdall-run", None, &["transport"]).unwrap();
        log.emit(
            "run.exec",
            Some(42),
            json!({"child_pid": 42, "executable": "curl", "argv_count": 2}),
        )
        .unwrap();
        let runtime = Path::new("/tmp").join(format!(
            "heimdall-events-{}-{}",
            std::process::id(),
            &log.run_id().unwrap().simple().to_string()[..8]
        ));
        let server = RotationServer::start_at(log.clone(), &runtime).unwrap();
        let events = EventClient::connect(server.event_socket_path().to_path_buf()).unwrap();
        let flow_id = Uuid::now_v7();
        events
            .emit(
                "flow.open",
                flow_id,
                json!({
                    "network": "tcp",
                    "source": {"cgroup_id": 7},
                    "destination": {"host": "example.com", "port": 443},
                    "action": {"type": "direct"},
                    "policy": "default",
                    "boundary": "transport"
                }),
            )
            .unwrap();
        events
            .emit(
                "flow.close",
                flow_id,
                json!({
                    "network": "tcp",
                    "status": "complete",
                    "error_code": null,
                    "client_to_remote_bytes": 10,
                    "remote_to_client_bytes": 20,
                    "duration_us": 30
                }),
            )
            .unwrap();
        let response = request_rotation_at(log.run_id().unwrap(), &runtime).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["segment"]["first_seq"], 1);
        assert_eq!(response["segment"]["last_seq"], 5);
        drop(server);
        log.finish(0, true).unwrap();
        let run_dir = log.run_dir().unwrap();
        let manifest = read_manifest(&run_dir.join("run.json")).unwrap();
        assert_eq!(manifest.state, "closed");
        assert_eq!(manifest.segments.len(), 2);
        assert_eq!(manifest.capture["payload_storage"], "content_addressed");
        assert_eq!(manifest.result.unwrap().exit_code, Some(0));
        let events = fs::read_to_string(run_dir.join("events-000001.jsonl")).unwrap();
        assert!(events.contains(r#""payload_storage":"content_addressed""#));
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&runtime).unwrap();
    }

    #[test]
    fn bundled_schemas_are_valid_json_and_segment_uses_final_key() {
        let _: Value = serde_json::from_str(EVENT_SCHEMA).unwrap();
        let _: Value = serde_json::from_str(RUN_SCHEMA).unwrap();
        let _: Value = serde_json::from_str(SUMMARY_SCHEMA).unwrap();
        let value = serde_json::to_value(SegmentManifest {
            file: "events-000001.jsonl".into(),
            first_seq: 1,
            last_seq: 2,
            bytes: 42,
            sha256: "0".repeat(64),
            final_: true,
        })
        .unwrap();
        assert_eq!(value["final"], true);
        assert!(value.get("final_").is_none());
    }

    #[test]
    fn rotates_an_old_nonempty_segment_before_the_next_record() {
        let root = test_state("age-rotation");
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        {
            let mut writer = log.lock().unwrap();
            writer.segment_max_age = Duration::from_millis(1);
            writer.segment_started = Instant::now() - Duration::from_millis(2);
        }
        log.ready("heimdall-run", None, &["transport"]).unwrap();
        // Why: this test targets the forced rotation before run.ready. Do not
        // let scheduler latency independently rotate run.close as well.
        log.lock().unwrap().segment_max_age = Duration::from_secs(60);
        log.finish(0, true).unwrap();

        let manifest = read_manifest(&log.run_dir().unwrap().join("run.json")).unwrap();
        assert_eq!(manifest.segments.len(), 2);
        assert_eq!(manifest.segments[0].last_seq, 1);
        assert_eq!(manifest.segments[1].first_seq, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn event_client_waits_for_active_flow_guards() {
        // Why: CI providers often set TMPDIR to a deeply nested checkout path,
        // while Linux Unix-domain socket paths are limited to SUN_LEN bytes.
        let root = Path::new("/tmp").join(format!(
            "hd-flow-{}-{}",
            std::process::id(),
            &Uuid::now_v7().simple().to_string()[..8]
        ));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("events.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let client = EventClient::connect(socket).unwrap();
        let flow = client.start_flow();

        assert!(!client.wait_for_flows(Duration::from_millis(1)));
        drop(flow);
        assert!(client.wait_for_flows(Duration::from_millis(1)));

        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stores_payload_as_a_deduplicated_content_addressed_blob() {
        let root = test_state("payload-blob");
        let runtime = Path::new("/tmp").join(format!(
            "hd-payload-{}-{}",
            std::process::id(),
            &Uuid::now_v7().simple().to_string()[..8]
        ));
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        let server = RotationServer::start_at(log.clone(), &runtime).unwrap();
        let client = EventClient::connect(server.event_socket_path().to_path_buf()).unwrap();
        let flow_id = Uuid::now_v7();
        for _ in 0..2 {
            client
                .emit_payload(
                    flow_id,
                    "client_to_remote",
                    "transport",
                    b"ping",
                    PayloadMetadata {
                        original_bytes: 4,
                        truncated: false,
                        index: 1,
                        max_bytes: 65_536,
                        flush_interval_ms: 100,
                        flush_reason: "close",
                    },
                )
                .unwrap();
        }
        drop(server);
        log.finish(0, true).unwrap();

        let run_dir = log.run_dir().unwrap();
        let manifest = read_manifest(&run_dir.join("run.json")).unwrap();
        assert_eq!(manifest.blobs.count, 1);
        assert_eq!(manifest.blobs.bytes, 4);
        let events = fs::read_to_string(run_dir.join("events-000001.jsonl")).unwrap();
        let payload_events = events
            .lines()
            .filter(|line| line.contains(r#""kind":"flow.data""#))
            .collect::<Vec<_>>();
        assert_eq!(payload_events.len(), 2);
        assert!(!events.contains("cGluZw=="));
        let digest = hex::encode(Sha256::digest(b"ping"));
        let blob = run_dir
            .join("blobs/sha256")
            .join(&digest[..2])
            .join(&digest[2..4])
            .join(&digest);
        assert_eq!(fs::read(&blob).unwrap(), b"ping");
        assert!(fs::read_dir(blob.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn event_store_io_failures_have_stable_codes() {
        let full = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .context("write payload");
        assert_eq!(classify_event_error(&full), "event_store_full");

        let denied = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(
            classify_event_error(&denied),
            "event_store_permission_denied"
        );
    }
}
