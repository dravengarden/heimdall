//! Bounded payload capture backed by the per-run event store.

use std::{
    collections::BTreeSet,
    os::unix::ffi::OsStrExt,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::{Context, Result};
use heimdall_config::{CaptureBoundary, CaptureConfig, CaptureDirection, CaptureMode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};
use uuid::Uuid;

use crate::event_log::{EventClient, PayloadMetadata};
use crate::http::HttpDeriver;

const COPY_BUFFER: usize = 16 * 1024;

#[derive(Clone)]
pub struct CaptureManager {
    max_bytes_per_flow: u64,
    block_max_bytes: usize,
    flush_interval: Duration,
    boundaries: BTreeSet<CaptureBoundary>,
    directions: BTreeSet<CaptureDirection>,
    redactions: Arc<Vec<Vec<u8>>>,
    events: Option<EventClient>,
}

impl std::fmt::Debug for CaptureManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureManager")
            .field("max_bytes_per_flow", &self.max_bytes_per_flow)
            .field("block_max_bytes", &self.block_max_bytes)
            .field("flush_interval", &self.flush_interval)
            .field("boundaries", &self.boundaries)
            .field("directions", &self.directions)
            .field("redaction_count", &self.redactions.len())
            .field("event_log", &self.events.is_some())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub enum Direction {
    ClientToRemote,
    RemoteToClient,
}

impl Direction {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ClientToRemote => "client_to_remote",
            Self::RemoteToClient => "remote_to_client",
        }
    }

    const fn config_value(self) -> CaptureDirection {
        match self {
            Self::ClientToRemote => CaptureDirection::ClientToRemote,
            Self::RemoteToClient => CaptureDirection::RemoteToClient,
        }
    }
}

pub struct FlowMeta<'a> {
    pub flow_id: Uuid,
    pub boundary: &'static str,
    pub network: &'static str,
    pub cgroup_id: u64,
    pub policy: &'a str,
    pub destination: &'a str,
    pub destination_port: u16,
    pub action: &'a str,
    pub payload: &'a str,
}

#[derive(Clone)]
pub struct CaptureFlow(Arc<Mutex<FlowWriter>>);

struct FlowWriter {
    flow_id: Uuid,
    boundary: &'static str,
    remaining: u64,
    enabled: bool,
    directions: BTreeSet<CaptureDirection>,
    redactions: Arc<Vec<Vec<u8>>>,
    block_max_bytes: usize,
    flush_interval_ms: u64,
    client_to_remote: PendingBytes,
    remote_to_client: PendingBytes,
    http: Option<HttpDeriver>,
    closed: bool,
    failure: Option<String>,
    events: Option<EventClient>,
}

#[derive(Default)]
struct PendingBytes {
    bytes: Vec<u8>,
    redacted: Vec<bool>,
    truncated: bool,
    next_block_index: u64,
}

impl CaptureManager {
    pub async fn from_config(
        config: &CaptureConfig,
        events: Option<EventClient>,
    ) -> Result<Option<Self>> {
        if config.mode == CaptureMode::Off {
            return Ok(None);
        }
        let mut redactions = Vec::new();
        let mut total_redaction_bytes = 0usize;
        for name in &config.redact_env {
            let value = std::env::var_os(name).with_context(|| {
                format!("capture redaction environment variable `{name}` is unset")
            })?;
            let value = value.as_os_str().as_bytes();
            anyhow::ensure!(
                !value.is_empty(),
                "capture redaction environment variable `{name}` is empty"
            );
            anyhow::ensure!(
                value.len() <= 4096,
                "capture redaction environment variable `{name}` exceeds 4096 bytes"
            );
            total_redaction_bytes = total_redaction_bytes.saturating_add(value.len());
            anyhow::ensure!(
                total_redaction_bytes <= 65_536,
                "capture redaction values exceed the 65536-byte aggregate limit"
            );
            if !redactions.iter().any(|existing| existing == value) {
                redactions.push(value.to_vec());
            }
        }
        redactions.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Ok(Some(Self {
            max_bytes_per_flow: config.max_bytes_per_flow,
            block_max_bytes: usize::try_from(config.block_max_bytes)
                .context("capture block limit does not fit usize")?,
            flush_interval: Duration::from_millis(config.flush_interval_ms),
            boundaries: config.boundaries.iter().copied().collect(),
            directions: config.directions.iter().copied().collect(),
            redactions: Arc::new(redactions),
            events,
        }))
    }

    pub async fn open(&self, meta: FlowMeta<'_>) -> Result<CaptureFlow> {
        let _ = (
            meta.network,
            meta.cgroup_id,
            meta.policy,
            meta.destination,
            meta.destination_port,
            meta.action,
            meta.payload,
        );
        let enabled = self
            .boundaries
            .iter()
            .any(|boundary| boundary.name() == meta.boundary);
        let state = Arc::new(Mutex::new(FlowWriter {
            flow_id: meta.flow_id,
            boundary: meta.boundary,
            remaining: self.max_bytes_per_flow,
            enabled,
            directions: self.directions.clone(),
            redactions: self.redactions.clone(),
            block_max_bytes: self.block_max_bytes,
            flush_interval_ms: self.flush_interval.as_millis() as u64,
            client_to_remote: PendingBytes::default(),
            remote_to_client: PendingBytes::default(),
            http: (enabled && meta.boundary.starts_with("tls_plaintext."))
                .then(HttpDeriver::default),
            closed: false,
            failure: None,
            events: self.events.clone(),
        }));
        if enabled {
            tokio::spawn(flush_on_interval(
                Arc::downgrade(&state),
                self.flush_interval,
            ));
        }
        Ok(CaptureFlow(state))
    }

    pub(crate) fn event_client(&self) -> Option<EventClient> {
        self.events.clone()
    }
}

impl CaptureFlow {
    pub async fn data(&self, direction: Direction, payload: &[u8]) -> Result<()> {
        let mut writer = self.0.lock().await;
        anyhow::ensure!(!writer.closed, "capture flow is already closed");
        if let Some(error) = &writer.failure {
            anyhow::bail!("capture writer failed: {error}");
        }
        if !writer.enabled || !writer.directions.contains(&direction.config_value()) {
            return Ok(());
        }
        let original_bytes = payload.len() as u64;
        let take = writer.remaining.min(original_bytes) as usize;
        writer.remaining -= take as u64;
        if take == 0 {
            return Ok(());
        }
        let truncated = take < payload.len();
        writer.append(direction, &payload[..take], truncated)?;
        if truncated && original_bytes > take as u64 {
            writer.remaining = 0;
        }
        Ok(())
    }

    pub async fn close(&self, _status: &'static str) -> Result<()> {
        let mut writer = self.0.lock().await;
        if writer.closed {
            return Ok(());
        }
        if let Some(error) = writer.failure.take() {
            writer.closed = true;
            anyhow::bail!("capture writer failed: {error}");
        }
        writer.flush(Direction::ClientToRemote, FlushReason::Close, true)?;
        writer.flush(Direction::RemoteToClient, FlushReason::Close, true)?;
        writer.closed = true;
        Ok(())
    }
}

impl FlowWriter {
    fn append(&mut self, direction: Direction, payload: &[u8], truncated: bool) -> Result<()> {
        let pending = self.pending(direction);
        pending.bytes.extend_from_slice(payload);
        pending.redacted.resize(pending.bytes.len(), false);
        pending.truncated |= truncated;
        self.flush(direction, FlushReason::Size, false)
    }

    fn flush(
        &mut self,
        direction: Direction,
        reason: FlushReason,
        final_flush: bool,
    ) -> Result<()> {
        let redactions = self.redactions.clone();
        let max_pattern_len = redactions.first().map_or(0, Vec::len);
        loop {
            let block_max_bytes = self.block_max_bytes;
            let Some((payload, truncated, block_index)) = self.pending(direction).take_block(
                &redactions,
                max_pattern_len,
                block_max_bytes,
                final_flush,
                reason != FlushReason::Size,
            ) else {
                break;
            };
            if let Some(events) = self.events.clone() {
                let source_seq = events.emit_payload(
                    self.flow_id,
                    direction.name(),
                    self.boundary,
                    &payload,
                    PayloadMetadata {
                        original_bytes: payload.len() as u64,
                        truncated,
                        index: block_index,
                        max_bytes: self.block_max_bytes as u64,
                        flush_interval_ms: self.flush_interval_ms,
                        flush_reason: reason.name(),
                    },
                )?;
                if let Some(derived) = self
                    .http
                    .as_mut()
                    .and_then(|http| http.observe(direction.name(), &payload, source_seq))
                {
                    events.emit(derived.kind, self.flow_id, derived.data)?;
                }
            }
        }
        Ok(())
    }

    fn pending(&mut self, direction: Direction) -> &mut PendingBytes {
        match direction {
            Direction::ClientToRemote => &mut self.client_to_remote,
            Direction::RemoteToClient => &mut self.remote_to_client,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlushReason {
    Size,
    Interval,
    Close,
}

impl FlushReason {
    const fn name(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Interval => "interval",
            Self::Close => "close",
        }
    }
}

async fn flush_on_interval(state: Weak<Mutex<FlowWriter>>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let Some(state) = state.upgrade() else {
            return;
        };
        let mut writer = state.lock().await;
        if writer.closed || writer.failure.is_some() {
            return;
        }
        let result = writer
            .flush(Direction::ClientToRemote, FlushReason::Interval, false)
            .and_then(|()| writer.flush(Direction::RemoteToClient, FlushReason::Interval, false));
        if let Err(error) = result {
            writer.failure = Some(error.to_string());
            return;
        }
    }
}

impl PendingBytes {
    fn take_block(
        &mut self,
        patterns: &[Vec<u8>],
        max_pattern_len: usize,
        block_max_bytes: usize,
        final_flush: bool,
        force: bool,
    ) -> Option<(Vec<u8>, bool, u64)> {
        for pattern in patterns {
            if pattern.len() > self.bytes.len() {
                continue;
            }
            for start in 0..=self.bytes.len() - pattern.len() {
                if self.bytes[start..start + pattern.len()] == **pattern {
                    self.redacted[start..start + pattern.len()].fill(true);
                }
            }
        }
        let safe = if final_flush {
            self.bytes.len()
        } else {
            self.bytes
                .len()
                .saturating_sub(max_pattern_len.saturating_sub(1))
        };
        if safe == 0 || (!force && safe < block_max_bytes) {
            return None;
        }
        let ready = safe.min(block_max_bytes);
        let payload = self
            .bytes
            .iter()
            .zip(&self.redacted)
            .take(ready)
            .map(|(&byte, &redacted)| if redacted { b'*' } else { byte })
            .collect();
        self.bytes.drain(..ready);
        self.redacted.drain(..ready);
        let truncated = self.truncated && (final_flush || self.bytes.is_empty());
        if truncated {
            self.truncated = false;
        }
        self.next_block_index += 1;
        Some((payload, truncated, self.next_block_index))
    }
}

pub async fn copy_tcp<A, B>(
    client: &mut A,
    remote: &mut B,
    capture: CaptureFlow,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let close_capture = capture.clone();
    let (client_read, client_write) = tokio::io::split(client);
    let (remote_read, remote_write) = tokio::io::split(remote);
    let result = tokio::try_join!(
        pump(
            client_read,
            remote_write,
            capture.clone(),
            Direction::ClientToRemote
        ),
        pump(
            remote_read,
            client_write,
            capture,
            Direction::RemoteToClient
        ),
    );
    let close_result = close_capture
        .close(if result.is_ok() { "complete" } else { "error" })
        .await;
    match result {
        Ok(counts) => {
            close_result?;
            Ok(counts)
        }
        Err(error) => {
            let _ = close_result;
            Err(error)
        }
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    capture: CaptureFlow,
    direction: Direction,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .context("read relayed transport")?;
        if count == 0 {
            writer
                .shutdown()
                .await
                .context("shutdown relayed transport")?;
            return Ok(total);
        }
        capture.data(direction, &buffer[..count]).await?;
        writer
            .write_all(&buffer[..count])
            .await
            .context("write relayed transport")?;
        total += count as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::{EventClient, RotationServer, RunLog};
    use std::{fs, path::Path};

    #[test]
    fn directions_are_stable() {
        assert_eq!(Direction::ClientToRemote.name(), "client_to_remote");
        assert_eq!(Direction::RemoteToClient.name(), "remote_to_client");
    }

    #[test]
    fn redacts_literals_split_across_observed_chunks() {
        let patterns = vec![b"secret-token".to_vec()];
        let mut pending = PendingBytes::default();
        pending.bytes.extend_from_slice(b"prefix secret-");
        pending.redacted.resize(pending.bytes.len(), false);
        let (first, _, _) = pending
            .take_block(&patterns, 12, 1024, false, true)
            .unwrap();
        pending.bytes.extend_from_slice(b"token suffix");
        pending.redacted.resize(pending.bytes.len(), false);
        let (second, _, _) = pending.take_block(&patterns, 12, 1024, true, true).unwrap();
        let output = [first, second].concat();
        assert_eq!(output, b"prefix ************ suffix");
        assert!(!output.windows(12).any(|window| window == b"secret-token"));
    }

    #[test]
    fn overlapping_redactions_do_not_reveal_a_longer_value() {
        let patterns = vec![b"abcdef".to_vec(), b"abc".to_vec()];
        let mut pending = PendingBytes::default();
        pending.bytes.extend_from_slice(b"abc");
        pending.redacted.resize(pending.bytes.len(), false);
        assert!(
            pending
                .take_block(&patterns, 6, 1024, false, true)
                .is_none()
        );
        pending.bytes.extend_from_slice(b"def");
        pending.redacted.resize(pending.bytes.len(), false);
        let (output, _, _) = pending.take_block(&patterns, 6, 1024, true, true).unwrap();
        assert_eq!(output, b"******");
    }

    #[tokio::test]
    async fn persists_allowlisted_payload_only_after_redaction() {
        let suffix = Uuid::now_v7().simple().to_string();
        let root = Path::new("/tmp").join(format!("heimdall-capture-test-{suffix}"));
        let runtime = Path::new("/tmp").join(format!("heimdall-capture-runtime-{suffix}"));
        let log = RunLog::create_at(&root, &["true".into()], "default", "foreground").unwrap();
        let server = RotationServer::start_at(log.clone(), &runtime).unwrap();
        let events = EventClient::connect(server.event_socket_path().to_path_buf()).unwrap();
        let manager = CaptureManager {
            max_bytes_per_flow: 1024,
            block_max_bytes: 8,
            flush_interval: Duration::from_millis(10),
            boundaries: [CaptureBoundary::TlsPlaintextRuntime].into_iter().collect(),
            directions: [CaptureDirection::ClientToRemote].into_iter().collect(),
            redactions: Arc::new(vec![b"secret-token".to_vec()]),
            events: Some(events),
        };
        let flow = manager
            .open(FlowMeta {
                flow_id: Uuid::now_v7(),
                boundary: "tls_plaintext.runtime",
                network: "tls",
                cgroup_id: 1,
                policy: "default",
                destination: "process:1",
                destination_port: 0,
                action: "runtime",
                payload: "tls_plaintext",
            })
            .await
            .unwrap();
        flow.data(Direction::ClientToRemote, b"prefix secret-")
            .await
            .unwrap();
        flow.data(Direction::ClientToRemote, b"token suffix")
            .await
            .unwrap();
        flow.data(Direction::RemoteToClient, b"must-not-be-stored")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        flow.close("complete").await.unwrap();
        drop(server);
        log.finish(0, true).unwrap();

        let run_dir = log.run_dir().unwrap();
        let mut stored = Vec::new();
        let mut blocks = Vec::new();
        for line in fs::read_to_string(run_dir.join("events-000001.jsonl"))
            .unwrap()
            .lines()
        {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            if event["kind"] == "flow.data" {
                blocks.push(event["data"]["block"].clone());
                stored.extend(
                    fs::read(run_dir.join(event["data"]["blob"]["path"].as_str().unwrap()))
                        .unwrap(),
                );
            }
        }
        assert!(!stored.windows(12).any(|bytes| bytes == b"secret-token"));
        assert!(
            !stored
                .windows(18)
                .any(|bytes| bytes == b"must-not-be-stored")
        );
        assert_eq!(stored, b"prefix ************ suffix");
        assert!(blocks.iter().all(|block| block["max_bytes"] == 8));
        assert!(blocks.iter().all(|block| block["flush_interval_ms"] == 10));
        assert!(
            blocks
                .iter()
                .all(|block| block["index"].as_u64().unwrap() > 0)
        );
        assert!(blocks.iter().any(|block| block["flush_reason"] == "size"));
        assert!(
            blocks
                .iter()
                .any(|block| block["flush_reason"] == "interval")
        );
        assert!(blocks.iter().any(|block| block["flush_reason"] == "close"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }
}
