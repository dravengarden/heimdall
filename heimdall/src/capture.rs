//! Bounded payload capture backed by the per-run event store.

use std::{collections::BTreeSet, os::unix::ffi::OsStrExt, sync::Arc};

use anyhow::{Context, Result};
use heimdall_config::{CaptureBoundary, CaptureConfig, CaptureDirection, CaptureMode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};
use uuid::Uuid;

use crate::event_log::EventClient;

const COPY_BUFFER: usize = 16 * 1024;

#[derive(Clone)]
pub struct CaptureManager {
    max_bytes_per_flow: u64,
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
    client_to_remote: PendingBytes,
    remote_to_client: PendingBytes,
    closed: bool,
    events: Option<EventClient>,
}

#[derive(Default)]
struct PendingBytes {
    bytes: Vec<u8>,
    redacted: Vec<bool>,
    truncated: bool,
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
        Ok(CaptureFlow(Arc::new(Mutex::new(FlowWriter {
            flow_id: meta.flow_id,
            boundary: meta.boundary,
            remaining: self.max_bytes_per_flow,
            enabled,
            directions: self.directions.clone(),
            redactions: self.redactions.clone(),
            client_to_remote: PendingBytes::default(),
            remote_to_client: PendingBytes::default(),
            closed: false,
            events: self.events.clone(),
        }))))
    }

    pub(crate) fn event_client(&self) -> Option<EventClient> {
        self.events.clone()
    }
}

impl CaptureFlow {
    pub async fn data(&self, direction: Direction, payload: &[u8]) -> Result<()> {
        let mut writer = self.0.lock().await;
        anyhow::ensure!(!writer.closed, "capture flow is already closed");
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
        writer.flush(Direction::ClientToRemote, true)?;
        writer.flush(Direction::RemoteToClient, true)?;
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
        self.flush(direction, false)
    }

    fn flush(&mut self, direction: Direction, final_flush: bool) -> Result<()> {
        let redactions = self.redactions.clone();
        let max_pattern_len = redactions.first().map_or(0, Vec::len);
        let (payload, truncated) =
            self.pending(direction)
                .take_ready(&redactions, max_pattern_len, final_flush);
        if payload.is_empty() {
            return Ok(());
        }
        if let Some(events) = &self.events {
            events.emit_payload(
                self.flow_id,
                direction.name(),
                self.boundary,
                payload.len() as u64,
                &payload,
                truncated,
            )?;
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

impl PendingBytes {
    fn take_ready(
        &mut self,
        patterns: &[Vec<u8>],
        max_pattern_len: usize,
        final_flush: bool,
    ) -> (Vec<u8>, bool) {
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
        let ready = if final_flush {
            self.bytes.len()
        } else {
            self.bytes
                .len()
                .saturating_sub(max_pattern_len.saturating_sub(1))
        };
        if ready == 0 {
            return (Vec::new(), false);
        }
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
        (payload, truncated)
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
        let (first, _) = pending.take_ready(&patterns, 12, false);
        pending.bytes.extend_from_slice(b"token suffix");
        pending.redacted.resize(pending.bytes.len(), false);
        let (second, _) = pending.take_ready(&patterns, 12, true);
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
        assert!(pending.take_ready(&patterns, 6, false).0.is_empty());
        pending.bytes.extend_from_slice(b"def");
        pending.redacted.resize(pending.bytes.len(), false);
        let (output, _) = pending.take_ready(&patterns, 6, true);
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
        flow.close("complete").await.unwrap();
        drop(server);
        log.finish(0, true).unwrap();

        let run_dir = log.run_dir().unwrap();
        let mut stored = Vec::new();
        for line in fs::read_to_string(run_dir.join("events-000001.jsonl"))
            .unwrap()
            .lines()
        {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            if event["kind"] == "flow.data" {
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
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }
}
