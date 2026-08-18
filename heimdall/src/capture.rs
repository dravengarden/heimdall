//! Bounded capture for relay transport and decrypted TLS payloads.

use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use heimdall_config::{CaptureConfig, CaptureMode};
use serde::Serialize;
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

const CONTRACT: &str = "heimdall.capture/v1";
const COPY_BUFFER: usize = 16 * 1024;
static NEXT_FLOW: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct CaptureManager {
    directory: Arc<std::path::PathBuf>,
    max_bytes_per_flow: u64,
}

#[derive(Clone, Copy)]
pub enum Direction {
    ClientToRemote,
    RemoteToClient,
}

impl Direction {
    const fn name(self) -> &'static str {
        match self {
            Self::ClientToRemote => "client_to_remote",
            Self::RemoteToClient => "remote_to_client",
        }
    }
}

pub struct FlowMeta<'a> {
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
    file: File,
    flow_id: String,
    sequence: u64,
    remaining: u64,
    client_to_remote_bytes: u64,
    remote_to_client_bytes: u64,
    captured_bytes: u64,
    truncated: bool,
}

#[derive(Serialize)]
struct Record<'a> {
    contract: &'static str,
    event: &'static str,
    flow_id: &'a str,
    sequence: u64,
    timestamp_unix_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    captured_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_to_remote_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_to_client_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
}

impl CaptureManager {
    pub async fn from_config(config: &CaptureConfig) -> Result<Option<Self>> {
        if config.mode == CaptureMode::Off {
            return Ok(None);
        }
        let existed = tokio::fs::try_exists(&config.directory)
            .await
            .with_context(|| format!("inspect capture path {}", config.directory.display()))?;
        tokio::fs::create_dir_all(&config.directory)
            .await
            .with_context(|| format!("create capture directory {}", config.directory.display()))?;
        let metadata = tokio::fs::symlink_metadata(&config.directory)
            .await
            .with_context(|| format!("inspect capture directory {}", config.directory.display()))?;
        anyhow::ensure!(
            metadata.is_dir(),
            "capture directory {} must be a directory, not a file or symbolic link",
            config.directory.display()
        );
        if existed {
            anyhow::ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "capture directory {} must not grant group or other permissions; use mode 0700",
                config.directory.display()
            );
        } else {
            tokio::fs::set_permissions(&config.directory, std::fs::Permissions::from_mode(0o700))
                .await
                .with_context(|| {
                    format!("secure capture directory {}", config.directory.display())
                })?;
        }

        // Why: configuration validation cannot prove the invoking identity can
        // write here. Fail before eBPF attachment instead of dropping the first
        // intercepted flow after the run reports ready.
        let probe = config.directory.join(format!(
            ".heimdall-write-probe-{}-{}",
            std::process::id(),
            NEXT_FLOW.fetch_add(1, Ordering::Relaxed)
        ));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&probe)
            .with_context(|| {
                format!(
                    "verify capture directory {} is writable",
                    config.directory.display()
                )
            })?;
        std::fs::remove_file(&probe)
            .with_context(|| format!("remove capture write probe {}", probe.display()))?;

        Ok(Some(Self {
            directory: Arc::new(config.directory.clone()),
            max_bytes_per_flow: config.max_bytes_per_flow,
        }))
    }

    pub async fn open(&self, meta: FlowMeta<'_>) -> Result<CaptureFlow> {
        let flow_id = format!(
            "{}-{}-{}",
            meta.network,
            timestamp_unix_us(),
            NEXT_FLOW.fetch_add(1, Ordering::Relaxed)
        );
        let path = self.directory.join(format!("{flow_id}.jsonl"));
        let std_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create capture file {}", path.display()))?;
        let mut writer = FlowWriter {
            file: File::from_std(std_file),
            flow_id,
            sequence: 0,
            remaining: self.max_bytes_per_flow,
            client_to_remote_bytes: 0,
            remote_to_client_bytes: 0,
            captured_bytes: 0,
            truncated: false,
        };
        let record = Record {
            contract: CONTRACT,
            event: "open",
            flow_id: &writer.flow_id,
            sequence: writer.sequence,
            timestamp_unix_us: timestamp_unix_us(),
            network: Some(meta.network),
            cgroup_id: Some(meta.cgroup_id),
            policy: Some(meta.policy),
            destination: Some(meta.destination),
            destination_port: Some(meta.destination_port),
            action: Some(meta.action),
            payload: Some(meta.payload),
            direction: None,
            payload_base64: None,
            original_bytes: None,
            captured_bytes: None,
            client_to_remote_bytes: None,
            remote_to_client_bytes: None,
            truncated: None,
            status: None,
        };
        write_record(&mut writer.file, &record).await?;
        writer.sequence += 1;
        Ok(CaptureFlow(Arc::new(Mutex::new(writer))))
    }
}

impl CaptureFlow {
    pub async fn data(&self, direction: Direction, payload: &[u8]) -> Result<()> {
        let mut writer = self.0.lock().await;
        let original_bytes = payload.len() as u64;
        match direction {
            Direction::ClientToRemote => writer.client_to_remote_bytes += original_bytes,
            Direction::RemoteToClient => writer.remote_to_client_bytes += original_bytes,
        }
        let take = writer.remaining.min(original_bytes) as usize;
        if take < payload.len() {
            writer.truncated = true;
        }
        if take == 0 {
            return Ok(());
        }
        writer.remaining -= take as u64;
        writer.captured_bytes += take as u64;
        let flow_id = writer.flow_id.clone();
        let sequence = writer.sequence;
        let record = Record {
            contract: CONTRACT,
            event: "data",
            flow_id: &flow_id,
            sequence,
            timestamp_unix_us: timestamp_unix_us(),
            network: None,
            cgroup_id: None,
            policy: None,
            destination: None,
            destination_port: None,
            action: None,
            payload: None,
            direction: Some(direction.name()),
            payload_base64: Some(STANDARD.encode(&payload[..take])),
            original_bytes: Some(original_bytes),
            captured_bytes: Some(take as u64),
            client_to_remote_bytes: None,
            remote_to_client_bytes: None,
            truncated: Some(take < payload.len()),
            status: None,
        };
        write_record(&mut writer.file, &record).await?;
        writer.sequence += 1;
        Ok(())
    }

    pub async fn close(&self, status: &'static str) -> Result<()> {
        let mut writer = self.0.lock().await;
        let flow_id = writer.flow_id.clone();
        let sequence = writer.sequence;
        let record = Record {
            contract: CONTRACT,
            event: "close",
            flow_id: &flow_id,
            sequence,
            timestamp_unix_us: timestamp_unix_us(),
            network: None,
            cgroup_id: None,
            policy: None,
            destination: None,
            destination_port: None,
            action: None,
            payload: None,
            direction: None,
            payload_base64: None,
            original_bytes: None,
            captured_bytes: Some(writer.captured_bytes),
            client_to_remote_bytes: Some(writer.client_to_remote_bytes),
            remote_to_client_bytes: Some(writer.remote_to_client_bytes),
            truncated: Some(writer.truncated),
            status: Some(status),
        };
        write_record(&mut writer.file, &record).await?;
        writer.file.flush().await.context("flush capture record")
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
            capture.clone(),
            Direction::RemoteToClient
        ),
    );
    let status = if result.is_ok() { "complete" } else { "error" };
    capture.close(status).await?;
    result
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

async fn write_record(file: &mut File, record: &Record<'_>) -> Result<()> {
    let mut encoded = serde_json::to_vec(record).context("encode capture record")?;
    encoded.push(b'\n');
    file.write_all(&encoded)
        .await
        .context("write capture record")
}

fn timestamp_unix_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directions_are_stable() {
        assert_eq!(Direction::ClientToRemote.name(), "client_to_remote");
        assert_eq!(Direction::RemoteToClient.name(), "remote_to_client");
    }

    #[tokio::test]
    async fn rejects_an_existing_capture_directory_with_broad_permissions() {
        let directory = std::env::temp_dir().join(format!(
            "heimdall-capture-permissions-{}-{}",
            std::process::id(),
            NEXT_FLOW.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = CaptureConfig {
            mode: CaptureMode::On,
            directory: directory.clone(),
            max_bytes_per_flow: 1024,
        };

        let error = CaptureManager::from_config(&config).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must not grant group or other permissions")
        );
        std::fs::remove_dir(directory).unwrap();
    }
}
