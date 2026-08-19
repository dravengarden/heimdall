//! Bounded payload capture backed by the per-run event store.

use std::sync::Arc;

use anyhow::{Context, Result};
use heimdall_config::{CaptureConfig, CaptureMode};
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
    events: Option<EventClient>,
}

impl std::fmt::Debug for CaptureManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureManager")
            .field("max_bytes_per_flow", &self.max_bytes_per_flow)
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
    events: Option<EventClient>,
}

impl CaptureManager {
    pub async fn from_config(
        config: &CaptureConfig,
        events: Option<EventClient>,
    ) -> Result<Option<Self>> {
        if config.mode == CaptureMode::Off {
            return Ok(None);
        }
        Ok(Some(Self {
            max_bytes_per_flow: config.max_bytes_per_flow,
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
        Ok(CaptureFlow(Arc::new(Mutex::new(FlowWriter {
            flow_id: meta.flow_id,
            boundary: meta.boundary,
            remaining: self.max_bytes_per_flow,
            events: self.events.clone(),
        }))))
    }
}

impl CaptureFlow {
    pub async fn data(&self, direction: Direction, payload: &[u8]) -> Result<()> {
        let mut writer = self.0.lock().await;
        let original_bytes = payload.len() as u64;
        let take = writer.remaining.min(original_bytes) as usize;
        writer.remaining -= take as u64;
        if take == 0 {
            return Ok(());
        }
        if let Some(events) = &writer.events {
            events.emit_payload(
                writer.flow_id,
                direction.name(),
                writer.boundary,
                original_bytes,
                &payload[..take],
                take < payload.len(),
            )?;
        }
        Ok(())
    }

    pub async fn close(&self, _status: &'static str) -> Result<()> {
        Ok(())
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
    tokio::try_join!(
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
    )
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

    #[test]
    fn directions_are_stable() {
        assert_eq!(Direction::ClientToRemote.name(), "client_to_remote");
        assert_eq!(Direction::RemoteToClient.name(), "remote_to_client");
    }
}
