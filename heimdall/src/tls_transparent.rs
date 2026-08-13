//! Transparent TLS plaintext capture through OpenSSL uprobes.

use std::{collections::HashSet, fs, os::unix::fs::MetadataExt, path::PathBuf};

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::{
        MapData, PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::{UProbe, uprobe::UProbeScope},
    util::online_cpus,
};
use heimdall_common::{TAP_DATA_LEN, TapDir, TapEvent};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::capture::{CaptureManager, Direction, FlowMeta};

struct Event {
    tgid: u32,
    cgroup_id: u64,
    direction: Direction,
    total_len: u32,
    payload: Vec<u8>,
}

pub fn start(bpf: &mut Ebpf, capture: CaptureManager) -> Result<usize> {
    for program in ["ssl_write", "ssl_read_enter", "ssl_read_exit"] {
        let probe: &mut UProbe = bpf
            .program_mut(program)
            .with_context(|| format!("{program} eBPF program not found"))?
            .try_into()?;
        probe.load().with_context(|| format!("load {program}"))?;
    }
    let images = scan_libssl();
    let mut attached = 0usize;
    for image in &images {
        match attach(bpf, image) {
            Ok(()) => attached += 1,
            Err(error) => warn!(
                image = %image.display(),
                error = %error,
                "skipped unsupported OpenSSL image"
            ),
        }
    }

    let map = bpf
        .take_map("TAP_EVENTS")
        .context("TAP_EVENTS map not found in eBPF object")?;
    let mut perf = PerfEventArray::try_from(map)?;
    let (tx, mut rx) = mpsc::channel::<Event>(8192);
    for cpu in online_cpus().map_err(|(message, error)| anyhow::anyhow!("{message}: {error}"))? {
        let buffer = perf.open(cpu, None)?;
        let tx = tx.clone();
        tokio::spawn(read_events(buffer, tx, cpu));
    }
    drop(tx);

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(error) = record_event(&capture, event).await {
                warn!(error = %error, "transparent TLS capture write failed");
            }
        }
    });
    info!(attached, "transparent TLS OpenSSL probes attached");
    Ok(attached)
}

async fn record_event(capture: &CaptureManager, event: Event) -> Result<()> {
    let destination = format!("process:{}", event.tgid);
    let flow = capture
        .open(FlowMeta {
            network: "tls",
            cgroup_id: event.cgroup_id,
            policy: "registered",
            destination: &destination,
            destination_port: 0,
            action: "transparent",
            payload: "tls_plaintext",
        })
        .await?;
    flow.data(event.direction, &event.payload).await?;
    let status = if event.payload.len() < event.total_len as usize {
        "source_truncated"
    } else {
        "complete"
    };
    flow.close(status).await
}

async fn read_events(buffer: PerfEventArrayBuffer<MapData>, tx: mpsc::Sender<Event>, cpu: u32) {
    let Ok(mut buffer) = tokio::io::unix::AsyncFd::new(buffer) else {
        warn!(cpu, "transparent TLS perf reader registration failed");
        return;
    };
    loop {
        let mut ready = match buffer.readable_mut().await {
            Ok(ready) => ready,
            Err(error) => {
                warn!(cpu, error = %error, "transparent TLS perf reader stopped");
                return;
            }
        };
        ready.get_inner_mut().for_each(|event| match event {
            PerfEvent::Sample { head, tail } => {
                let event = if tail.is_empty() {
                    decode(head)
                } else {
                    let mut bytes = Vec::with_capacity(head.len() + tail.len());
                    bytes.extend_from_slice(head);
                    bytes.extend_from_slice(tail);
                    decode(&bytes)
                };
                if let Some(event) = event {
                    let _ = tx.try_send(event);
                }
            }
            PerfEvent::Lost { count } => {
                warn!(cpu, lost = count, "transparent TLS events dropped");
            }
        });
        ready.clear_ready();
    }
}

#[allow(
    unsafe_code,
    reason = "the fixed-size byte slice is checked before copying the shared repr(C) event"
)]
fn decode(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < std::mem::size_of::<TapEvent>() {
        return None;
    }
    let raw: TapEvent = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&raw as *const TapEvent).cast_mut().cast::<u8>(),
            std::mem::size_of::<TapEvent>(),
        );
    }
    let direction = match raw.dir {
        value if value == TapDir::Send as u32 => Direction::ClientToRemote,
        value if value == TapDir::Recv as u32 => Direction::RemoteToClient,
        _ => return None,
    };
    let captured = raw.captured_len.min(TAP_DATA_LEN as u32) as usize;
    Some(Event {
        tgid: (raw.tgid_pid >> 32) as u32,
        cgroup_id: raw.cgroup_id,
        direction,
        total_len: raw.total_len,
        payload: raw.data[..captured].to_vec(),
    })
}

fn attach(bpf: &mut Ebpf, target: &PathBuf) -> Result<()> {
    for (program, symbol, ret) in [
        ("ssl_write", "SSL_write", false),
        ("ssl_read_enter", "SSL_read", false),
        ("ssl_read_exit", "SSL_read", true),
    ] {
        let probe: &mut UProbe = bpf
            .program_mut(program)
            .with_context(|| format!("{program} eBPF program not found"))?
            .try_into()?;
        probe
            .attach(symbol, target, UProbeScope::AllProcesses)
            .with_context(|| {
                format!(
                    "attach {program} ({})",
                    if ret { "return" } else { "entry" }
                )
            })?;
    }
    Ok(())
}

fn scan_libssl() -> Vec<PathBuf> {
    let mut identities = HashSet::new();
    let mut images = Vec::new();
    let Ok(processes) = fs::read_dir("/proc") else {
        return images;
    };
    for process in processes.flatten() {
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            if !path.contains("libssl.so") {
                continue;
            }
            let host_path = PathBuf::from(format!("/proc/{pid}/root{path}"));
            let Ok(metadata) = fs::metadata(&host_path) else {
                continue;
            };
            if identities.insert((metadata.dev(), metadata.ino())) {
                images.push(host_path);
            }
        }
    }
    images
}
