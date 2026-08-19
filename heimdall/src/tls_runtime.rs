//! Runtime TLS plaintext capture through OpenSSL uprobes.

use std::{
    collections::HashSet,
    fs,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
    ptr,
    sync::atomic::{self, Ordering},
};

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::{MapData, PerfEventArray, perf::PerfEventArrayBuffer},
    programs::{
        UProbe,
        links::FdLink,
        uprobe::{UProbeLinkId, UProbeScope},
    },
    util::online_cpus,
};
use heimdall_common::{TAP_DATA_LEN, TapDir, TapEvent};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::capture::{CaptureManager, Direction, FlowMeta};

struct Event {
    tgid: u32,
    cgroup_id: u64,
    direction: Direction,
    total_len: u32,
    payload: Vec<u8>,
}

const MAX_SETUP_IMAGES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct StartReport {
    pub discovered_images: usize,
    pub attached_images: usize,
    pub attached_links: usize,
    pub perf_cpus: Vec<u32>,
}

pub struct SetupRuntime {
    pub report: StartReport,
    pub links: Vec<FdLink>,
    pub buffers: Vec<PerfEventArrayBuffer<MapData>>,
}

pub struct RuntimeCapture {
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RuntimeCapture {
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        for task in std::mem::take(&mut self.tasks) {
            let _ = task.await;
        }
    }
}

impl Drop for RuntimeCapture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub fn start_from_fds(
    buffers: Vec<(u32, OwnedFd)>,
    capture: CaptureManager,
) -> Result<RuntimeCapture> {
    let (tx, mut rx) = mpsc::channel::<Event>(8192);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let mut tasks = Vec::with_capacity(buffers.len() + 1);
    for (cpu, fd) in buffers {
        let buffer = InheritedPerfBuffer::new(fd)
            .with_context(|| format!("map inherited runtime TLS perf buffer for CPU {cpu}"))?;
        let tx = tx.clone();
        tasks.push(tokio::spawn(read_inherited_events(
            buffer,
            tx,
            cpu,
            shutdown_rx.clone(),
        )));
    }
    drop(tx);

    tasks.push(tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(error) = record_event(&capture, event).await {
                warn!(error = %error, "runtime TLS capture write failed");
            }
        }
    }));
    Ok(RuntimeCapture { shutdown, tasks })
}

pub fn prepare_setup(bpf: &mut Ebpf) -> Result<SetupRuntime> {
    let (mut report, attached) = load_and_attach(bpf, MAX_SETUP_IMAGES)?;
    let mut links = Vec::with_capacity(attached.len());
    for (program, link_id) in attached {
        let probe: &mut UProbe = bpf
            .program_mut(program)
            .with_context(|| format!("{program} eBPF program disappeared"))?
            .try_into()?;
        links.push(
            probe
                .take_link(link_id)
                .with_context(|| format!("take ownership of {program} link"))?
                .try_into()
                .with_context(|| format!("convert {program} uprobe to an FD link"))?,
        );
    }
    let tap_events = bpf
        .take_map("TAP_EVENTS")
        .context("TAP_EVENTS map not found in eBPF object")?;
    let mut perf = PerfEventArray::try_from(tap_events)?;
    report.perf_cpus =
        online_cpus().map_err(|(message, error)| anyhow::anyhow!("{message}: {error}"))?;
    let mut buffers = Vec::with_capacity(report.perf_cpus.len());
    for &cpu in &report.perf_cpus {
        buffers.push(
            perf.open(cpu, None)
                .with_context(|| format!("open runtime TLS perf buffer for CPU {cpu}"))?,
        );
    }
    Ok(SetupRuntime {
        report,
        links,
        buffers,
    })
}

const PERF_PAGE_COUNT: usize = 2;
const PERF_DATA_HEAD_OFFSET: usize = 1024;
const PERF_DATA_TAIL_OFFSET: usize = PERF_DATA_HEAD_OFFSET + std::mem::size_of::<u64>();
const PERF_RECORD_LOST: u32 = 2;
const PERF_RECORD_SAMPLE: u32 = 9;
// Why: libc follows each Linux libc ABI here: ioctl requests are c_ulong on
// glibc but c_int on musl. Keeping the constants in libc's target-specific
// type lets the exact same source back both Nix and static release builds.
const PERF_EVENT_IOC_ENABLE: libc::Ioctl = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::Ioctl = 0x2401;

#[derive(Clone, Copy)]
#[repr(C)]
struct PerfEventHeader {
    event_type: u32,
    misc: u16,
    size: u16,
}

struct InheritedPerfBuffer {
    fd: OwnedFd,
    address: usize,
    mapped_len: usize,
    page_size: usize,
    data_size: usize,
}

impl InheritedPerfBuffer {
    #[allow(
        unsafe_code,
        reason = "the setup worker created this perf FD; mmap and ioctl are the Linux ABI for consuming its ring"
    )]
    fn new(fd: OwnedFd) -> Result<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        anyhow::ensure!(page_size > 0, "could not determine the system page size");
        let page_size = usize::try_from(page_size)?;
        let data_size = page_size * PERF_PAGE_COUNT;
        let mapped_len = page_size + data_size;
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("mmap inherited perf ring");
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE) } == -1 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::munmap(address, mapped_len);
            }
            return Err(error).context("enable inherited perf event");
        }
        Ok(Self {
            fd,
            address: address as usize,
            mapped_len,
            page_size,
            data_size,
        })
    }

    #[allow(
        unsafe_code,
        reason = "volatile positions and wrapped copies follow the perf_event_mmap_page userspace ABI"
    )]
    fn drain(&mut self, mut on_event: impl FnMut(InheritedPerfEvent)) {
        let metadata = self.address as *mut u8;
        let data = unsafe { metadata.add(self.page_size) };
        let head_ptr = unsafe { metadata.add(PERF_DATA_HEAD_OFFSET).cast::<u64>() };
        let tail_ptr = unsafe { metadata.add(PERF_DATA_TAIL_OFFSET).cast::<u64>() };
        let head = unsafe { ptr::read_volatile(head_ptr) };
        atomic::fence(Ordering::Acquire);
        let initial_tail = unsafe { ptr::read_volatile(tail_ptr) };
        let mut tail = initial_tail;
        while tail != head {
            let event_start = (tail % self.data_size as u64) as usize;
            let header: PerfEventHeader = unsafe { ptr::read(data.add(event_start).cast()) };
            let record_size = usize::from(header.size);
            if record_size < std::mem::size_of::<PerfEventHeader>()
                || record_size > self.data_size
                || tail.wrapping_add(record_size as u64) > head
            {
                warn!(record_size, "discarded malformed runtime TLS perf record");
                tail = head;
                break;
            }
            tail = tail.wrapping_add(record_size as u64);
            match header.event_type {
                PERF_RECORD_SAMPLE => {
                    let size_offset =
                        (event_start + std::mem::size_of::<PerfEventHeader>()) % self.data_size;
                    let sample_size =
                        unsafe { ptr::read(data.add(size_offset).cast::<u32>()) } as usize;
                    if sample_size + std::mem::size_of::<PerfEventHeader>() + 4 > record_size
                        || sample_size > self.data_size
                    {
                        warn!(
                            sample_size,
                            record_size, "discarded malformed runtime TLS sample"
                        );
                        continue;
                    }
                    let sample_start = (size_offset + 4) % self.data_size;
                    let mut bytes = vec![0_u8; sample_size];
                    let first = sample_size.min(self.data_size - sample_start);
                    unsafe {
                        ptr::copy_nonoverlapping(data.add(sample_start), bytes.as_mut_ptr(), first);
                        if first < sample_size {
                            ptr::copy_nonoverlapping(
                                data,
                                bytes.as_mut_ptr().add(first),
                                sample_size - first,
                            );
                        }
                    }
                    on_event(InheritedPerfEvent::Sample(bytes));
                }
                PERF_RECORD_LOST => {
                    let lost_offset = (event_start
                        + std::mem::size_of::<PerfEventHeader>()
                        + std::mem::size_of::<u64>())
                        % self.data_size;
                    let count = unsafe { ptr::read(data.add(lost_offset).cast::<u64>()) };
                    on_event(InheritedPerfEvent::Lost(count));
                }
                event_type => warn!(event_type, "ignored unexpected runtime TLS perf record"),
            }
        }

        if tail != initial_tail {
            atomic::fence(Ordering::SeqCst);
            unsafe {
                ptr::write_volatile(tail_ptr, tail);
            }
        }
    }
}

impl AsRawFd for InheritedPerfBuffer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for InheritedPerfBuffer {
    #[allow(
        unsafe_code,
        reason = "the mapping and perf event were acquired through the Linux ABI in new"
    )]
    fn drop(&mut self) {
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PERF_EVENT_IOC_DISABLE);
            libc::munmap(self.address as *mut libc::c_void, self.mapped_len);
        }
    }
}

enum InheritedPerfEvent {
    Sample(Vec<u8>),
    Lost(u64),
}

async fn record_event(capture: &CaptureManager, event: Event) -> Result<()> {
    let destination = format!("process:{}", event.tgid);
    let flow = capture
        .open(FlowMeta {
            flow_id: uuid::Uuid::now_v7(),
            boundary: "tls_plaintext.runtime",
            network: "tls",
            cgroup_id: event.cgroup_id,
            policy: "registered",
            destination: &destination,
            destination_port: 0,
            action: "runtime",
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

async fn read_inherited_events(
    buffer: InheritedPerfBuffer,
    tx: mpsc::Sender<Event>,
    cpu: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    let Ok(mut buffer) = tokio::io::unix::AsyncFd::new(buffer) else {
        warn!(cpu, "inherited runtime TLS perf reader registration failed");
        return;
    };
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    drain_inherited_events(buffer.get_mut(), &tx, cpu);
                }
                return;
            }
            ready = buffer.readable_mut() => {
                let mut ready = match ready {
                    Ok(ready) => ready,
                    Err(error) => {
                        warn!(cpu, error = %error, "inherited runtime TLS perf reader stopped");
                        return;
                    }
                };
                drain_inherited_events(ready.get_inner_mut(), &tx, cpu);
                ready.clear_ready();
            }
        }
    }
}

fn drain_inherited_events(buffer: &mut InheritedPerfBuffer, tx: &mpsc::Sender<Event>, cpu: u32) {
    buffer.drain(|event| match event {
        InheritedPerfEvent::Sample(bytes) => {
            if let Some(event) = decode(&bytes) {
                let _ = tx.try_send(event);
            }
        }
        InheritedPerfEvent::Lost(count) => {
            warn!(cpu, lost = count, "runtime TLS events dropped");
        }
    })
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

type AttachedLink = (&'static str, UProbeLinkId);

fn load_and_attach(bpf: &mut Ebpf, image_limit: usize) -> Result<(StartReport, Vec<AttachedLink>)> {
    for program in [
        "ssl_write_enter",
        "ssl_write_exit",
        "ssl_write_ex_enter",
        "ssl_write_ex_exit",
        "ssl_read_enter",
        "ssl_read_exit",
        "ssl_read_ex_enter",
        "ssl_read_ex_exit",
    ] {
        let probe: &mut UProbe = bpf
            .program_mut(program)
            .with_context(|| format!("{program} eBPF program not found"))?
            .try_into()?;
        probe.load().with_context(|| format!("load {program}"))?;
    }
    let images = scan_libssl();
    let mut attached_images = 0usize;
    let mut attached = Vec::new();
    for image in images.iter().take(image_limit) {
        match attach_image(bpf, image) {
            Ok(mut links) => {
                attached_images += 1;
                attached.append(&mut links);
            }
            Err(error) => warn!(
                image = %image.display(),
                error = %error,
                "skipped unsupported OpenSSL image"
            ),
        }
    }
    if images.len() > image_limit {
        warn!(
            discovered = images.len(),
            limit = image_limit,
            "runtime TLS setup capped the number of OpenSSL images"
        );
    }
    Ok((
        StartReport {
            discovered_images: images.len(),
            attached_images,
            attached_links: attached.len(),
            perf_cpus: Vec::new(),
        },
        attached,
    ))
}

fn attach_image(bpf: &mut Ebpf, target: &PathBuf) -> Result<Vec<AttachedLink>> {
    let mut attached = Vec::new();
    let result = (|| {
        attached.extend(attach_pair(
            bpf,
            target,
            "SSL_write",
            "ssl_write_enter",
            "ssl_write_exit",
        )?);
        attached.extend(attach_pair(
            bpf,
            target,
            "SSL_read",
            "ssl_read_enter",
            "ssl_read_exit",
        )?);
        for (symbol, entry, exit) in [
            ("SSL_write_ex", "ssl_write_ex_enter", "ssl_write_ex_exit"),
            ("SSL_read_ex", "ssl_read_ex_enter", "ssl_read_ex_exit"),
        ] {
            match attach_pair(bpf, target, symbol, entry, exit) {
                Ok(links) => attached.extend(links),
                Err(error) => warn!(
                    image = %target.display(),
                    symbol,
                    error = %error,
                    "optional OpenSSL API is unavailable"
                ),
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        detach_links(bpf, attached);
        return Err(error);
    }
    Ok(attached)
}

fn attach_pair(
    bpf: &mut Ebpf,
    target: &PathBuf,
    symbol: &'static str,
    entry: &'static str,
    exit: &'static str,
) -> Result<Vec<AttachedLink>> {
    let mut attached = Vec::with_capacity(2);
    for (program, ret) in [(entry, false), (exit, true)] {
        let probe: &mut UProbe = bpf
            .program_mut(program)
            .with_context(|| format!("{program} eBPF program not found"))?
            .try_into()?;
        match probe
            .attach(symbol, target, UProbeScope::AllProcesses)
            .with_context(|| {
                format!(
                    "attach {program} ({})",
                    if ret { "return" } else { "entry" }
                )
            }) {
            Ok(link_id) => attached.push((program, link_id)),
            Err(error) => {
                detach_links(bpf, attached);
                return Err(error);
            }
        }
    }
    Ok(attached)
}

fn detach_links(bpf: &mut Ebpf, links: Vec<AttachedLink>) {
    for (program, link_id) in links {
        if let Some(program) = bpf.program_mut(program)
            && let Ok(probe) = <&mut UProbe>::try_from(program)
        {
            let _ = probe.detach(link_id);
        }
    }
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
