//! Runtime TLS plaintext capture through OpenSSL uprobes.

use std::{
    collections::HashSet,
    fs,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{self, Ordering},
};

use crate::heimdall_common::{TAP_DATA_LEN, TapDir, TapEvent};
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
const MAX_DISCOVERED_IMAGES: usize = 64;
const MAX_LOADER_CONFIGS: usize = 64;
const MAX_LOADER_DIRECTORIES: usize = 64;
const MAX_LOADER_CONFIG_BYTES: u64 = 64 * 1024;
const DEFAULT_LIBRARY_DIRECTORIES: [&str; 6] = [
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
];

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
    let flow_id = uuid::Uuid::now_v7();
    let truncated = event.payload.len() < event.total_len as usize;
    if let Some(events) = capture.event_client() {
        events.emit_with_pid(
            "tls.runtime",
            flow_id,
            Some(event.tgid),
            serde_json::json!({
                "library": "openssl",
                "api_family": match event.direction {
                    Direction::ClientToRemote => "SSL_write*",
                    Direction::RemoteToClient => "SSL_read*",
                },
                "direction": event.direction.name(),
                "boundary": "tls_plaintext.runtime",
                "reported_bytes": event.total_len,
                "observed_bytes": event.payload.len(),
                "truncated": truncated
            }),
        )?;
    }
    let flow = capture
        .open(FlowMeta {
            flow_id,
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
    let status = if truncated {
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
    let mut capped = false;
    for image in &images {
        if attached_images == image_limit {
            capped = true;
            break;
        }
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
    if capped {
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
    let mut images = ImageSet::default();
    scan_mapped_libssl(Path::new("/proc"), &mut images);
    // Why: an inode-backed uprobe may be attached before the image is mapped.
    // Pre-attaching loader-known libraries covers ordinary post-exec dlopen
    // without retaining setup privilege after the workload starts.
    for directory in loader_directories(
        Path::new("/etc/ld.so.conf"),
        DEFAULT_LIBRARY_DIRECTORIES.iter().map(Path::new),
    ) {
        scan_library_directory(&directory, 1, &mut images);
    }
    images.paths
}

#[derive(Default)]
struct ImageSet {
    identities: HashSet<(u64, u64)>,
    paths: Vec<PathBuf>,
}

impl ImageSet {
    fn insert(&mut self, path: PathBuf) {
        if self.paths.len() == MAX_DISCOVERED_IMAGES {
            return;
        }
        let Ok(metadata) = fs::metadata(&path) else {
            return;
        };
        if metadata.is_file() && self.identities.insert((metadata.dev(), metadata.ino())) {
            self.paths.push(path);
        }
    }

    const fn is_full(&self) -> bool {
        self.paths.len() == MAX_DISCOVERED_IMAGES
    }
}

fn scan_mapped_libssl(proc_root: &Path, images: &mut ImageSet) {
    let Ok(processes) = fs::read_dir(proc_root) else {
        return;
    };
    let mut processes = processes.flatten().collect::<Vec<_>>();
    processes.sort_by_key(std::fs::DirEntry::file_name);
    for process in processes {
        if images.is_full() {
            return;
        }
        let Some(_pid) = process
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(maps) = fs::read_to_string(process.path().join("maps")) else {
            continue;
        };
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            let path = Path::new(path);
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(is_libssl_name)
            {
                continue;
            }
            images.insert(
                process
                    .path()
                    .join("root")
                    .join(path.strip_prefix("/").unwrap_or(path)),
            );
            if images.is_full() {
                return;
            }
        }
    }
}

fn scan_library_directory(directory: &Path, remaining_depth: usize, images: &mut ImageSet) {
    if images.is_full() {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut entries = entries.flatten().collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if images.is_full() {
            return;
        }
        let path = entry.path();
        let name_matches = entry.file_name().to_str().is_some_and(is_libssl_name);
        if name_matches {
            images.insert(path);
            continue;
        }
        if remaining_depth > 0 && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            scan_library_directory(&path, remaining_depth - 1, images);
        }
    }
}

fn is_libssl_name(name: &str) -> bool {
    name == "libssl.so"
        || name.strip_prefix("libssl.so.").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
}

fn loader_directories<'a>(
    config: &Path,
    defaults: impl IntoIterator<Item = &'a Path>,
) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    let mut seen_directories = HashSet::new();
    for directory in defaults {
        insert_loader_directory(
            directory.to_path_buf(),
            &mut directories,
            &mut seen_directories,
        );
    }
    let mut seen_configs = HashSet::new();
    collect_loader_config(
        config,
        &mut directories,
        &mut seen_directories,
        &mut seen_configs,
    );
    directories
}

fn insert_loader_directory(
    directory: PathBuf,
    directories: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) {
    if directories.len() < MAX_LOADER_DIRECTORIES && seen.insert(directory.clone()) {
        directories.push(directory);
    }
}

fn collect_loader_config(
    config: &Path,
    directories: &mut Vec<PathBuf>,
    seen_directories: &mut HashSet<PathBuf>,
    seen_configs: &mut HashSet<PathBuf>,
) {
    if seen_configs.len() == MAX_LOADER_CONFIGS {
        return;
    }
    let Ok(identity) = fs::canonicalize(config) else {
        return;
    };
    if !seen_configs.insert(identity) {
        return;
    }
    let Ok(metadata) = fs::metadata(config) else {
        return;
    };
    if metadata.len() > MAX_LOADER_CONFIG_BYTES {
        return;
    }
    let Ok(contents) = fs::read_to_string(config) else {
        return;
    };
    let base = config.parent().unwrap_or_else(|| Path::new("/"));
    for line in contents.lines() {
        let line = line.split_once('#').map_or(line, |(value, _)| value).trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        if first == "include" {
            for pattern in fields {
                let pattern = resolve_loader_path(base, Path::new(pattern));
                for included in expand_loader_include(&pattern) {
                    collect_loader_config(&included, directories, seen_directories, seen_configs);
                }
            }
        } else if fields.next().is_none() {
            insert_loader_directory(
                resolve_loader_path(base, Path::new(first)),
                directories,
                seen_directories,
            );
        }
    }
}

fn resolve_loader_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn expand_loader_include(pattern: &Path) -> Vec<PathBuf> {
    let Some(file_pattern) = pattern.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    if !file_pattern.contains('*') {
        return vec![pattern.to_path_buf()];
    }
    let Some(parent) = pattern.parent() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut matches = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| wildcard_matches(file_pattern, name))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    matches.sort();
    matches
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    let mut cursor = 0;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 && !pattern.starts_with('*') {
            let Some(rest) = value.get(cursor..).and_then(|rest| rest.strip_prefix(part)) else {
                return false;
            };
            cursor = value.len() - rest.len();
        } else if index + 1 == parts.len() && !pattern.ends_with('*') {
            return value.get(cursor..).is_some_and(|rest| rest.ends_with(part));
        } else {
            let Some(position) = value.get(cursor..).and_then(|rest| rest.find(part)) else {
                return false;
            };
            cursor += position + part.len();
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct TestTree(PathBuf);

    impl TestTree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "heimdall-runtime-discovery-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn libssl_name_rejects_debug_and_prefix_matches() {
        assert!(is_libssl_name("libssl.so"));
        assert!(is_libssl_name("libssl.so.3"));
        assert!(is_libssl_name("libssl.so.60.1.0"));
        assert!(!is_libssl_name("libssl.so.debug"));
        assert!(!is_libssl_name("libssl.so.3.backup"));
        assert!(!is_libssl_name("not-libssl.so.3"));
    }

    #[test]
    fn loader_config_expands_includes_without_cycles() {
        let tree = TestTree::new();
        let snippets = tree.0.join("conf.d");
        let libraries = tree.0.join("libraries");
        fs::create_dir_all(&snippets).unwrap();
        fs::create_dir_all(&libraries).unwrap();
        let config = tree.0.join("ld.so.conf");
        fs::write(&config, "include conf.d/*.conf\n").unwrap();
        fs::write(
            snippets.join("runtime.conf"),
            "../libraries\ninclude ../ld.so.conf\n",
        )
        .unwrap();

        let directories = loader_directories(&config, std::iter::empty());
        assert_eq!(directories, vec![snippets.join("../libraries")]);
    }

    #[test]
    fn library_scan_is_bounded_and_deduplicates_symlinks() {
        let tree = TestTree::new();
        let root = tree.0.join("lib");
        let arch = root.join("x86_64-linux-gnu");
        let too_deep = arch.join("nested");
        fs::create_dir_all(&too_deep).unwrap();
        fs::write(arch.join("libssl.so.3"), b"fixture").unwrap();
        symlink("libssl.so.3", arch.join("libssl.so")).unwrap();
        fs::write(arch.join("libssl.so.debug"), b"debug").unwrap();
        fs::write(too_deep.join("libssl.so.9"), b"deep").unwrap();

        let mut images = ImageSet::default();
        scan_library_directory(&root, 1, &mut images);

        assert_eq!(images.paths.len(), 1);
        assert!(images.paths[0].ends_with("libssl.so"));
    }

    #[test]
    fn wildcard_matching_is_anchored() {
        assert!(wildcard_matches("*.conf", "runtime.conf"));
        assert!(wildcard_matches("lib*.so.*", "libssl.so.3"));
        assert!(!wildcard_matches("*.conf", "runtime.conf.backup"));
        assert!(!wildcard_matches("lib*.so", "prefix-libssl.so"));
    }
}
