//! Phase B — TLS plaintext tap via libssl uprobes.
//!
//! Pipeline:
//!
//!   /proc/*/maps → unique libssl files (deduped by inode + dev)
//!       │
//!       │ aya UProbe::attach(SSL_write / SSL_read entry / SSL_read return)
//!       ▼
//!   eBPF uprobe programs emit TapEvent → TAP_EVENTS perf array
//!       │
//!       ▼
//!   AsyncPerfEventArray (one buffer per CPU) → mpsc::Sender<ObservedTap>
//!
//! Caveats / scope:
//!  * libssl + Go + rustls + statically-linked BoringSSL. Java needs
//!    different program logic (JVMTI, see docs/observability.md).
//!  * Symbol resolution via the dynsym table (libssl exports SSL_write and
//!    SSL_read). If a build strips them, attach fails for that file.
//!  * We attach by *file path*, not pid. One attach catches every process
//!    that maps that libssl image (including pods and the host). Userspace
//!    can later filter events by tgid → cgroup_id → pod_uid.
//!
//! Future work tracked elsewhere:
//!
//!  * rustls — investigated and deliberately deferred. Write side IS
//!    attachable via the demangled symbol `<rustls::conn::ConnectionCommon
//!    <T> as rustls::conn::connection::PlaintextSink>::write`, but each
//!    binary mangles a different `::h<hash>` suffix so we'd need a
//!    demangle-and-pattern-match pass instead of aya's exact-name lookup.
//!    Read side is harder: Reader::read is inlined into call sites in
//!    every rustls build we've seen on this cluster, so only `consume`
//!    and `into_first_chunk` remain as standalone symbols and neither
//!    carries the plaintext buffer in a usable register. The Coroot
//!    pattern is a recvfrom(fd) kprobe joined to the rustls Connection's
//!    Reader at userspace correlation time — ~1 day of work and per
//!    binary verification. The 6 rustls binaries on this host are vector,
//!    edge-runtime, clickhouse, heimdall itself, pop-launcher, and zed
//!    remote-server — we cover the high-traffic ones (clickhouse, vector)
//!    in a future iteration when justified.
//!
//!  * Java/JVM — JVMTI agent + native stub probed via uprobe.
//!  * Live discovery — re-scan periodically or via fanotify on cgroup procs.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    fs::{self, File},
    io::{BufRead, BufReader},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    maps::AsyncPerfEventArray,
    programs::UProbe,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use heimdall_common::{TapDir, TapEvent, TAP_DATA_LEN};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Set of `(dev, inode)` pairs whose binaries already have uprobes
/// attached. Shared between `start()` and `spawn_rescan()` so the
/// periodic re-scan only attaches to *newly* discovered binaries.
pub type AttachedSet = Arc<Mutex<HashSet<(u64, u64)>>>;

/// AI-queryable snapshot of what the tap layer has done. Surfaces via
/// `/api/status`'s `tap` field. The whole struct is `Default` + `Clone`
/// + `Serialize`, so the API handler just clones the locked snapshot.
///
/// Counters are running totals from daemon start; they include rescan
/// activity. `recent_failures` is a circular buffer (cap 32) so memory
/// can't grow unbounded on a binary-churn loop.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TapStatus {
    /// Total live uprobe attaches across every scanner.
    pub attached: usize,
    /// Per-scanner attach counts.
    pub scanners: TapScannerCounts,
    /// Most-recent attach failures, oldest first. Useful for AI to
    /// answer "why did pod X's TLS not get captured?" — search for
    /// path components.
    pub recent_failures: Vec<TapAttachFailure>,
    /// Live re-scan loop health.
    pub rescan: TapRescanStatus,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TapScannerCounts {
    pub libssl: usize,
    pub go: usize,
    pub rustls: usize,
    pub boringssl_static: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TapAttachFailure {
    pub scanner: &'static str,
    pub path: String,
    pub error: String,
    pub ts_us: i64,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TapRescanStatus {
    /// `true` once `spawn_rescan` has been wired up; `false` means the
    /// rescan task wasn't spawned (tap disabled, daemon misconfig).
    pub enabled: bool,
    pub period_secs: u64,
    /// Ticks completed (including ticks that found 0 new probes).
    pub ticks: u64,
    /// Wall-clock micros of the most recent tick. AI can compute
    /// `(now - last_tick_ts_us) / 1_000_000 > period_secs * 2` to flag
    /// a stalled rescan loop.
    pub last_tick_ts_us: i64,
    /// Count of times the rescan body panicked and was caught. Any
    /// non-zero value is a bug — the loop continues, but a Sentry-style
    /// alert should fire.
    pub panics: u64,
}

pub type TapStatusHandle = Arc<Mutex<TapStatus>>;

/// Bump the right scanner's attach counter and the global total.
fn record_attach_ok(status: &TapStatusHandle, scanner: &'static str) {
    let mut s = status.lock().unwrap();
    s.attached += 1;
    match scanner {
        "libssl" => s.scanners.libssl += 1,
        "go" => s.scanners.go += 1,
        "rustls" => s.scanners.rustls += 1,
        "boringssl_static" => s.scanners.boringssl_static += 1,
        _ => {}
    }
}

/// Append an attach failure to the circular buffer (cap 32). Older
/// entries get dropped from the front. The error string is the
/// `Display` of the anyhow error chain — sufficient for grep but not
/// enormous.
fn record_attach_fail(
    status: &TapStatusHandle,
    scanner: &'static str,
    path: PathBuf,
    error: anyhow::Error,
) {
    let mut s = status.lock().unwrap();
    s.recent_failures.push(TapAttachFailure {
        scanner,
        path: path.display().to_string(),
        error: format!("{error:#}"),
        ts_us: crate::store::now_micros(),
    });
    while s.recent_failures.len() > 32 {
        s.recent_failures.remove(0);
    }
}

/// One captured SSL_write call or SSL_read return, ready for the daemon
/// to correlate with a flow via cgroup_id.
#[derive(Debug, Clone)]
pub struct ObservedTap {
    pub tgid: u32,
    /// Leaf cgroup id of the task that made the SSL call. The relay
    /// stamps the same value into `flows.cgroup_id` at connect4 time,
    /// so we can match plaintext to the right flow without /proc walks.
    pub cgroup_id: u64,
    pub dir: TapDir,
    pub total_len: u32,
    pub captured: Vec<u8>,
}

/// Receiver end of the tap pipeline. Daemon owns this and reads events.
pub struct TapHandle {
    pub events: mpsc::Receiver<ObservedTap>,
    /// Number of unique TLS-bearing images attached at startup
    /// (libssl + Go + rustls + BoringSSL static combined).
    pub attached_libs: usize,
    /// `(dev, inode)` pairs of every binary that has uprobes attached.
    /// Owned by `spawn_rescan` so periodic discovery skips already-
    /// attached files. Shared via `Arc` so `main` can pass it to the
    /// rescan task without taking it out of the handle.
    pub attached_inodes: AttachedSet,
}

/// Initialize the tap: scan processes for libssl, attach uprobes, spawn
/// per-CPU perf consumers. Returns an `mpsc::Receiver` of decoded events.
///
/// On any single-step error this returns an empty handle (0 attached libs)
/// rather than failing — the relay should keep working even when the tap
/// can't.
pub fn start(bpf: &mut Ebpf, status: &TapStatusHandle) -> Result<TapHandle> {
    let attached_inodes: AttachedSet = Arc::new(Mutex::new(HashSet::new()));

    // ─── Discover libssl images ──────────────────────────────────────────
    let libs = scan_libssl();
    info!(count = libs.len(), "tap: libssl candidates discovered");

    // ─── Discover Go TLS binaries ────────────────────────────────────────
    let go_bins = scan_go_tls();
    info!(count = go_bins.len(), "tap: Go TLS binaries discovered");

    // ─── Discover rustls binaries ────────────────────────────────────────
    let rs_bins = scan_rustls();
    info!(count = rs_bins.len(), "tap: rustls binaries discovered");

    // ─── Discover statically-linked BoringSSL binaries ───────────────────
    let bssl_bins = scan_boringssl_static();
    info!(count = bssl_bins.len(), "tap: BoringSSL static binaries discovered");

    if libs.is_empty() && go_bins.is_empty() && rs_bins.is_empty() && bssl_bins.is_empty() {
        info!("tap: no libssl / Go TLS / rustls / BoringSSL binaries found at startup; rescan loop will catch new pods");
        let (_, rx) = mpsc::channel(1);
        return Ok(TapHandle { events: rx, attached_libs: 0, attached_inodes });
    }

    let mut attached: usize = 0;

    // ─── Attach uprobes per unique libssl ────────────────────────────────
    for lib in &libs {
        let key = (lib.dev, lib.inode);
        if !attached_inodes.lock().unwrap().insert(key) {
            continue;
        }
        match attach_one(bpf, &lib.path) {
            Ok(()) => {
                attached += 1;
                record_attach_ok(status, "libssl");
                info!(path = %lib.path.display(), "tap: libssl uprobes attached");
            }
            Err(e) => {
                warn!(path = %lib.path.display(), error = %e, "tap: libssl uprobe attach failed");
                attached_inodes.lock().unwrap().remove(&key);
                record_attach_fail(status, "libssl", lib.path.clone(), e);
            }
        }
    }

    // ─── Attach Go TLS write probe per unique binary ─────────────────────
    for bin in &go_bins {
        let key = (bin.dev, bin.inode);
        if !attached_inodes.lock().unwrap().insert(key) {
            continue;
        }
        match attach_go_one(bpf, &bin.path) {
            Ok(()) => {
                attached += 1;
                record_attach_ok(status, "go");
                info!(path = %bin.path.display(), "tap: go_tls_write attached");
            }
            Err(e) => {
                warn!(path = %bin.path.display(), error = %e, "tap: go_tls_write attach failed");
                attached_inodes.lock().unwrap().remove(&key);
                record_attach_fail(status, "go", bin.path.clone(), e);
            }
        }
    }

    // ─── Attach rustls probes per unique binary ──────────────────────────
    for bin in &rs_bins {
        let key = (bin.dev, bin.inode);
        if !attached_inodes.lock().unwrap().insert(key) {
            continue;
        }
        match attach_rustls_one(bpf, bin) {
            Ok(()) => {
                attached += 1;
                record_attach_ok(status, "rustls");
                info!(path = %bin.path.display(), "tap: rustls uprobes attached");
            }
            Err(e) => {
                warn!(path = %bin.path.display(), error = %e, "tap: rustls uprobe attach failed");
                attached_inodes.lock().unwrap().remove(&key);
                record_attach_fail(status, "rustls", bin.path.clone(), e);
            }
        }
    }

    // ─── Attach BoringSSL static probes per unique binary ────────────────
    for bin in &bssl_bins {
        let key = (bin.dev, bin.inode);
        if !attached_inodes.lock().unwrap().insert(key) {
            continue;
        }
        match attach_boringssl_one(bpf, bin) {
            Ok(()) => {
                attached += 1;
                record_attach_ok(status, "boringssl_static");
                info!(path = %bin.path.display(), "tap: BoringSSL static uprobes attached");
            }
            Err(e) => {
                warn!(path = %bin.path.display(), error = %e, "tap: BoringSSL static uprobe attach failed");
                attached_inodes.lock().unwrap().remove(&key);
                record_attach_fail(status, "boringssl_static", bin.path.clone(), e);
            }
        }
    }

    // ─── Open perf event consumers ───────────────────────────────────────
    let (tx, rx) = mpsc::channel::<ObservedTap>(8192);

    let map = bpf
        .take_map("TAP_EVENTS")
        .context("TAP_EVENTS map not found in eBPF object")?;
    let mut perf: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map)?;

    let cpus = online_cpus().map_err(|(s, e)| anyhow::anyhow!("online_cpus({s}): {e}"))?;
    for cpu in cpus {
        let buf = perf
            .open(cpu, None)
            .with_context(|| format!("open perf buffer on cpu {cpu}"))?;
        let tx = tx.clone();
        tokio::spawn(consumer_loop(buf, tx, cpu));
    }

    Ok(TapHandle { events: rx, attached_libs: attached, attached_inodes })
}

/// Periodic re-scan loop. Owns `bpf` so it can attach uprobes to pods
/// that came up after `start()` ran. Skips files whose `(dev, inode)`
/// already lives in the shared `AttachedSet`.
///
/// Failure isolation: each tick body is wrapped in `catch_unwind`; a
/// panic in `rescan_once` (eBPF state corruption, /proc race, etc.)
/// gets logged + counted in `TapRescanStatus.panics` and the loop
/// keeps running. Without this, a single panic would silently kill
/// the rescan task and pods deployed afterwards would be invisible
/// until daemon restart — exactly the failure mode rescan was added
/// to fix.
pub fn spawn_rescan(
    mut bpf: Ebpf,
    attached: AttachedSet,
    status: TapStatusHandle,
    period: Duration,
) {
    {
        let mut s = status.lock().unwrap();
        s.rescan.enabled = true;
        s.rescan.period_secs = period.as_secs();
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        // First tick fires immediately; skip it — the initial scan
        // already covered what `start()` saw.
        tick.tick().await;
        info!(period_secs = period.as_secs(), "tap: rescan loop started");
        loop {
            tick.tick().await;
            // Run scans on the spawned task's blocking-friendly thread —
            // each scan_* opens hundreds of files.
            let result = tokio::task::block_in_place(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rescan_once(&mut bpf, &attached, &status)
                }))
            });
            match result {
                Ok(added) => {
                    let mut s = status.lock().unwrap();
                    s.rescan.ticks += 1;
                    s.rescan.last_tick_ts_us = crate::store::now_micros();
                    drop(s);
                    if added > 0 {
                        info!(added, "tap: rescan attached new probes");
                    } else {
                        debug!("tap: rescan found no new TLS binaries");
                    }
                }
                Err(_panic) => {
                    let mut s = status.lock().unwrap();
                    s.rescan.panics += 1;
                    s.rescan.ticks += 1;
                    s.rescan.last_tick_ts_us = crate::store::now_micros();
                    let total_panics = s.rescan.panics;
                    drop(s);
                    warn!(
                        total_panics,
                        "tap: rescan tick panicked; loop continuing (see TapStatus.rescan.panics in /api/status)"
                    );
                }
            }
        }
    });
}

fn rescan_once(bpf: &mut Ebpf, attached: &AttachedSet, status: &TapStatusHandle) -> usize {
    let mut added: usize = 0;

    for lib in scan_libssl() {
        let key = (lib.dev, lib.inode);
        if !attached.lock().unwrap().insert(key) {
            continue;
        }
        match attach_one(bpf, &lib.path) {
            Ok(()) => {
                info!(path = %lib.path.display(), "tap: rescan libssl attached");
                record_attach_ok(status, "libssl");
                added += 1;
            }
            Err(e) => {
                warn!(path = %lib.path.display(), error = %e, "tap: rescan libssl attach failed");
                attached.lock().unwrap().remove(&key);
                record_attach_fail(status, "libssl", lib.path.clone(), e);
            }
        }
    }

    for bin in scan_go_tls() {
        let key = (bin.dev, bin.inode);
        if !attached.lock().unwrap().insert(key) {
            continue;
        }
        match attach_go_one(bpf, &bin.path) {
            Ok(()) => {
                info!(path = %bin.path.display(), "tap: rescan go_tls_write attached");
                record_attach_ok(status, "go");
                added += 1;
            }
            Err(e) => {
                warn!(path = %bin.path.display(), error = %e, "tap: rescan go_tls attach failed");
                attached.lock().unwrap().remove(&key);
                record_attach_fail(status, "go", bin.path.clone(), e);
            }
        }
    }

    for bin in scan_rustls() {
        let key = (bin.dev, bin.inode);
        if !attached.lock().unwrap().insert(key) {
            continue;
        }
        match attach_rustls_one(bpf, &bin) {
            Ok(()) => {
                info!(path = %bin.path.display(), "tap: rescan rustls attached");
                record_attach_ok(status, "rustls");
                added += 1;
            }
            Err(e) => {
                warn!(path = %bin.path.display(), error = %e, "tap: rescan rustls attach failed");
                attached.lock().unwrap().remove(&key);
                record_attach_fail(status, "rustls", bin.path.clone(), e);
            }
        }
    }

    for bin in scan_boringssl_static() {
        let key = (bin.dev, bin.inode);
        if !attached.lock().unwrap().insert(key) {
            continue;
        }
        match attach_boringssl_one(bpf, &bin) {
            Ok(()) => {
                info!(path = %bin.path.display(), "tap: rescan BoringSSL static attached");
                record_attach_ok(status, "boringssl_static");
                added += 1;
            }
            Err(e) => {
                warn!(path = %bin.path.display(), error = %e, "tap: rescan BoringSSL attach failed");
                attached.lock().unwrap().remove(&key);
                record_attach_fail(status, "boringssl_static", bin.path.clone(), e);
            }
        }
    }

    added
}

/// Per-CPU perf event consumer. Decodes raw TapEvent bytes into ObservedTap
/// and forwards to the daemon via an mpsc channel. The channel can drop
/// events under backpressure (try_send) — the relay path stays unblocked.
async fn consumer_loop(
    mut buf: aya::maps::perf::AsyncPerfEventArrayBuffer<aya::maps::MapData>,
    tx: mpsc::Sender<ObservedTap>,
    cpu: u32,
) {
    // 16 buffers x event_size, enough headroom for bursty TLS reads.
    let event_size = std::mem::size_of::<TapEvent>();
    let mut bufs: Vec<BytesMut> = (0..16)
        .map(|_| BytesMut::with_capacity(event_size))
        .collect();

    loop {
        let events = match buf.read_events(&mut bufs).await {
            Ok(e) => e,
            Err(e) => {
                warn!(cpu, error = %e, "tap: perf buffer read error, exiting");
                return;
            }
        };
        if events.lost > 0 {
            warn!(cpu, lost = events.lost, "tap: perf buffer dropped events");
        }
        for slot in bufs.iter_mut().take(events.read) {
            if let Some(ev) = decode(slot) {
                let _ = tx.try_send(ev);
            }
        }
    }
}

fn decode(raw: &BytesMut) -> Option<ObservedTap> {
    if raw.len() < std::mem::size_of::<TapEvent>() {
        return None;
    }
    // Safe: TapEvent is #[repr(C)] of plain integers + a fixed-size byte
    // array, no padding-sensitive interpretation, and we just memcpy.
    let mut ev: TapEvent = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            raw.as_ptr(),
            (&mut ev as *mut TapEvent) as *mut u8,
            std::mem::size_of::<TapEvent>(),
        );
    }
    let dir = match ev.dir {
        0 => TapDir::Send,
        1 => TapDir::Recv,
        _ => return None,
    };
    let tgid = (ev.tgid_pid >> 32) as u32;
    let cap = ev.captured_len.min(TAP_DATA_LEN as u32) as usize;
    Some(ObservedTap {
        tgid,
        cgroup_id: ev.cgroup_id,
        dir,
        total_len: ev.total_len,
        captured: ev.data[..cap].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// libssl discovery — scan /proc/*/maps for unique inode mappings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LibImage {
    /// Host-visible path (e.g. /proc/<pid>/root/usr/lib/libssl.so.3) —
    /// works for processes in mount namespaces (containers).
    path: PathBuf,
    /// (dev, inode) for dedup; we keep one path per unique pair.
    #[allow(dead_code)]
    dev: u64,
    #[allow(dead_code)]
    inode: u64,
}

fn scan_libssl() -> Vec<LibImage> {
    let mut by_inode: StdHashMap<(u64, u64), LibImage> = StdHashMap::new();

    let entries = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "tap: cannot read /proc");
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        let maps_path = format!("/proc/{pid}/maps");
        let f = match File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => continue, // process gone or unreadable
        };

        // Use a per-pid set of paths we've already seen in *this* maps file
        // so we don't try to stat the same `r--p`/`r-xp` twice.
        let mut seen_in_pid: HashSet<String> = HashSet::new();

        for line in BufReader::new(f).lines().flatten() {
            // Format: addr_lo-addr_hi perms offset dev inode  pathname
            //   7f...000-7f...000 r-xp 00000000 fd:00 1234567 /usr/lib/libssl.so.3
            // We accept any executable-mapped libssl image; we'll attach
            // SSL_write/SSL_read symbols which live in .text anyway.
            let pathname_idx = match line.match_indices(' ').nth(5) {
                Some((i, _)) => i + 1,
                None => continue,
            };
            let pathname = line[pathname_idx..].trim();
            if pathname.is_empty() || !is_libssl(pathname) {
                continue;
            }
            if !seen_in_pid.insert(pathname.to_string()) {
                continue;
            }

            // Resolve via /proc/<pid>/root so we read the file as the
            // container sees it, not the host (paths can collide).
            let host_path = PathBuf::from(format!("/proc/{pid}/root{pathname}"));
            let meta = match fs::metadata(&host_path) {
                Ok(m) => m,
                Err(e) => {
                    debug!(path = %host_path.display(), error = %e, "tap: stat failed, skipping");
                    continue;
                }
            };
            let key = (meta.dev(), meta.ino());
            by_inode.entry(key).or_insert(LibImage {
                path: host_path,
                dev: meta.dev(),
                inode: meta.ino(),
            });
        }
    }

    by_inode.into_values().collect()
}

// ---------------------------------------------------------------------------
// Go TLS discovery — scan /proc/*/exe for Go binaries with crypto/tls
//
// Identification heuristic:
//   1. Walk /proc/<pid>/exe (resolved via /proc/<pid>/root for containers).
//   2. Dedup by inode.
//   3. ELF-parse the binary; require `.gopclntab` section to be present
//      (every Go binary has it; non-Go binaries don't).
//   4. Require the `crypto/tls.(*Conn).Write` symbol — many Go binaries
//      don't link the TLS package and we'd fail attach with a noisy error.
//
// We intentionally don't scan symbols on huge non-Go binaries (e.g. libffi,
// big C++ apps) — the .gopclntab gate skips them in milliseconds.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GoBinary {
    /// Host-visible path (/proc/<pid>/root/...) — works for containerized
    /// processes since the relay runs in the host mount namespace.
    path: PathBuf,
    /// `(dev, inode)` for `AttachedSet` dedup across rescan cycles.
    dev: u64,
    inode: u64,
}

fn scan_go_tls() -> Vec<GoBinary> {
    let mut by_inode: StdHashMap<(u64, u64), GoBinary> = StdHashMap::new();
    let mut tried = 0u32;
    let mut readlink_fail = 0u32;
    let mut metadata_fail = 0u32;
    let mut not_go = 0u32;

    let entries = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "tap: cannot read /proc for Go scan");
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        tried += 1;

        // Resolve the binary as the container sees it.
        let exe_link = format!("/proc/{pid}/exe");
        let exe_target = match fs::read_link(&exe_link) {
            Ok(t) => t,
            Err(_) => {
                readlink_fail += 1;
                continue;
            }
        };
        let exe_str = match exe_target.to_str() {
            Some(s) => s,
            None => continue,
        };
        let host_path = if exe_str.starts_with('/') {
            PathBuf::from(format!("/proc/{pid}/root{exe_str}"))
        } else {
            PathBuf::from(format!("/proc/{pid}/root/{exe_str}"))
        };

        let meta = match fs::metadata(&host_path) {
            Ok(m) => m,
            Err(_) => {
                metadata_fail += 1;
                continue; // not a file (kernel thread, etc.)
            }
        };
        let key = (meta.dev(), meta.ino());
        if by_inode.contains_key(&key) {
            continue;
        }

        // Cheap ELF probe: only inspect binaries that look like Go.
        if !is_go_binary_with_tls(&host_path).unwrap_or(false) {
            not_go += 1;
            continue;
        }

        by_inode.insert(key, GoBinary { path: host_path, dev: meta.dev(), inode: meta.ino() });
    }

    debug!(
        tried,
        readlink_fail,
        metadata_fail,
        not_go,
        unique_go = by_inode.len(),
        "tap: Go scan stats"
    );

    by_inode.into_values().collect()
}

/// Return true iff this ELF is a Go binary that links `crypto/tls`.
///
/// Stripped Go binaries (rancher, cilium, fleet — anything built with
/// `-ldflags="-s -w"`) have no ELF symbol table, so we can't use
/// `obj.symbols()` to check. Instead we do a two-stage probe:
///
///   1. `.gopclntab` section exists → Go binary.
///   2. `crypto::gosym::find_functions` resolves `crypto/tls.(*Conn).Write`
///      via the runtime's own symbol table inside `.gopclntab`.
///
/// Both stages are cheap on this codebase — gosym walks the function
/// table linearly with an early exit once the needle is found.
fn is_go_binary_with_tls(path: &Path) -> Result<bool> {
    if !crate::gosym::looks_like_go(path).unwrap_or(false) {
        return Ok(false);
    }
    let funcs =
        crate::gosym::find_functions(path, &["crypto/tls.(*Conn).Write"]).unwrap_or_default();
    Ok(funcs.contains_key("crypto/tls.(*Conn).Write"))
}

fn is_libssl(p: &str) -> bool {
    // Match `libssl.so`, `libssl.so.3`, `libssl.so.1.1`, etc. anywhere in
    // the path. We deliberately do not accept `libsslN.so` or musl variants
    // here — that's a future iteration.
    let fname = match Path::new(p).file_name().and_then(|s| s.to_str()) {
        Some(f) => f,
        None => return false,
    };
    fname == "libssl.so"
        || fname.starts_with("libssl.so.")
}

// ---------------------------------------------------------------------------
// Uprobe attach — wires our 3 BPF programs to one libssl image
// ---------------------------------------------------------------------------

fn attach_one(bpf: &mut Ebpf, target: &Path) -> Result<()> {
    // SSL_write — entry-only, captures plaintext send.
    // ProbeKind (uprobe vs uretprobe) is set by the eBPF section name,
    // which the `#[uprobe]` / `#[uretprobe]` attribute on the kernel
    // program already determines — no need to assert it here.
    {
        let prog: &mut UProbe = bpf
            .program_mut("ssl_write")
            .context("ssl_write program not found")?
            .try_into()?;
        // load() is a no-op the second time we hit it for the same program,
        // but we must call it at least once. Errors here usually mean
        // "already loaded", which is fine on per-image attach iterations.
        let _ = prog.load();
        prog.attach(Some("SSL_write"), 0, target, None)
            .with_context(|| format!("attach SSL_write at {}", target.display()))?;
    }

    // SSL_read — entry stashes buf pointer keyed by tgid_pid.
    {
        let prog: &mut UProbe = bpf
            .program_mut("ssl_read_enter")
            .context("ssl_read_enter program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(Some("SSL_read"), 0, target, None)
            .with_context(|| format!("attach SSL_read entry at {}", target.display()))?;
    }

    // SSL_read return — reads stash, copies `ret` bytes from buf, emits.
    {
        let prog: &mut UProbe = bpf
            .program_mut("ssl_read_exit")
            .context("ssl_read_exit program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(Some("SSL_read"), 0, target, None)
            .with_context(|| format!("attach SSL_read return at {}", target.display()))?;
    }

    Ok(())
}

/// Attach the Go TLS probes (write entry, read entry, read-at-RET) to
/// a single Go binary. Function locations come from `.gopclntab` via
/// `crate::gosym`, so this works equally well on stripped builds —
/// it doesn't depend on the ELF symbol table at all. RET sites for
/// Read are computed via iced-x86 disassembly because uretprobes
/// don't compose with Go's movable stacks.
fn attach_go_one(bpf: &mut Ebpf, target: &Path) -> Result<()> {
    let funcs = crate::gosym::find_functions(
        target,
        &[
            "crypto/tls.(*Conn).Write",
            "crypto/tls.(*Conn).Read",
        ],
    )
    .context("gosym lookup")?;

    let write_fn = funcs
        .get("crypto/tls.(*Conn).Write")
        .context("crypto/tls.(*Conn).Write not in .gopclntab")?;
    let read_fn = funcs
        .get("crypto/tls.(*Conn).Read")
        .context("crypto/tls.(*Conn).Read not in .gopclntab")?;

    // ─── crypto/tls.(*Conn).Write — entry only ──────────────────────────
    {
        let prog: &mut UProbe = bpf
            .program_mut("go_tls_write")
            .context("go_tls_write program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, write_fn.file_offset, target, None)
            .with_context(|| {
                format!(
                    "attach go_tls_write at {} offset {:#x}",
                    target.display(),
                    write_fn.file_offset
                )
            })?;
    }

    // ─── crypto/tls.(*Conn).Read — entry stash ──────────────────────────
    {
        let prog: &mut UProbe = bpf
            .program_mut("go_tls_read_enter")
            .context("go_tls_read_enter program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, read_fn.file_offset, target, None)
            .with_context(|| {
                format!(
                    "attach go_tls_read_enter at {} offset {:#x}",
                    target.display(),
                    read_fn.file_offset
                )
            })?;
    }

    // ─── crypto/tls.(*Conn).Read — every RET site ───────────────────────
    let rets = match find_go_ret_offsets(target, read_fn) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                path = %target.display(),
                error = %e,
                "tap: could not enumerate RET offsets; recv-side uprobe skipped"
            );
            return Ok(());
        }
    };
    if rets.is_empty() {
        warn!(
            path = %target.display(),
            "tap: 0 RET sites found in crypto/tls.(*Conn).Read; recv-side uprobe skipped"
        );
        return Ok(());
    }
    info!(path = %target.display(), ret_sites = rets.len(), "tap: Go Read RET sites found");

    let prog: &mut UProbe = bpf
        .program_mut("go_tls_read_ret")
        .context("go_tls_read_ret program not found")?
        .try_into()?;
    let _ = prog.load();
    let mut attached_rets = 0usize;
    for off in rets {
        match prog.attach(None, off, target, None) {
            Ok(_) => attached_rets += 1,
            Err(e) => {
                warn!(
                    path = %target.display(),
                    offset = format_args!("{:#x}", off),
                    error = %e,
                    "tap: go_tls_read_ret attach failed at offset"
                );
            }
        }
    }
    if attached_rets == 0 {
        warn!(path = %target.display(), "tap: 0/N RET attachments succeeded for Read");
    }
    Ok(())
}

/// Disassemble the named function's body and return the file offset
/// of every RET instruction. Uses iced-x86's `FlowControl::Return`
/// classification, which covers near-RET, near-RET-imm16, far-RET,
/// and IRET in one shot.
fn find_go_ret_offsets(
    path: &Path,
    func: &crate::gosym::FuncLocation,
) -> Result<Vec<u64>> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};
    use object::{Object, ObjectSection};

    if func.size == 0 {
        return Ok(Vec::new());
    }

    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let obj = object::read::File::parse(&*data)
        .map_err(|e| anyhow::anyhow!("ELF parse: {e}"))?;
    let text = obj
        .section_by_name(".text")
        .context(".text section not found")?;
    let text_addr = text.address();
    let text_data = text
        .data()
        .map_err(|e| anyhow::anyhow!("section data: {e}"))?;

    let func_off_in_text = func
        .vaddr
        .checked_sub(text_addr)
        .ok_or_else(|| anyhow::anyhow!("vaddr below .text base"))?
        as usize;
    let end = func_off_in_text
        .checked_add(func.size as usize)
        .ok_or_else(|| anyhow::anyhow!("func size overflow"))?;
    if end > text_data.len() {
        anyhow::bail!(
            "func body [{func_off_in_text}..{end}] exceeds .text data ({})",
            text_data.len()
        );
    }

    let bytes = &text_data[func_off_in_text..end];
    let mut decoder = Decoder::with_ip(64, bytes, func.vaddr, DecoderOptions::NONE);
    let mut rets = Vec::new();
    while decoder.can_decode() {
        let pos_in_func = decoder.position();
        let insn = decoder.decode();
        if matches!(insn.flow_control(), FlowControl::Return) {
            rets.push(func.file_offset + pos_in_func as u64);
        }
    }
    Ok(rets)
}

// ---------------------------------------------------------------------------
// rustls discovery — scan /proc/*/exe for binaries that link rustls
//
// Identification: a Rust binary that contains the canonical mangled
// symbol prefix for `<rustls::conn::ConnectionCommon<T> as
// rustls::conn::connection::PlaintextSink>::write`.
//
// Caveats:
//
//  * Stripped Rust binaries lose `.symtab` so we can't find these —
//    there's no `.gopclntab` equivalent. In practice most Rust
//    release binaries on this cluster ship with full symbols, since
//    stripping is opt-in (not cargo's default).
//
//  * The presence of the symbol does NOT guarantee the binary
//    actively calls it. ClickHouse for instance links rustls (some
//    optional dependency pulls it in) but its production TLS path
//    statically links OpenSSL and never reaches the rustls code —
//    `objdump` finds zero direct call sites for the symbol. Our
//    attach succeeds in both cases; whether tap events fire depends
//    on runtime usage.
//
//  * The current Rust SysV ABI assumption (`buf` in RSI/RDX,
//    `Result<usize, io::Error>` in RAX/RDX) was reverse-engineered
//    from typical compiled output and may need updating if the
//    compiler ever switches to a niche-packed layout for this
//    Result type.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RustlsBinary {
    path: PathBuf,
    /// File offset of `<...PlaintextSink>::write` (entry).
    write_offset: u64,
    /// File offset of `<...Reader as std::io::Read>::read` (entry).
    /// None when the build inlined this away (some binaries do).
    read_offset: Option<u64>,
    /// `(dev, inode)` for `AttachedSet` dedup across rescan cycles.
    dev: u64,
    inode: u64,
}

fn scan_rustls() -> Vec<RustlsBinary> {
    let mut by_inode: StdHashMap<(u64, u64), RustlsBinary> = StdHashMap::new();

    let entries = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "tap: cannot read /proc for rustls scan");
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        let exe_link = format!("/proc/{pid}/exe");
        let exe_target = match fs::read_link(&exe_link) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let exe_str = match exe_target.to_str() {
            Some(s) => s,
            None => continue,
        };
        let host_path = if exe_str.starts_with('/') {
            PathBuf::from(format!("/proc/{pid}/root{exe_str}"))
        } else {
            PathBuf::from(format!("/proc/{pid}/root/{exe_str}"))
        };

        let meta = match fs::metadata(&host_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let key = (meta.dev(), meta.ino());
        if by_inode.contains_key(&key) {
            continue;
        }

        match find_rustls_offsets(&host_path) {
            Ok(Some(mut rb)) => {
                rb.dev = meta.dev();
                rb.inode = meta.ino();
                by_inode.insert(key, rb);
            }
            Ok(None) => {} // Not a rustls binary; ignore.
            Err(e) => {
                debug!(path = %host_path.display(), error = %e, "tap: rustls scan failed");
            }
        }
    }

    by_inode.into_values().collect()
}

/// Inspect an ELF symtab for the canonical rustls plaintext-API
/// symbols and return their file offsets.
///
/// Substring-tuple match (Coroot's approach), more robust than the
/// exact mangled patterns we used to grep for:
///
///   write: name contains "rustls" + ("Writer" OR "PlaintextSink") + "write"
///   read:  name contains "rustls" + "Reader" + "read"
///
/// Why both `Writer` and `PlaintextSink`:
///   - rustls 0.21 and earlier: write goes through the `PlaintextSink`
///     trait (`<...PlaintextSink>::write`).
///   - rustls 0.22+: `PlaintextSink` is gone; write goes through
///     `<rustls::common_state::Writer<'_, ...> as std::io::Write>::write`.
/// Heimdall's own kube-rs client and ClickHouse still link 0.21-style
/// rustls; Deno alpine ships 0.23. Matching both terms covers both eras
/// without needing version-specific patterns.
///
/// `read_to_end` / `write_vectored` etc. are excluded so we don't pick
/// the wrong overload as the canonical entry.
fn find_rustls_offsets(path: &Path) -> Result<Option<RustlsBinary>> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let data = fs::read(path)?;
    let obj = match object::read::File::parse(&*data) {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };

    // Helper: does `name` look like a rustls write entry?
    let is_rustls_write = |name: &str| -> bool {
        name.contains("rustls")
            && (name.contains("Writer") || name.contains("PlaintextSink"))
            && name.contains("write")
            && !name.contains("write_vectored")
            && !name.contains("write_all")
            && !name.contains("write_fmt")
            && !name.contains("write_str")
    };

    // Helper: does `name` look like a rustls read entry?
    let is_rustls_read = |name: &str| -> bool {
        name.contains("rustls")
            && name.contains("Reader")
            && name.contains("read")
            && !name.contains("read_to_end")
            && !name.contains("read_to_string")
            && !name.contains("read_exact")
            && !name.contains("read_buf")
            && !name.contains("read_vectored")
    };

    let mut write_addr: Option<(u64, object::SectionIndex)> = None;
    let mut read_addr: Option<(u64, object::SectionIndex)> = None;

    for sym in obj.symbols() {
        let name = match sym.name() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if write_addr.is_none() && is_rustls_write(name) {
            if let Some(idx) = sym.section_index() {
                write_addr = Some((sym.address(), idx));
            }
        } else if read_addr.is_none() && is_rustls_read(name) {
            if let Some(idx) = sym.section_index() {
                read_addr = Some((sym.address(), idx));
            }
        }
        if write_addr.is_some() && read_addr.is_some() {
            break;
        }
    }

    let (write_vaddr, write_section) = match write_addr {
        Some(v) => v,
        None => return Ok(None), // Not a rustls binary, or symbols stripped.
    };

    let to_file_offset = |vaddr: u64, sec_idx: object::SectionIndex| -> Result<u64> {
        let section = obj
            .section_by_index(sec_idx)
            .map_err(|e| anyhow::anyhow!("section_by_index: {e}"))?;
        let section_addr = section.address();
        let (sec_file_off, _) = section
            .file_range()
            .ok_or_else(|| anyhow::anyhow!("section has no file range"))?;
        vaddr
            .checked_sub(section_addr)
            .map(|d| sec_file_off + d)
            .ok_or_else(|| anyhow::anyhow!("vaddr below section base"))
    };

    let write_offset = to_file_offset(write_vaddr, write_section)?;
    let read_offset = match read_addr {
        Some((vaddr, sec)) => Some(to_file_offset(vaddr, sec)?),
        None => None,
    };

    Ok(Some(RustlsBinary {
        path: path.to_path_buf(),
        write_offset,
        read_offset,
        // Filled in by the caller (`scan_rustls`) which already has
        // the cached `(dev, inode)` from the /proc walk.
        dev: 0,
        inode: 0,
    }))
}

/// Attach the three rustls probes (write entry, read entry,
/// read return) to a single binary using gosym-style file offsets.
///
/// Rust supports kernel uretprobes (no movable stacks), so the read
/// side uses an actual `#[uretprobe]` rather than the Go RET-offset
/// trick.
fn attach_rustls_one(bpf: &mut Ebpf, bin: &RustlsBinary) -> Result<()> {
    use aya::programs::UProbe;

    {
        let prog: &mut UProbe = bpf
            .program_mut("rustls_write")
            .context("rustls_write program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, bin.write_offset, &bin.path, None)
            .with_context(|| format!("attach rustls_write at {} offset {:#x}",
                bin.path.display(), bin.write_offset))?;
    }

    let read_off = match bin.read_offset {
        Some(o) => o,
        None => {
            warn!(
                path = %bin.path.display(),
                "tap: rustls Read::read symbol absent (likely inlined); recv-side skipped"
            );
            return Ok(());
        }
    };

    {
        let prog: &mut UProbe = bpf
            .program_mut("rustls_read_enter")
            .context("rustls_read_enter program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, read_off, &bin.path, None)
            .with_context(|| format!("attach rustls_read_enter at {} offset {:#x}",
                bin.path.display(), read_off))?;
    }

    {
        let prog: &mut UProbe = bpf
            .program_mut("rustls_read_exit")
            .context("rustls_read_exit program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, read_off, &bin.path, None)
            .with_context(|| format!("attach rustls_read_exit at {} offset {:#x}",
                bin.path.display(), read_off))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// BoringSSL static discovery — scan /proc/*/exe for binaries that
// statically link BoringSSL.
//
// BoringSSL preserves the OpenSSL C ABI: `int SSL_write(SSL*, void*, int)`
// and `int SSL_read(SSL*, void*, int)`. The libssl uprobes (`ssl_write`,
// `ssl_read_enter`, `ssl_read_exit`) attach unchanged — this scanner only
// does the user-space half: detect a static-linked BoringSSL image and
// resolve file offsets for the two symbols.
//
// Identification (two cheap stages):
//
//  1. Marker bytes. The literal "BoringSSL" appears in the
//     `OPENSSL_VERSION_TEXT` constant and several internal error strings,
//     all of which end up in `.rodata`. A static-linked BoringSSL build
//     contains the bytes; vendored OpenSSL or no SSL at all does not.
//     We restrict the search to `.rodata` to keep the scan O(rodata-size)
//     rather than O(binary-size).
//
//  2. Symbol lookup in `.symtab` then `.dynsym` for `SSL_write` and
//     `SSL_read`. Static linkage doesn't normally export these to
//     `.dynsym` (LTO keeps them internal), but `.symtab` survives unless
//     the binary was explicitly stripped.
//
// Caveats:
//
//  * Stripped binaries (`strip --strip-all` or `-Wl,-s`) lose both
//    symbol tables; this scanner returns None for them. Recovery
//    requires byte-pattern matching the function prologue (the
//    Pixie / Stirling approach) — deferred until we have a stripped
//    BoringSSL workload to validate signatures against.
//
//  * LTO can inline `SSL_write` / `SSL_read` into a single caller; the
//    symbol then either disappears or points at code that is no longer
//    the canonical entry. We attach blindly; non-firing is a silent
//    failure mode, same as rustls.
//
//  * The marker check excludes statically-linked non-BoringSSL OpenSSL
//    by design. If you want to capture those too, relax the marker —
//    expect more false positives without it.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct BoringSSLBinary {
    path: PathBuf,
    /// File offset of `SSL_write` in the binary.
    write_offset: u64,
    /// File offset of `SSL_read` in the binary.
    read_offset: u64,
    /// `(dev, inode)` for `AttachedSet` dedup across rescan cycles.
    dev: u64,
    inode: u64,
}

fn scan_boringssl_static() -> Vec<BoringSSLBinary> {
    let mut by_inode: StdHashMap<(u64, u64), BoringSSLBinary> = StdHashMap::new();

    let entries = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "tap: cannot read /proc for BoringSSL scan");
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        let exe_link = format!("/proc/{pid}/exe");
        let exe_target = match fs::read_link(&exe_link) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let exe_str = match exe_target.to_str() {
            Some(s) => s,
            None => continue,
        };
        let host_path = if exe_str.starts_with('/') {
            PathBuf::from(format!("/proc/{pid}/root{exe_str}"))
        } else {
            PathBuf::from(format!("/proc/{pid}/root/{exe_str}"))
        };

        let meta = match fs::metadata(&host_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let key = (meta.dev(), meta.ino());
        if by_inode.contains_key(&key) {
            continue;
        }

        match find_boringssl_offsets(&host_path) {
            Ok(Some(mut b)) => {
                b.dev = meta.dev();
                b.inode = meta.ino();
                by_inode.insert(key, b);
            }
            Ok(None) => {} // Not a static-linked BoringSSL binary.
            Err(e) => {
                debug!(path = %host_path.display(), error = %e, "tap: BoringSSL scan failed");
            }
        }
    }

    by_inode.into_values().collect()
}

/// Two-stage check: marker bytes in `.rodata`, then symbol lookup in
/// `.symtab` and `.dynsym`. Returns `Ok(None)` for binaries that are
/// not static-linked BoringSSL or whose symbol tables have been
/// stripped — neither is an error.
fn find_boringssl_offsets(path: &Path) -> Result<Option<BoringSSLBinary>> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let data = fs::read(path)?;
    let obj = match object::read::File::parse(&*data) {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };

    // Stage 1: marker bytes in .rodata. Scan only this section to keep
    // the cost bounded; .rodata is usually a few MB even on large
    // binaries, vs hundreds of MB for the full file.
    let rodata = match obj.section_by_name(".rodata") {
        Some(s) => s,
        None => return Ok(None),
    };
    let rodata_bytes = match rodata.data() {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    if !contains_subseq(rodata_bytes, b"BoringSSL") {
        return Ok(None);
    }

    // Stage 2: SSL_write / SSL_read in .symtab, falling back to .dynsym.
    let mut write_addr: Option<(u64, object::SectionIndex)> = None;
    let mut read_addr: Option<(u64, object::SectionIndex)> = None;

    for sym in obj.symbols() {
        let name = match sym.name() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name == "SSL_write" && write_addr.is_none() {
            if let Some(idx) = sym.section_index() {
                write_addr = Some((sym.address(), idx));
            }
        } else if name == "SSL_read" && read_addr.is_none() {
            if let Some(idx) = sym.section_index() {
                read_addr = Some((sym.address(), idx));
            }
        }
        if write_addr.is_some() && read_addr.is_some() {
            break;
        }
    }
    if write_addr.is_none() || read_addr.is_none() {
        for sym in obj.dynamic_symbols() {
            let name = match sym.name() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if name == "SSL_write" && write_addr.is_none() {
                if let Some(idx) = sym.section_index() {
                    write_addr = Some((sym.address(), idx));
                }
            } else if name == "SSL_read" && read_addr.is_none() {
                if let Some(idx) = sym.section_index() {
                    read_addr = Some((sym.address(), idx));
                }
            }
            if write_addr.is_some() && read_addr.is_some() {
                break;
            }
        }
    }

    let (write_vaddr, write_section) = match write_addr {
        Some(v) => v,
        None => return Ok(None),
    };
    let (read_vaddr, read_section) = match read_addr {
        Some(v) => v,
        None => return Ok(None),
    };

    let to_file_offset = |vaddr: u64, sec_idx: object::SectionIndex| -> Result<u64> {
        let section = obj
            .section_by_index(sec_idx)
            .map_err(|e| anyhow::anyhow!("section_by_index: {e}"))?;
        let section_addr = section.address();
        let (sec_file_off, _) = section
            .file_range()
            .ok_or_else(|| anyhow::anyhow!("section has no file range"))?;
        vaddr
            .checked_sub(section_addr)
            .map(|d| sec_file_off + d)
            .ok_or_else(|| anyhow::anyhow!("vaddr below section base"))
    };

    Ok(Some(BoringSSLBinary {
        path: path.to_path_buf(),
        write_offset: to_file_offset(write_vaddr, write_section)?,
        read_offset: to_file_offset(read_vaddr, read_section)?,
        // Filled in by the caller (`scan_boringssl_static`) which has
        // the cached `(dev, inode)` from the /proc walk.
        dev: 0,
        inode: 0,
    }))
}

/// Naive substring search. Avoids pulling in `memchr` for one call
/// site; the haystack is a single `.rodata` section, typically a few
/// MB, which `windows().any()` chews through in a few ms in release
/// mode (Boyer-Moore-style autovectorization on `==`).
fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Attach the libssl-style probes (write entry, read entry, read return)
/// to a BoringSSL static binary at file offsets resolved by the scanner.
/// Reuses the same eBPF programs as `attach_one` for libssl images,
/// since BoringSSL preserves the OpenSSL C ABI.
fn attach_boringssl_one(bpf: &mut Ebpf, bin: &BoringSSLBinary) -> Result<()> {
    {
        let prog: &mut UProbe = bpf
            .program_mut("ssl_write")
            .context("ssl_write program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, bin.write_offset, &bin.path, None)
            .with_context(|| format!(
                "attach BoringSSL SSL_write at {} offset {:#x}",
                bin.path.display(), bin.write_offset))?;
    }
    {
        let prog: &mut UProbe = bpf
            .program_mut("ssl_read_enter")
            .context("ssl_read_enter program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, bin.read_offset, &bin.path, None)
            .with_context(|| format!(
                "attach BoringSSL SSL_read entry at {} offset {:#x}",
                bin.path.display(), bin.read_offset))?;
    }
    {
        let prog: &mut UProbe = bpf
            .program_mut("ssl_read_exit")
            .context("ssl_read_exit program not found")?
            .try_into()?;
        let _ = prog.load();
        prog.attach(None, bin.read_offset, &bin.path, None)
            .with_context(|| format!(
                "attach BoringSSL SSL_read return at {} offset {:#x}",
                bin.path.display(), bin.read_offset))?;
    }
    Ok(())
}

/// Convenience: spawn a logger task that drains a TapHandle and writes
/// each event to the tracing journal at INFO level. Used during
/// development to confirm uprobes are firing without persisting.
pub fn spawn_journal_logger(mut handle: TapHandle) {
    tokio::spawn(async move {
        info!(attached_libs = handle.attached_libs, "tap: journal logger started");
        while let Some(ev) = handle.events.recv().await {
            let preview = String::from_utf8_lossy(
                &ev.captured[..ev.captured.len().min(96)],
            )
            .replace('\n', "\\n")
            .replace('\r', "\\r");
            let dir = match ev.dir {
                TapDir::Send => "SEND",
                TapDir::Recv => "RECV",
            };
            info!(
                "tap[{} cg={} tgid={} total={} cap={}]: {}",
                dir, ev.cgroup_id, ev.tgid, ev.total_len, ev.captured.len(), preview
            );
        }
        warn!("tap: journal logger stopped (channel closed)");
    });
}

/// Drain a TapHandle into the sqlite store. Each event becomes a row in
/// `messages`. The provided `correlate` closure resolves cgroup_id to a
/// flow_id for the open-flow index (NULL when nothing matches).
///
/// Insertion is best-effort: errors are logged and the loop continues —
/// a transient sqlite error must not stall the perf consumers (which
/// would back up the kernel ring buffer).
pub fn spawn_store_writer<F>(
    mut handle: TapHandle,
    store: std::sync::Arc<crate::store::Store>,
    correlate: F,
)
where
    F: Fn(u64) -> Option<i64> + Send + Sync + 'static,
{
    tokio::spawn(async move {
        info!(
            attached_libs = handle.attached_libs,
            "tap: store writer started (messages will persist)"
        );
        // Use SystemTime at message-receive time. The eBPF ev.ts_ns is
        // monotonic kernel time and does not match wall-clock ts_us
        // used in the flows table; we'd need a kallsyms-style offset to
        // convert. For now, "wall clock at userspace dequeue" is good
        // enough for ordering within a flow — events arrive < 10ms
        // after the syscall.
        while let Some(ev) = handle.events.recv().await {
            let flow_id = correlate(ev.cgroup_id);
            let msg = crate::store::InsertMessage {
                flow_id,
                ts_us: crate::store::now_micros(),
                cgroup_id: ev.cgroup_id as i64,
                tgid: ev.tgid as i64,
                dir: match ev.dir {
                    TapDir::Send => 0,
                    TapDir::Recv => 1,
                },
                total_len: ev.total_len as i64,
                body: ev.captured,
            };
            if let Err(e) = store.insert_message(msg).await {
                warn!(error = %e, "tap: insert_message failed");
            }
        }
        warn!("tap: store writer stopped (channel closed)");
    });
}
