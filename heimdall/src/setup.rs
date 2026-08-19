//! Narrow protocol between `heimdall run` and its privileged setup worker.

use std::{
    io::{IoSlice, IoSliceMut, Read, Write},
    os::fd::{BorrowedFd, OwnedFd},
    os::unix::net::UnixStream,
    path::{Component, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::{Context, Result};
use aya::maps::{HashMap, Map, MapData};
use heimdall_common::OrigDst;
use heimdall_common::{
    POLICY_DNS_HIJACK, POLICY_DNS_SYSTEM, POLICY_REDIRECT_OFF, POLICY_UDP_REJECT,
};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const CONTRACT: &str = "heimdall.setup/v2";
const MAX_FRAME_BYTES: usize = 64 * 1024;
// Linux permits at most 253 descriptors in one SCM_RIGHTS message. Keep room
// for transport details while supporting hosts with large CPU sets.
const MAX_FDS: usize = 240;
const RIGHTS_MARKER: &[u8] = b"F";
const KNOWN_POLICY_FLAGS: u8 =
    POLICY_REDIRECT_OFF | POLICY_DNS_HIJACK | POLICY_UDP_REJECT | POLICY_DNS_SYSTEM;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupRequest {
    contract: String,
    cgroup_path: PathBuf,
    cgroup_id: u64,
    relay_port: u16,
    dns_port: u16,
    policy_flags: u8,
    runtime_tls: bool,
}

impl SetupRequest {
    pub(crate) fn new(
        cgroup_path: PathBuf,
        cgroup_id: u64,
        relay_port: u16,
        dns_port: u16,
        policy_flags: u8,
        runtime_tls: bool,
    ) -> Result<Self> {
        let request = Self {
            contract: CONTRACT.to_owned(),
            cgroup_path,
            cgroup_id,
            relay_port,
            dns_port,
            policy_flags,
            runtime_tls,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.contract == CONTRACT, "unsupported setup contract");
        anyhow::ensure!(self.cgroup_id != 0, "setup cgroup ID must be non-zero");
        anyhow::ensure!(self.relay_port != 0, "setup relay port must be non-zero");
        anyhow::ensure!(self.dns_port != 0, "setup DNS port must be non-zero");
        anyhow::ensure!(
            self.policy_flags & !KNOWN_POLICY_FLAGS == 0,
            "setup policy contains unknown flags"
        );
        anyhow::ensure!(
            self.cgroup_path.starts_with("/sys/fs/cgroup/"),
            "setup cgroup must be below /sys/fs/cgroup"
        );
        anyhow::ensure!(
            !self
                .cgroup_path
                .components()
                .any(|component| matches!(component, Component::ParentDir)),
            "setup cgroup path must not contain parent traversal"
        );
        Ok(())
    }

    pub(crate) fn cgroup_path(&self) -> &std::path::Path {
        &self.cgroup_path
    }

    pub(crate) const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) const fn relay_port(&self) -> u16 {
        self.relay_port
    }

    pub(crate) const fn dns_port(&self) -> u16 {
        self.dns_port
    }

    pub(crate) const fn policy_flags(&self) -> u8 {
        self.policy_flags
    }

    pub(crate) const fn runtime_tls(&self) -> bool {
        self.runtime_tls
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupFd {
    PortMap,
    UdpPortMap,
    UdpTokenMap,
    UdpCookieMap,
    Connect4Link,
    Connect6Link,
    Getpeername4Link,
    Getpeername6Link,
    Udp4SendmsgLink,
    Udp6SendmsgLink,
    Udp6BindLink,
    Udp4RecvmsgLink,
    Udp6RecvmsgLink,
    SockReleaseLink,
    SkbEgressLink,
    RuntimeTlsLink,
    RuntimePerfBuffer,
}

pub(crate) const FD_MANIFEST: [SetupFd; 15] = [
    SetupFd::PortMap,
    SetupFd::UdpPortMap,
    SetupFd::UdpTokenMap,
    SetupFd::UdpCookieMap,
    SetupFd::Connect4Link,
    SetupFd::Connect6Link,
    SetupFd::Getpeername4Link,
    SetupFd::Getpeername6Link,
    SetupFd::Udp4SendmsgLink,
    SetupFd::Udp6SendmsgLink,
    SetupFd::Udp6BindLink,
    SetupFd::Udp4RecvmsgLink,
    SetupFd::Udp6RecvmsgLink,
    SetupFd::SockReleaseLink,
    SetupFd::SkbEgressLink,
];

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum SetupReply {
    Ready {
        contract: String,
        fds: Vec<SetupFd>,
        runtime: Option<crate::tls_runtime::StartReport>,
    },
    Error {
        contract: String,
        code: String,
        message: String,
    },
}

pub(crate) struct SetupBundle {
    pub(crate) fds: Vec<(SetupFd, OwnedFd)>,
    pub(crate) runtime: Option<crate::tls_runtime::StartReport>,
    worker: Option<SetupWorker>,
}

pub(crate) struct SetupWorker {
    socket: Option<UnixStream>,
    child: Option<Child>,
}

impl SetupWorker {
    pub(crate) fn shutdown(mut self) -> Result<()> {
        if let Some(mut socket) = self.socket.take() {
            socket
                .write_all(b"G")
                .context("mark graceful setup helper shutdown")?;
        }
        let status = self
            .child
            .take()
            .context("setup helper is already reaped")?
            .wait()
            .context("wait for setup helper")?;
        anyhow::ensure!(status.success(), "setup helper exited with {status}");
        Ok(())
    }
}

impl Drop for SetupWorker {
    fn drop(&mut self) {
        self.socket.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

pub(crate) struct RuntimeFds {
    pub(crate) port_map: HashMap<MapData, u32, OrigDst>,
    pub(crate) udp_port_map: HashMap<MapData, u32, OrigDst>,
    pub(crate) udp_token_map: HashMap<MapData, u32, OrigDst>,
    pub(crate) udp_cookie_map: HashMap<MapData, u64, OrigDst>,
    pub(crate) links: Vec<OwnedFd>,
    pub(crate) runtime_buffers: Vec<(u32, OwnedFd)>,
    pub(crate) runtime: Option<crate::tls_runtime::StartReport>,
    pub(crate) worker: Option<SetupWorker>,
}

impl SetupBundle {
    pub(crate) fn into_runtime_fds(self) -> Result<RuntimeFds> {
        let Self {
            fds,
            runtime,
            worker,
        } = self;
        let mut fds = fds.into_iter();
        let port_map = take_map(&mut fds, SetupFd::PortMap)?;
        let udp_port_map = take_map(&mut fds, SetupFd::UdpPortMap)?;
        let udp_token_map = take_map(&mut fds, SetupFd::UdpTokenMap)?;
        let udp_cookie_map = take_map(&mut fds, SetupFd::UdpCookieMap)?;
        let mut links = Vec::new();
        for _ in 0..FD_MANIFEST.len() - 4 {
            let (_, fd) = fds.next().context("setup bundle is missing a link FD")?;
            links.push(fd);
        }
        let mut runtime_buffers = Vec::new();
        if let Some(report) = runtime.as_ref() {
            for _ in 0..report.attached_links {
                let (kind, fd) = fds
                    .next()
                    .context("setup bundle is missing a runtime TLS link FD")?;
                anyhow::ensure!(
                    kind == SetupFd::RuntimeTlsLink,
                    "setup runtime link order changed"
                );
                links.push(fd);
            }
            for &cpu in &report.perf_cpus {
                let (kind, fd) = fds
                    .next()
                    .context("setup bundle is missing a runtime perf buffer FD")?;
                anyhow::ensure!(
                    kind == SetupFd::RuntimePerfBuffer,
                    "setup runtime perf buffer order changed"
                );
                runtime_buffers.push((cpu, fd));
            }
        }
        anyhow::ensure!(fds.next().is_none(), "setup bundle contains trailing FDs");
        Ok(RuntimeFds {
            port_map: HashMap::try_from(Map::from_map_data(MapData::from_fd(port_map)?)?)?,
            udp_port_map: HashMap::try_from(Map::from_map_data(MapData::from_fd(udp_port_map)?)?)?,
            udp_token_map: HashMap::try_from(Map::from_map_data(MapData::from_fd(
                udp_token_map,
            )?)?)?,
            udp_cookie_map: HashMap::try_from(Map::from_map_data(MapData::from_fd(
                udp_cookie_map,
            )?)?)?,
            links,
            runtime_buffers,
            runtime,
            worker,
        })
    }
}

fn take_map(
    fds: &mut impl Iterator<Item = (SetupFd, OwnedFd)>,
    expected: SetupFd,
) -> Result<OwnedFd> {
    let (kind, fd) = fds.next().context("setup bundle is missing a map FD")?;
    anyhow::ensure!(kind == expected, "setup map FD order changed");
    Ok(fd)
}

pub(crate) fn send_request(stream: &mut UnixStream, request: &SetupRequest) -> Result<()> {
    request.validate()?;
    send_frame(stream, request)
}

pub(crate) fn receive_request(stream: &mut UnixStream) -> Result<SetupRequest> {
    let request: SetupRequest = receive_frame(stream)?;
    request.validate()?;
    Ok(request)
}

pub(crate) fn send_ready(
    stream: &mut UnixStream,
    manifest: Vec<SetupFd>,
    runtime: Option<crate::tls_runtime::StartReport>,
    fds: &[BorrowedFd<'_>],
) -> Result<()> {
    anyhow::ensure!(
        fds.len() == manifest.len(),
        "setup worker produced {} FDs, manifest has {}",
        fds.len(),
        manifest.len()
    );
    validate_manifest(&manifest, runtime.as_ref())?;
    send_frame(
        stream,
        &SetupReply::Ready {
            contract: CONTRACT.to_owned(),
            fds: manifest,
            runtime,
        },
    )?;
    send_rights(stream, fds)
}

pub(crate) fn send_error(stream: &mut UnixStream, code: &str, message: &str) -> Result<()> {
    send_frame(
        stream,
        &SetupReply::Error {
            contract: CONTRACT.to_owned(),
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
}

pub(crate) fn receive_reply(stream: &mut UnixStream) -> Result<SetupBundle> {
    match receive_frame::<SetupReply>(stream)? {
        SetupReply::Ready {
            contract,
            fds,
            runtime,
        } => {
            anyhow::ensure!(contract == CONTRACT, "unsupported setup reply contract");
            validate_manifest(&fds, runtime.as_ref())?;
            let owned = receive_rights(stream, fds.len())?;
            Ok(SetupBundle {
                fds: fds.into_iter().zip(owned).collect(),
                runtime,
                worker: None,
            })
        }
        SetupReply::Error {
            contract,
            code,
            message,
        } => {
            anyhow::ensure!(contract == CONTRACT, "unsupported setup reply contract");
            anyhow::bail!("setup worker failed ({code}): {message}")
        }
    }
}

pub(crate) fn launch_worker(request: &SetupRequest) -> Result<SetupBundle> {
    request.validate()?;
    let (mut parent, child_socket) = UnixStream::pair().context("create setup socketpair")?;
    parent
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .context("bound setup worker response time")?;
    let executable = std::env::current_exe().context("resolve heimdall executable")?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(&executable)
    } else {
        let mut command = Command::new("sudo");
        command.args(["--non-interactive", "--"]).arg(&executable);
        command
    };
    command
        .arg("__setup-worker")
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().context("start privileged setup worker")?;
    // Why: Command remains reusable after spawn and therefore retains its
    // configured stdin FD. Close that duplicate now so an authorization or
    // exec failure is observed as immediate EOF instead of the read timeout.
    drop(command);

    let exchange = send_request(&mut parent, request).and_then(|()| receive_reply(&mut parent));
    let mut bundle = match exchange {
        Ok(bundle) => bundle,
        Err(error) => {
            drop(parent);
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).with_context(|| {
                format!(
                    "setup worker did not return a session bundle; non-interactive setup authorization must allow exactly `{} __setup-worker`",
                    executable.display()
                )
            });
        }
    };
    parent
        .set_read_timeout(None)
        .context("clear setup helper response timeout")?;
    bundle.worker = Some(SetupWorker {
        socket: Some(parent),
        child: Some(child),
    });
    Ok(bundle)
}

fn send_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encode setup protocol frame")?;
    anyhow::ensure!(
        bytes.len() <= MAX_FRAME_BYTES,
        "setup protocol frame exceeds {MAX_FRAME_BYTES} bytes"
    );
    let length = u32::try_from(bytes.len()).context("setup frame length exceeds u32")?;
    stream
        .write_all(&length.to_be_bytes())
        .context("write setup frame length")?;
    stream
        .write_all(&bytes)
        .context("write setup frame payload")?;
    Ok(())
}

fn receive_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .context("read setup frame length")?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    anyhow::ensure!(
        length <= MAX_FRAME_BYTES,
        "setup protocol frame exceeds {MAX_FRAME_BYTES} bytes"
    );
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .context("read setup frame payload")?;
    serde_json::from_slice(&bytes).context("decode setup protocol frame")
}

fn send_rights(stream: &UnixStream, fds: &[BorrowedFd<'_>]) -> Result<()> {
    anyhow::ensure!(fds.len() <= MAX_FDS, "setup FD count exceeds {MAX_FDS}");
    let mut control_bytes = [0_u8; rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut control = SendAncillaryBuffer::new(&mut control_bytes);
    anyhow::ensure!(
        control.push(SendAncillaryMessage::ScmRights(fds)),
        "setup FD control buffer is too small"
    );
    let sent = sendmsg(
        stream,
        &[IoSlice::new(RIGHTS_MARKER)],
        &mut control,
        SendFlags::empty(),
    )
    .context("send setup file descriptors")?;
    anyhow::ensure!(sent == RIGHTS_MARKER.len(), "short setup FD marker write");
    Ok(())
}

fn receive_rights(stream: &UnixStream, expected: usize) -> Result<Vec<OwnedFd>> {
    anyhow::ensure!(expected <= MAX_FDS, "invalid setup FD count");
    let mut marker = [0_u8; 1];
    let mut iov = [IoSliceMut::new(&mut marker)];
    let mut control_bytes = [0_u8; rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut control_bytes);
    let message = recvmsg(stream, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
        .context("receive setup file descriptors")?;
    anyhow::ensure!(message.bytes == 1, "invalid setup FD marker length");
    anyhow::ensure!(
        !message
            .flags
            .intersects(RecvFlags::TRUNC | RecvFlags::from_bits_retain(libc::MSG_CTRUNC as u32)),
        "truncated setup FD message"
    );

    let mut owned = Vec::new();
    for item in control.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(fds) => owned.extend(fds),
            _ => anyhow::bail!("unexpected setup ancillary message"),
        }
    }
    anyhow::ensure!(marker == RIGHTS_MARKER, "invalid setup FD marker");
    anyhow::ensure!(
        owned.len() == expected,
        "setup worker sent {} FDs, expected {expected}",
        owned.len()
    );
    Ok(owned)
}

fn validate_manifest(
    manifest: &[SetupFd],
    runtime: Option<&crate::tls_runtime::StartReport>,
) -> Result<()> {
    anyhow::ensure!(manifest.len() <= MAX_FDS, "setup FD manifest is too large");
    anyhow::ensure!(
        manifest.starts_with(&FD_MANIFEST),
        "setup worker returned an unexpected base FD manifest"
    );
    match runtime {
        None => anyhow::ensure!(
            manifest == FD_MANIFEST,
            "setup worker returned runtime FDs without a runtime report"
        ),
        Some(report) => {
            let tail = &manifest[FD_MANIFEST.len()..];
            let link_end = report.attached_links;
            anyhow::ensure!(
                tail.len() == report.attached_links + report.perf_cpus.len(),
                "setup runtime FD count does not match its report"
            );
            anyhow::ensure!(
                tail[..link_end]
                    .iter()
                    .all(|kind| *kind == SetupFd::RuntimeTlsLink),
                "setup runtime link manifest contains an unexpected FD"
            );
            anyhow::ensure!(
                tail[link_end..]
                    .iter()
                    .all(|kind| *kind == SetupFd::RuntimePerfBuffer),
                "setup runtime perf manifest contains an unexpected FD"
            );
            anyhow::ensure!(
                report.attached_images > 0
                    && report.attached_links > 0
                    && !report.perf_cpus.is_empty(),
                "setup runtime report is incomplete"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        os::fd::{AsFd, AsRawFd},
    };

    use super::*;

    fn request() -> SetupRequest {
        SetupRequest::new(
            PathBuf::from("/sys/fs/cgroup/heimdall/run-123"),
            42,
            12345,
            5353,
            POLICY_DNS_HIJACK,
            false,
        )
        .unwrap()
    }

    #[test]
    fn request_round_trip_is_strict_and_versioned() {
        let (mut parent, mut worker) = UnixStream::pair().unwrap();
        send_request(&mut parent, &request()).unwrap();
        assert_eq!(receive_request(&mut worker).unwrap(), request());

        let malformed = serde_json::json!({
            "contract": CONTRACT,
            "cgroup_path": "/sys/fs/cgroup/heimdall/run-123",
            "cgroup_id": 42,
            "relay_port": 12345,
            "dns_port": 5353,
            "policy_flags": POLICY_DNS_HIJACK,
            "runtime_tls": false,
            "command": ["sh"]
        });
        assert!(serde_json::from_value::<SetupRequest>(malformed).is_err());
    }

    #[test]
    fn request_rejects_traversal_and_unknown_policy_bits() {
        assert!(
            SetupRequest::new(
                PathBuf::from("/sys/fs/cgroup/heimdall/../user.slice"),
                42,
                12345,
                5353,
                POLICY_DNS_HIJACK,
                false,
            )
            .is_err()
        );
        assert!(
            SetupRequest::new(
                PathBuf::from("/sys/fs/cgroup/heimdall/run-123"),
                42,
                12345,
                5353,
                1 << 7,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn ready_reply_transfers_the_exact_cloexec_fd_manifest() {
        let (mut worker, mut parent) = UnixStream::pair().unwrap();
        let files: Vec<File> = (0..FD_MANIFEST.len())
            .map(|_| File::open("/dev/null").unwrap())
            .collect();
        let borrowed: Vec<BorrowedFd<'_>> = files.iter().map(AsFd::as_fd).collect();

        send_ready(&mut worker, FD_MANIFEST.to_vec(), None, &borrowed).unwrap();
        let bundle = receive_reply(&mut parent).unwrap();

        assert_eq!(
            bundle.fds.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            FD_MANIFEST
        );
        for (_, fd) in bundle.fds {
            let flags = nix::fcntl::fcntl(fd.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn runtime_reply_transfers_counted_links_and_perf_buffers() {
        let (mut worker, mut parent) = UnixStream::pair().unwrap();
        let report = crate::tls_runtime::StartReport {
            discovered_images: 1,
            attached_images: 1,
            attached_links: 2,
            perf_cpus: vec![0, 2],
        };
        let mut manifest = FD_MANIFEST.to_vec();
        manifest.extend([
            SetupFd::RuntimeTlsLink,
            SetupFd::RuntimeTlsLink,
            SetupFd::RuntimePerfBuffer,
            SetupFd::RuntimePerfBuffer,
        ]);
        let files: Vec<File> = (0..manifest.len())
            .map(|_| File::open("/dev/null").unwrap())
            .collect();
        let borrowed: Vec<BorrowedFd<'_>> = files.iter().map(AsFd::as_fd).collect();

        send_ready(
            &mut worker,
            manifest.clone(),
            Some(report.clone()),
            &borrowed,
        )
        .unwrap();
        let bundle = receive_reply(&mut parent).unwrap();

        assert_eq!(bundle.runtime, Some(report));
        assert_eq!(
            bundle.fds.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            manifest
        );
    }

    #[test]
    fn runtime_reply_rejects_a_mismatched_link_count() {
        let report = crate::tls_runtime::StartReport {
            discovered_images: 1,
            attached_images: 1,
            attached_links: 2,
            perf_cpus: vec![0],
        };
        let mut manifest = FD_MANIFEST.to_vec();
        manifest.extend([SetupFd::RuntimeTlsLink, SetupFd::RuntimePerfBuffer]);
        assert!(validate_manifest(&manifest, Some(&report)).is_err());
    }

    #[test]
    fn error_reply_does_not_wait_for_file_descriptors() {
        let (mut worker, mut parent) = UnixStream::pair().unwrap();
        send_error(&mut worker, "permission_denied", "authorization failed").unwrap();
        let error = receive_reply(&mut parent).err().unwrap().to_string();
        assert!(error.contains("permission_denied"));
    }
}
