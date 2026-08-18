//! Narrow protocol between `heimdall run` and its short-lived setup worker.

use std::{
    io::{IoSlice, IoSliceMut, Read, Write},
    os::fd::{BorrowedFd, OwnedFd},
    os::unix::net::UnixStream,
    path::{Component, PathBuf},
};

use anyhow::{Context, Result};
use heimdall_common::{
    POLICY_DNS_HIJACK, POLICY_DNS_SYSTEM, POLICY_REDIRECT_OFF, POLICY_UDP_REJECT,
};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const CONTRACT: &str = "heimdall.setup/v1";
const MAX_FRAME_BYTES: usize = 64 * 1024;
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
}

impl SetupRequest {
    pub(crate) fn new(
        cgroup_path: PathBuf,
        cgroup_id: u64,
        relay_port: u16,
        dns_port: u16,
        policy_flags: u8,
    ) -> Result<Self> {
        let request = Self {
            contract: CONTRACT.to_owned(),
            cgroup_path,
            cgroup_id,
            relay_port,
            dns_port,
            policy_flags,
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
    },
    Error {
        contract: String,
        code: String,
        message: String,
    },
}

pub(crate) struct SetupBundle {
    pub(crate) fds: Vec<(SetupFd, OwnedFd)>,
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

pub(crate) fn send_ready(stream: &mut UnixStream, fds: &[BorrowedFd<'_>]) -> Result<()> {
    anyhow::ensure!(
        fds.len() == FD_MANIFEST.len(),
        "setup worker produced {} FDs, expected {}",
        fds.len(),
        FD_MANIFEST.len()
    );
    send_frame(
        stream,
        &SetupReply::Ready {
            contract: CONTRACT.to_owned(),
            fds: FD_MANIFEST.to_vec(),
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
        SetupReply::Ready { contract, fds } => {
            anyhow::ensure!(contract == CONTRACT, "unsupported setup reply contract");
            anyhow::ensure!(
                fds == FD_MANIFEST,
                "setup worker returned an unexpected FD manifest"
            );
            let owned = receive_rights(stream, fds.len())?;
            Ok(SetupBundle {
                fds: fds.into_iter().zip(owned).collect(),
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
    let mut control_bytes = [0_u8; rustix::cmsg_space!(ScmRights(FD_MANIFEST.len()))];
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
    anyhow::ensure!(expected == FD_MANIFEST.len(), "invalid setup FD count");
    let mut marker = [0_u8; 1];
    let mut iov = [IoSliceMut::new(&mut marker)];
    let mut control_bytes = [0_u8; rustix::cmsg_space!(ScmRights(FD_MANIFEST.len()))];
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

        send_ready(&mut worker, &borrowed).unwrap();
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
    fn error_reply_does_not_wait_for_file_descriptors() {
        let (mut worker, mut parent) = UnixStream::pair().unwrap();
        send_error(&mut worker, "permission_denied", "authorization failed").unwrap();
        let error = receive_reply(&mut parent).err().unwrap().to_string();
        assert!(error.contains("permission_denied"));
    }
}
