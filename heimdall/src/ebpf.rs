//! Process-owned eBPF link lifetime for one foreground command.

use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::{Context, Result};
use aya::programs::links::FdLink;

const BPF_LINK_GET_FD_BY_ID: libc::c_uint = 30;

#[repr(C)]
struct IdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
    token_fd: i32,
}

/// Keeps process-owned eBPF links attached until the foreground session drops.
pub struct LinkSet {
    links: Vec<FdLink>,
}

impl LinkSet {
    pub fn duplicate_fds(&self) -> Result<Vec<OwnedFd>> {
        self.links.iter().map(duplicate_link_fd).collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.links.len()
    }
}

pub fn duplicate_link_fd(link: &FdLink) -> Result<OwnedFd> {
    let id = link.info().context("query process-owned eBPF link")?.id();
    link_by_id(id)
}

#[allow(
    unsafe_code,
    reason = "BPF_LINK_GET_FD_BY_ID returns a new owned raw descriptor"
)]
fn link_by_id(id: u32) -> Result<OwnedFd> {
    let attr = IdAttr {
        id,
        next_id: 0,
        open_flags: 0,
        token_fd: 0,
    };
    let fd = bpf_call(BPF_LINK_GET_FD_BY_ID, &attr).context("open eBPF link by ID")?;
    // SAFETY: BPF_LINK_GET_FD_BY_ID returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Collects a complete foreground link generation. Dropping an uncommitted
/// transaction detaches every link automatically through FD ownership.
pub struct LinkTransaction {
    links: Vec<FdLink>,
}

impl LinkTransaction {
    pub const fn new() -> Self {
        Self { links: Vec::new() }
    }

    pub fn install_link(&mut self, link: FdLink) {
        self.links.push(link);
    }

    pub fn commit(mut self) -> LinkSet {
        LinkSet {
            links: std::mem::take(&mut self.links),
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the attribute is the repr(C) prefix defined by linux/bpf.h"
)]
fn bpf_call<T>(command: libc::c_uint, attr: &T) -> std::io::Result<libc::c_long> {
    // SAFETY: the kernel copies exactly the supplied attribute structure size.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            attr as *const T,
            std::mem::size_of::<T>(),
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::LinkTransaction;

    #[test]
    fn empty_transaction_commits_an_fd_owned_set() {
        assert_eq!(LinkTransaction::new().commit().len(), 0);
    }
}
