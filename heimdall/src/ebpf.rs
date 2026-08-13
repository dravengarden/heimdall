//! Persistent eBPF ownership across daemon restarts.

use std::{
    ffi::CString,
    fs,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use aya::programs::links::FdLink;

pub const ROOT: &str = "/sys/fs/bpf/heimdall";
pub const MAPS: &str = "/sys/fs/bpf/heimdall/maps";
const LINKS: &str = "/sys/fs/bpf/heimdall/links";
const BPF_OBJ_GET: libc::c_uint = 7;
const BPF_LINK_UPDATE: libc::c_uint = 29;

#[repr(C)]
struct ObjectGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
}

#[repr(C)]
struct LinkUpdateAttr {
    link_fd: u32,
    new_prog_fd: u32,
    flags: u32,
    old_prog_fd: u32,
}

pub fn prepare_pin_dirs() -> Result<()> {
    for path in [ROOT, MAPS, LINKS] {
        fs::create_dir_all(path).with_context(|| format!("create eBPF pin directory {path}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set eBPF pin directory permissions on {path}"))?;
    }
    Ok(())
}

/// Atomically redirects an existing pinned link to the newly loaded program.
///
/// Returns `false` only on the first boot, when the caller must attach and pin
/// the initial link. `BPF_LINK_UPDATE` keeps the link attached for the entire
/// replacement; an incompatible program fails without changing the old link.
pub fn update_link(name: &str, program: BorrowedFd<'_>) -> Result<bool> {
    let path = link_path(name)?;
    let Some(link) = open_pinned(&path)? else {
        return Ok(false);
    };
    let attr = LinkUpdateAttr {
        link_fd: link.as_raw_fd() as u32,
        new_prog_fd: program.as_raw_fd() as u32,
        flags: 0,
        old_prog_fd: 0,
    };
    bpf_call(BPF_LINK_UPDATE, &attr)
        .with_context(|| format!("atomically update eBPF link {}", path.display()))?;
    Ok(true)
}

pub fn pin_link(name: &str, link: FdLink) -> Result<()> {
    let path = link_path(name)?;
    link.pin(&path)
        .with_context(|| format!("pin initial eBPF link {}", path.display()))?;
    Ok(())
}

fn link_path(name: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "invalid eBPF link pin name `{name}`"
    );
    Ok(Path::new(LINKS).join(name))
}

#[allow(
    unsafe_code,
    reason = "BPF_OBJ_GET returns an owned raw descriptor; Aya does not expose the pinned link FD"
)]
fn open_pinned(path: &Path) -> Result<Option<OwnedFd>> {
    let path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("eBPF link path contains NUL: {}", path.display()))?;
    let attr = ObjectGetAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
        path_fd: 0,
    };
    match bpf_call(BPF_OBJ_GET, &attr) {
        Ok(fd) => {
            // SAFETY: BPF_OBJ_GET returned a new owned descriptor on success.
            Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("open eBPF link {}", path.to_string_lossy()))
        }
    }
}

#[allow(
    unsafe_code,
    reason = "Aya 0.14 exposes cgroup link pinning but not the generic BPF_LINK_UPDATE syscall"
)]
fn bpf_call<T>(command: libc::c_uint, attr: &T) -> std::io::Result<libc::c_long> {
    // SAFETY: both attributes are repr(C) prefixes defined by linux/bpf.h for
    // their command, and the kernel copies exactly the supplied structure size.
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
    use super::link_path;

    #[test]
    fn link_pin_names_cannot_escape_the_private_directory() {
        assert!(link_path("connect4-user").is_ok());
        assert!(link_path("../connect4").is_err());
        assert!(link_path("connect4/system").is_err());
        assert!(link_path("").is_err());
    }
}
