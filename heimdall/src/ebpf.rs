//! Versioned and transactional eBPF ownership across daemon restarts.

use std::{
    ffi::CString,
    fs,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use aya::{
    maps::{Array, Map},
    programs::links::FdLink,
};

pub const ROOT: &str = "/sys/fs/bpf/heimdall";
pub const MAPS: &str = "/sys/fs/bpf/heimdall/maps";
const LINKS: &str = "/sys/fs/bpf/heimdall/links";
const STATE_SCHEMA_PATH: &str = "/sys/fs/bpf/heimdall/maps/STATE_SCHEMA";
pub const STATE_SCHEMA: u32 = 1;

const BPF_OBJ_GET: libc::c_uint = 7;
const BPF_MAP_LOOKUP_ELEM: libc::c_uint = 1;
const BPF_PROG_GET_FD_BY_ID: libc::c_uint = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_uint = 15;
const BPF_LINK_UPDATE: libc::c_uint = 29;
const BPF_LINK_GET_FD_BY_ID: libc::c_uint = 30;
const BPF_F_REPLACE: u32 = 1 << 2;

#[repr(C)]
struct ObjectGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
    padding: u32,
}

#[repr(C)]
struct ObjectInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
struct MapElementAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct LinkInfo {
    type_: u32,
    id: u32,
    program_id: u32,
}

#[repr(C)]
struct IdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
    token_fd: i32,
}

#[repr(C)]
struct LinkUpdateAttr {
    link_fd: u32,
    new_prog_fd: u32,
    flags: u32,
    old_prog_fd: u32,
}

struct ReplacedLink {
    path: PathBuf,
    link: OwnedFd,
    old_program: OwnedFd,
    new_program: OwnedFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkLifetime {
    Persistent,
    Process,
}

/// Keeps process-owned eBPF links attached until the foreground session drops.
pub struct LinkSet {
    _links: Vec<FdLink>,
}

impl LinkSet {
    pub fn duplicate_fds(&self) -> Result<Vec<OwnedFd>> {
        self._links
            .iter()
            .map(|link| {
                let id = link.info().context("query process-owned eBPF link")?.id();
                link_by_id(id)
            })
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self._links.len()
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

/// Rolls a partially installed program generation back unless committed.
pub struct LinkTransaction {
    lifetime: LinkLifetime,
    replaced: Vec<ReplacedLink>,
    created: Vec<PathBuf>,
    owned: Vec<FdLink>,
    committed: bool,
}

impl LinkTransaction {
    pub const fn new(lifetime: LinkLifetime) -> Self {
        Self {
            lifetime,
            replaced: Vec::new(),
            created: Vec::new(),
            owned: Vec::new(),
            committed: false,
        }
    }

    /// CAS-replaces a pinned link while retaining both generations for rollback.
    pub fn update_link(&mut self, name: &str, program: BorrowedFd<'_>) -> Result<bool> {
        if self.lifetime == LinkLifetime::Process {
            return Ok(false);
        }
        let path = link_path(name)?;
        let Some(link) = open_pinned(&path)? else {
            return Ok(false);
        };
        let old_program = program_for_link(&link)
            .with_context(|| format!("open current program for eBPF link {}", path.display()))?;
        update_link_fd(&link, program, Some(old_program.as_fd()))
            .with_context(|| format!("atomically update eBPF link {}", path.display()))?;
        self.replaced.push(ReplacedLink {
            path,
            link,
            old_program,
            new_program: program.try_clone_to_owned()?,
        });
        Ok(true)
    }

    pub fn install_link(&mut self, name: &str, link: FdLink) -> Result<()> {
        let path = link_path(name)?;
        match self.lifetime {
            LinkLifetime::Persistent => {
                link.pin(&path)
                    .with_context(|| format!("pin initial eBPF link {}", path.display()))?;
                self.created.push(path);
            }
            LinkLifetime::Process => self.owned.push(link),
        }
        Ok(())
    }

    pub fn commit(mut self) -> LinkSet {
        self.committed = true;
        LinkSet {
            _links: std::mem::take(&mut self.owned),
        }
    }

    fn rollback(&mut self) {
        for replaced in self.replaced.iter().rev() {
            if let Err(error) = update_link_fd(
                &replaced.link,
                replaced.old_program.as_fd(),
                Some(replaced.new_program.as_fd()),
            ) {
                eprintln!(
                    "heimdall: CRITICAL: failed to roll back eBPF link {}: {error}",
                    replaced.path.display()
                );
            }
        }
        for path in self.created.iter().rev() {
            if let Err(error) = fs::remove_file(path) {
                eprintln!(
                    "heimdall: CRITICAL: failed to remove partial eBPF link {}: {error}",
                    path.display()
                );
            }
        }
    }
}

impl Drop for LinkTransaction {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback();
        }
    }
}

pub fn prepare_pin_dirs() -> Result<()> {
    for path in [ROOT, MAPS, LINKS] {
        fs::create_dir_all(path).with_context(|| format!("create eBPF pin directory {path}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set eBPF pin directory permissions on {path}"))?;
    }
    Ok(())
}

/// Rejects pins from an incompatible future map layout before object loading.
pub fn validate_state_schema() -> Result<()> {
    let path = Path::new(STATE_SCHEMA_PATH);
    if !path.exists() {
        // Releases before schema v1 already pinned the same layouts but lacked
        // the bootstrap marker. Loading this release creates it after Aya has
        // validated every reused map.
        return Ok(());
    }
    let map = open_pinned(path)?.context("pinned eBPF state schema disappeared")?;
    let key = 0u32;
    let mut schema = 0u32;
    let attr = MapElementAttr {
        map_fd: map.as_raw_fd() as u32,
        padding: 0,
        key: (&raw const key) as u64,
        value: (&raw mut schema) as u64,
        flags: 0,
    };
    bpf_call(BPF_MAP_LOOKUP_ELEM, &attr).context("read pinned eBPF state schema value")?;
    anyhow::ensure!(
        schema == STATE_SCHEMA,
        "incompatible pinned eBPF state schema {schema}; this binary requires {STATE_SCHEMA}. Stop heimdall, wait for wrapped commands to exit, then run `heimdall ebpf cleanup --json`"
    );
    Ok(())
}

pub fn write_state_schema(map: &mut Map) -> Result<()> {
    let mut schema = Array::<&mut aya::maps::MapData, u32>::try_from(map)
        .context("open loaded eBPF state schema map")?;
    schema
        .set(0, STATE_SCHEMA, 0)
        .context("write eBPF state schema")
}

pub fn cleanup_pins() -> Result<usize> {
    let root = Path::new(ROOT);
    if !root.exists() {
        return Ok(0);
    }
    let removed = fs::read_dir(root)
        .context("read eBPF pin root")?
        .filter_map(std::result::Result::ok)
        .count();
    fs::remove_dir_all(root).context("remove /sys/fs/bpf/heimdall")?;
    Ok(removed)
}

#[allow(
    unsafe_code,
    reason = "BPF_PROG_GET_FD_BY_ID returns a new owned raw descriptor"
)]
fn program_for_link(link: &OwnedFd) -> Result<OwnedFd> {
    let mut info = LinkInfo::default();
    let attr = ObjectInfoAttr {
        bpf_fd: link.as_raw_fd() as u32,
        info_len: std::mem::size_of::<LinkInfo>() as u32,
        info: (&raw mut info) as u64,
    };
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr).context("query eBPF link information")?;
    anyhow::ensure!(info.program_id != 0, "pinned eBPF link has no program");
    let attr = IdAttr {
        id: info.program_id,
        next_id: 0,
        open_flags: 0,
        token_fd: 0,
    };
    let fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &attr).context("open eBPF program by ID")?;
    // SAFETY: BPF_PROG_GET_FD_BY_ID returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn update_link_fd(
    link: &OwnedFd,
    new_program: BorrowedFd<'_>,
    expected_program: Option<BorrowedFd<'_>>,
) -> Result<()> {
    let attr = LinkUpdateAttr {
        link_fd: link.as_raw_fd() as u32,
        new_prog_fd: new_program.as_raw_fd() as u32,
        flags: expected_program.map_or(0, |_| BPF_F_REPLACE),
        old_prog_fd: expected_program.map_or(0, |fd| fd.as_raw_fd() as u32),
    };
    bpf_call(BPF_LINK_UPDATE, &attr)?;
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

#[allow(unsafe_code, reason = "BPF_OBJ_GET returns a new owned raw descriptor")]
fn open_pinned(path: &Path) -> Result<Option<OwnedFd>> {
    let path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("eBPF link path contains NUL: {}", path.display()))?;
    let attr = ObjectGetAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
        path_fd: 0,
        padding: 0,
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
    reason = "Aya does not expose generic pinned-link CAS replacement or program lookup"
)]
fn bpf_call<T>(command: libc::c_uint, attr: &T) -> std::io::Result<libc::c_long> {
    // SAFETY: every attribute is a repr(C) prefix defined by linux/bpf.h for
    // its command, and the kernel copies exactly the supplied structure size.
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
    use super::{LinkLifetime, LinkTransaction, link_path};

    #[test]
    fn link_pin_names_cannot_escape_the_private_directory() {
        assert!(link_path("connect4-user").is_ok());
        assert!(link_path("../connect4").is_err());
        assert!(link_path("connect4/system").is_err());
        assert!(link_path("").is_err());
    }

    #[test]
    fn process_link_transaction_commits_an_fd_owned_set() {
        let links = LinkTransaction::new(LinkLifetime::Process).commit();
        assert_eq!(links.len(), 0);
    }
}
