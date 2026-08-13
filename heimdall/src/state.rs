//! Runtime state that must survive a daemon process restart within one boot.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const RUNTIME_DIR: &str = "/run/heimdall";
const REGISTRATIONS_DIR: &str = "registrations";
const DAEMON_LOCK: &str = "daemon.lock";

pub struct DaemonLock(File);

impl DaemonLock {
    #[allow(
        unsafe_code,
        reason = "flock is the process-shared daemon and lifecycle-operation exclusion primitive"
    )]
    pub fn acquire() -> Result<Self> {
        prepare_runtime_dir()?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(Path::new(RUNTIME_DIR).join(DAEMON_LOCK))
            .context("open /run/heimdall/daemon.lock")?;
        let result = unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context(
                "lock /run/heimdall/daemon.lock; another daemon or lifecycle operation is active",
            );
        }
        Ok(Self(file))
    }
}

impl Drop for DaemonLock {
    #[allow(
        unsafe_code,
        reason = "release the flock acquired for the daemon lifecycle guard"
    )]
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN) };
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub cgroup_id: u64,
    pub policy: String,
}

pub fn prepare_runtime_dir() -> Result<()> {
    let runtime = Path::new(RUNTIME_DIR);
    let registrations = registrations_dir(runtime);
    fs::create_dir_all(&registrations).context("create /run/heimdall/registrations")?;
    fs::set_permissions(runtime, fs::Permissions::from_mode(0o700))
        .context("secure /run/heimdall")?;
    fs::set_permissions(&registrations, fs::Permissions::from_mode(0o700))
        .context("secure /run/heimdall/registrations")
}

pub fn persist_registration(registration: &Registration) -> Result<()> {
    persist_registration_at(Path::new(RUNTIME_DIR), registration)
}

pub fn remove_registration(cgroup_id: u64) -> Result<()> {
    remove_registration_at(Path::new(RUNTIME_DIR), cgroup_id)
}

pub fn load_registrations() -> Result<Vec<Registration>> {
    load_registrations_at(Path::new(RUNTIME_DIR))
}

fn registrations_dir(runtime_dir: impl AsRef<Path>) -> PathBuf {
    runtime_dir.as_ref().join(REGISTRATIONS_DIR)
}

fn registration_path(runtime_dir: impl AsRef<Path>, cgroup_id: u64) -> PathBuf {
    registrations_dir(runtime_dir).join(format!("{cgroup_id}.json"))
}

fn persist_registration_at(runtime_dir: &Path, registration: &Registration) -> Result<()> {
    let dir = registrations_dir(runtime_dir);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure {}", dir.display()))?;
    let target = registration_path(runtime_dir, registration.cgroup_id);
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        registration.cgroup_id,
        std::process::id()
    ));
    let bytes = serde_json::to_vec(registration).context("encode CLI registration")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("open {}", temporary.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, &target).with_context(|| format!("publish {}", target.display()))
}

fn remove_registration_at(runtime_dir: &Path, cgroup_id: u64) -> Result<()> {
    let path = registration_path(runtime_dir, cgroup_id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn load_registrations_at(runtime_dir: &Path) -> Result<Vec<Registration>> {
    let dir = registrations_dir(runtime_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut registrations = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let registration: Registration =
            serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))?;
        let filename_id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.parse::<u64>().ok());
        anyhow::ensure!(
            filename_id == Some(registration.cgroup_id),
            "registration filename does not match cgroup_id in {}",
            path.display()
        );
        registrations.push(registration);
    }
    registrations.sort_by_key(|registration| registration.cgroup_id);
    Ok(registrations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("heimdall-state-{name}-{}", std::process::id()))
    }

    #[test]
    fn registration_round_trip_and_removal() {
        let dir = test_dir("round-trip");
        let registration = Registration {
            cgroup_id: 42,
            policy: "default".into(),
        };
        persist_registration_at(&dir, &registration).unwrap();
        let registration_mode = fs::metadata(registration_path(&dir, 42))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(registration_mode, 0o600);
        assert_eq!(load_registrations_at(&dir).unwrap(), vec![registration]);
        remove_registration_at(&dir, 42).unwrap();
        assert!(load_registrations_at(&dir).unwrap().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_mismatched_registration_filename() {
        let dir = test_dir("mismatch");
        let registrations = registrations_dir(&dir);
        fs::create_dir_all(&registrations).unwrap();
        fs::write(
            registrations.join("7.json"),
            br#"{"cgroup_id":8,"policy":"default"}"#,
        )
        .unwrap();
        assert!(load_registrations_at(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
