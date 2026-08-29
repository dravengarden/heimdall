//! Platform-neutral ownership of one run's append-only evidence lifecycle.

use std::path::{Path, PathBuf};

use crate::{
    event_log::{RotationServer, RunLog},
    heimdall_config::CaptureConfig,
};
use anyhow::Result;

/// Keeps the writer and its control sockets inside the foreground run lifetime.
pub(crate) struct RunEvidence {
    log: RunLog,
    rotation: RotationServer,
}

impl RunEvidence {
    pub(crate) fn start(
        command: &[String],
        policy: &str,
        backend: &str,
        capture: &CaptureConfig,
    ) -> Result<Self> {
        let log = RunLog::create_with_capture(command, policy, backend, capture)?;
        let rotation = RotationServer::start(log.clone())?;
        Ok(Self { log, rotation })
    }

    #[cfg(test)]
    fn start_at(
        runs: &Path,
        runtime: &Path,
        command: &[String],
        policy: &str,
        backend: &str,
    ) -> Result<Self> {
        let log = RunLog::create_at(runs, command, policy, backend)?;
        let rotation = RotationServer::start_at(log.clone(), runtime)?;
        Ok(Self { log, rotation })
    }

    pub(crate) fn log(&self) -> &RunLog {
        &self.log
    }

    pub(crate) fn event_socket_path(&self) -> &Path {
        self.rotation.event_socket_path()
    }

    pub(crate) fn run_dir(&self) -> Result<PathBuf> {
        self.log.run_dir()
    }

    pub(crate) fn ready(
        &self,
        owner: &str,
        control: Option<&str>,
        boundaries: &[&str],
    ) -> Result<()> {
        self.log.ready(owner, control, boundaries)
    }

    /// Consuming the owner prevents control sockets from outliving finalization.
    pub(crate) fn finish(self, exit_code: i32, descendants_cleaned: bool) -> Result<()> {
        self.log.finish(exit_code, descendants_cleaned)
    }

    /// Consuming the owner closes control sockets after failed-run evidence lands.
    pub(crate) fn fail(self, code: &str, message: &str) -> Result<()> {
        self.log.fail(code, message)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileTypeExt;

    use super::*;

    #[test]
    fn evidence_owner_finalizes_before_releasing_control_sockets() {
        let uuid = uuid::Uuid::now_v7().simple().to_string();
        let suffix = format!("{}-{}", std::process::id(), &uuid[..8]);
        let runs = Path::new("/tmp").join(format!("her-{suffix}"));
        let runtime = Path::new("/tmp").join(format!("het-{suffix}"));
        let evidence = RunEvidence::start_at(
            &runs,
            &runtime,
            &["true".into()],
            "default",
            "portable-test",
        )
        .unwrap();
        let run_dir = evidence.run_dir().unwrap();
        let event_socket = evidence.event_socket_path().to_path_buf();

        evidence.ready("test-owner", None, &["transport"]).unwrap();
        assert!(
            std::fs::symlink_metadata(&event_socket)
                .unwrap()
                .file_type()
                .is_socket()
        );
        evidence.finish(0, true).unwrap();
        assert!(!event_socket.exists());

        let manifest = crate::event_log::read_manifest(&run_dir.join("run.json")).unwrap();
        assert_eq!(manifest.state, "closed");
        assert_eq!(manifest.backend, "portable-test");
        assert_eq!(manifest.result.unwrap().exit_code, Some(0));

        std::fs::remove_dir_all(runs).unwrap();
        std::fs::remove_dir_all(runtime).unwrap();
    }
}
