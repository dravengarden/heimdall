//! Shared command-line override for the strict execution backend config.

use clap::ValueEnum;

use crate::heimdall_config::ExecutionBackend;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum BackendArg {
    Ebpf,
    Interpose,
    Explicit,
}

impl From<BackendArg> for ExecutionBackend {
    fn from(value: BackendArg) -> Self {
        match value {
            BackendArg::Ebpf => Self::Ebpf,
            BackendArg::Interpose => Self::Interpose,
            BackendArg::Explicit => Self::Explicit,
        }
    }
}

impl BackendArg {
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ebpf => "ebpf",
            Self::Interpose => "interpose",
            Self::Explicit => "explicit",
        }
    }
}

#[must_use]
pub fn selected(
    configured: ExecutionBackend,
    command_line: Option<BackendArg>,
) -> ExecutionBackend {
    command_line.map_or(configured, Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_override_wins_without_mutating_config() {
        assert_eq!(
            selected(ExecutionBackend::Ebpf, Some(BackendArg::Interpose)),
            ExecutionBackend::Interpose
        );
        assert_eq!(
            selected(ExecutionBackend::Explicit, None),
            ExecutionBackend::Explicit
        );
    }
}
