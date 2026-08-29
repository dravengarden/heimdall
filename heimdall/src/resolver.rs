//! Read-only host resolver compatibility classification for fake DNS.

use std::{fs, path::Path};

use serde::Serialize;

use crate::heimdall_config::DnsMode;

const NSSWITCH_PATH: &str = "/etc/nsswitch.conf";
const NSCD_PATHS: [&str; 2] = ["/run/nscd/socket", "/var/run/nscd/socket"];
const APPARMOR_ENABLED_PATH: &str = "/sys/module/apparmor/parameters/enabled";
const APPARMOR_USERNS_PATH: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
const UNPRIVILEGED_USERNS_PATH: &str = "/proc/sys/kernel/unprivileged_userns_clone";
const MAX_USER_NAMESPACES_PATH: &str = "/proc/sys/user/max_user_namespaces";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResolverStrategy {
    System,
    Port53Intercept,
    PrivateMount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResolverReason {
    SystemDns,
    FilesDns,
    NscdSocket,
    NsswitchUnreadable,
    HostsMissing,
    HostsDuplicate,
    DnsMissing,
    NssStatusAction,
    NssBypassSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateMountStatus {
    NotRequired,
    RuntimeCheck,
    ApparmorPolicyCheck,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ResolverError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ResolverReport {
    pub(crate) strategy: ResolverStrategy,
    pub(crate) reason: ResolverReason,
    pub(crate) nsswitch_path: Option<&'static str>,
    pub(crate) hosts_sources: Vec<String>,
    pub(crate) unsupported_sources: Vec<String>,
    pub(crate) nscd_socket: Option<String>,
    pub(crate) private_mount_required: bool,
    pub(crate) private_mount_status: PrivateMountStatus,
    pub(crate) apparmor_enabled: Option<bool>,
    pub(crate) apparmor_restrict_unprivileged_userns: Option<bool>,
    pub(crate) unprivileged_userns_clone: Option<bool>,
    pub(crate) max_user_namespaces: Option<u64>,
    pub(crate) ready: bool,
    pub(crate) error: Option<ResolverError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NsswitchReport {
    reason: ResolverReason,
    hosts_sources: Vec<String>,
    unsupported_sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct UserNamespaceSettings {
    apparmor_enabled: Option<bool>,
    apparmor_restricted: Option<bool>,
    unprivileged_userns_clone: Option<bool>,
    max_user_namespaces: Option<u64>,
}

impl ResolverReport {
    pub(crate) fn inspect(mode: DnsMode) -> Self {
        if mode == DnsMode::System {
            return Self::system();
        }

        let nsswitch = fs::read_to_string(NSSWITCH_PATH)
            .ok()
            .map_or_else(unreadable_nsswitch, |contents| classify_nsswitch(&contents));
        let nscd_socket = NSCD_PATHS
            .iter()
            .find(|path| Path::new(path).exists())
            .map(|path| (*path).to_string());
        let settings = read_user_namespace_settings();
        Self::fake(nsswitch, nscd_socket, settings)
    }

    pub(crate) const fn requires_private_mount(&self) -> bool {
        self.private_mount_required
    }

    pub(crate) fn blocking_error(&self) -> Option<&ResolverError> {
        self.error.as_ref()
    }

    pub(crate) fn inspection_actions(&self) -> Vec<Vec<String>> {
        let mut actions = Vec::new();
        if let Some(path) = self.nsswitch_path {
            actions.push(vec!["cat".into(), path.into()]);
        }
        if let Some(path) = &self.nscd_socket {
            actions.push(vec!["stat".into(), "--".into(), path.clone()]);
        }
        if self.apparmor_enabled.is_some() {
            actions.push(vec!["cat".into(), APPARMOR_ENABLED_PATH.into()]);
        }
        if self.apparmor_restrict_unprivileged_userns.is_some() {
            actions.push(vec!["cat".into(), APPARMOR_USERNS_PATH.into()]);
        }
        if self.unprivileged_userns_clone.is_some() {
            actions.push(vec!["cat".into(), UNPRIVILEGED_USERNS_PATH.into()]);
        }
        if self.max_user_namespaces.is_some() {
            actions.push(vec!["cat".into(), MAX_USER_NAMESPACES_PATH.into()]);
        }
        actions
    }

    fn system() -> Self {
        Self {
            strategy: ResolverStrategy::System,
            reason: ResolverReason::SystemDns,
            nsswitch_path: None,
            hosts_sources: Vec::new(),
            unsupported_sources: Vec::new(),
            nscd_socket: None,
            private_mount_required: false,
            private_mount_status: PrivateMountStatus::NotRequired,
            apparmor_enabled: None,
            apparmor_restrict_unprivileged_userns: None,
            unprivileged_userns_clone: None,
            max_user_namespaces: None,
            ready: true,
            error: None,
        }
    }

    fn fake(
        nsswitch: NsswitchReport,
        nscd_socket: Option<String>,
        settings: UserNamespaceSettings,
    ) -> Self {
        let direct = nsswitch.reason == ResolverReason::FilesDns && nscd_socket.is_none();
        let private_mount_required = !direct;
        let namespace_disabled = private_mount_required
            && (settings.unprivileged_userns_clone == Some(false)
                || settings.max_user_namespaces == Some(0));
        let private_mount_status = if !private_mount_required {
            PrivateMountStatus::NotRequired
        } else if namespace_disabled {
            PrivateMountStatus::Disabled
        } else if settings.apparmor_enabled == Some(true)
            && settings.apparmor_restricted == Some(true)
        {
            PrivateMountStatus::ApparmorPolicyCheck
        } else {
            PrivateMountStatus::RuntimeCheck
        };
        let reason = if nscd_socket.is_some() {
            ResolverReason::NscdSocket
        } else {
            nsswitch.reason
        };
        let error = namespace_disabled.then(|| ResolverError {
            code: "fake_dns_user_namespace_disabled",
            message: "fake DNS needs a private resolver mount, but unprivileged user namespaces are disabled by host settings".into(),
            hint: "Select dns.mode = \"system\" for this policy or use a host where the private resolver namespace is permitted; do not relax host-wide security settings.".into(),
        });

        Self {
            strategy: if direct {
                ResolverStrategy::Port53Intercept
            } else {
                ResolverStrategy::PrivateMount
            },
            reason,
            nsswitch_path: Some(NSSWITCH_PATH),
            hosts_sources: nsswitch.hosts_sources,
            unsupported_sources: nsswitch.unsupported_sources,
            nscd_socket,
            private_mount_required,
            private_mount_status,
            apparmor_enabled: settings.apparmor_enabled,
            apparmor_restrict_unprivileged_userns: settings.apparmor_restricted,
            unprivileged_userns_clone: settings.unprivileged_userns_clone,
            max_user_namespaces: settings.max_user_namespaces,
            ready: !namespace_disabled,
            error,
        }
    }
}

fn unreadable_nsswitch() -> NsswitchReport {
    NsswitchReport {
        reason: ResolverReason::NsswitchUnreadable,
        hosts_sources: Vec::new(),
        unsupported_sources: Vec::new(),
    }
}

fn classify_nsswitch(contents: &str) -> NsswitchReport {
    let mut hosts_lines = Vec::new();
    for line in contents.lines() {
        let line = line.split_once('#').map_or(line, |(value, _)| value).trim();
        let Some((database, sources)) = line.split_once(':') else {
            continue;
        };
        if database.trim() == "hosts" {
            hosts_lines.push(sources.trim());
        }
    }

    if hosts_lines.is_empty() {
        return NsswitchReport {
            reason: ResolverReason::HostsMissing,
            hosts_sources: Vec::new(),
            unsupported_sources: Vec::new(),
        };
    }
    if hosts_lines.len() != 1 {
        return NsswitchReport {
            reason: ResolverReason::HostsDuplicate,
            hosts_sources: hosts_lines
                .iter()
                .flat_map(|sources| sources.split_whitespace())
                .map(str::to_owned)
                .collect(),
            unsupported_sources: Vec::new(),
        };
    }

    let hosts_sources: Vec<String> = hosts_lines[0]
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if hosts_sources
        .iter()
        .any(|source| source.contains(['[', ']']))
    {
        return NsswitchReport {
            reason: ResolverReason::NssStatusAction,
            unsupported_sources: hosts_sources
                .iter()
                .filter(|source| source.contains(['[', ']']))
                .cloned()
                .collect(),
            hosts_sources,
        };
    }

    let unsupported_sources: Vec<String> = hosts_sources
        .iter()
        .filter(|source| source.as_str() != "files" && source.as_str() != "dns")
        .cloned()
        .collect();
    if !unsupported_sources.is_empty() {
        return NsswitchReport {
            reason: ResolverReason::NssBypassSource,
            hosts_sources,
            unsupported_sources,
        };
    }
    if !hosts_sources.iter().any(|source| source == "dns") {
        return NsswitchReport {
            reason: ResolverReason::DnsMissing,
            hosts_sources,
            unsupported_sources,
        };
    }

    NsswitchReport {
        reason: ResolverReason::FilesDns,
        hosts_sources,
        unsupported_sources,
    }
}

fn read_user_namespace_settings() -> UserNamespaceSettings {
    UserNamespaceSettings {
        apparmor_enabled: read_bool(APPARMOR_ENABLED_PATH),
        apparmor_restricted: read_bool(APPARMOR_USERNS_PATH),
        unprivileged_userns_clone: read_bool(UNPRIVILEGED_USERNS_PATH),
        max_user_namespaces: read_u64(MAX_USER_NAMESPACES_PATH),
    }
}

fn read_bool(path: &str) -> Option<bool> {
    match fs::read_to_string(path).ok()?.trim() {
        "1" | "Y" | "y" | "yes" | "true" => Some(true),
        "0" | "N" | "n" | "no" | "false" => Some(false),
        _ => None,
    }
}

fn read_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> UserNamespaceSettings {
        UserNamespaceSettings {
            max_user_namespaces: Some(1024),
            ..UserNamespaceSettings::default()
        }
    }

    #[test]
    fn accepts_only_a_direct_files_and_dns_path() {
        for contents in [
            "passwd: files systemd\nhosts: files dns\n",
            "hosts: dns files # local overrides remain supported\n",
        ] {
            let report = classify_nsswitch(contents);
            assert_eq!(report.reason, ResolverReason::FilesDns);
            assert!(report.unsupported_sources.is_empty());
        }
    }

    #[test]
    fn classifies_every_private_mount_reason() {
        for (contents, reason) in [
            (
                "hosts: files resolve [!UNAVAIL=return] dns\n",
                ResolverReason::NssStatusAction,
            ),
            (
                "hosts: files mdns4_minimal dns\n",
                ResolverReason::NssBypassSource,
            ),
            ("hosts: files\n", ResolverReason::DnsMissing),
            (
                "hosts: files dns\nhosts: dns\n",
                ResolverReason::HostsDuplicate,
            ),
            ("passwd: files\n", ResolverReason::HostsMissing),
        ] {
            assert_eq!(classify_nsswitch(contents).reason, reason);
        }
    }

    #[test]
    fn direct_port53_path_ignores_an_unrelated_apparmor_restriction() {
        let report = ResolverReport::fake(
            classify_nsswitch("hosts: files dns\n"),
            None,
            UserNamespaceSettings {
                apparmor_enabled: Some(true),
                apparmor_restricted: Some(true),
                max_user_namespaces: Some(0),
                ..UserNamespaceSettings::default()
            },
        );
        assert_eq!(report.strategy, ResolverStrategy::Port53Intercept);
        assert_eq!(report.private_mount_status, PrivateMountStatus::NotRequired);
        assert!(report.ready);
        assert!(report.error.is_none());
        assert_eq!(
            report.inspection_actions()[1],
            ["cat", APPARMOR_ENABLED_PATH]
        );
    }

    #[test]
    fn disabled_user_namespaces_block_only_the_private_mount_fallback() {
        let report = ResolverReport::fake(
            classify_nsswitch("hosts: files resolve [!UNAVAIL=return] dns\n"),
            None,
            UserNamespaceSettings {
                max_user_namespaces: Some(0),
                ..UserNamespaceSettings::default()
            },
        );
        assert_eq!(report.strategy, ResolverStrategy::PrivateMount);
        assert_eq!(report.private_mount_status, PrivateMountStatus::Disabled);
        assert!(!report.ready);
        assert_eq!(
            report.error.as_ref().map(|error| error.code),
            Some("fake_dns_user_namespace_disabled")
        );
    }

    #[test]
    fn apparmor_restriction_remains_a_runtime_policy_check() {
        let report = ResolverReport::fake(
            classify_nsswitch("hosts: files resolve dns\n"),
            None,
            UserNamespaceSettings {
                apparmor_enabled: Some(true),
                apparmor_restricted: Some(true),
                ..settings()
            },
        );
        assert_eq!(
            report.private_mount_status,
            PrivateMountStatus::ApparmorPolicyCheck
        );
        assert!(report.ready);
        assert!(report.error.is_none());
    }

    #[test]
    fn nscd_forces_the_private_mount_even_with_plain_dns() {
        let report = ResolverReport::fake(
            classify_nsswitch("hosts: files dns\n"),
            Some("/run/nscd/socket".into()),
            settings(),
        );
        assert_eq!(report.strategy, ResolverStrategy::PrivateMount);
        assert_eq!(report.reason, ResolverReason::NscdSocket);
        assert!(report.requires_private_mount());
        assert_eq!(
            report.inspection_actions()[1],
            ["stat", "--", "/run/nscd/socket"]
        );
    }
}
