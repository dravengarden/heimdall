//! Strict, format-independent configuration for the heimdall CLI wrapper.

use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

pub const DEFAULT_DIR: &str = "/etc/heimdall";
const CONFIG_CANDIDATES: [&str; 5] = [
    "config.toml",
    "config.yaml",
    "config.yml",
    "config.json",
    "config.ncl",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Yaml,
    Json,
    Nickel,
}

impl ConfigFormat {
    #[must_use]
    pub fn detect(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "toml" => Some(Self::Toml),
            "yaml" | "yml" => Some(Self::Yaml),
            "json" => Some(Self::Json),
            "ncl" => Some(Self::Nickel),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Nickel => "nickel",
        }
    }
}

/// Discover exactly one supported config in `dir`.
///
/// No match returns the conventional TOML path so callers produce a useful
/// read error. Multiple matches are rejected instead of silently selecting a
/// stale file.
///
/// # Errors
/// Returns [`ConfigError::AmbiguousConfig`] when more than one candidate exists.
pub fn discover_config_path(dir: impl AsRef<Path>) -> Result<PathBuf, ConfigError> {
    let dir = dir.as_ref();
    let matches: Vec<PathBuf> = CONFIG_CANDIDATES
        .iter()
        .map(|name| dir.join(name))
        .filter(|path| path.is_file())
        .collect();
    match matches.as_slice() {
        [] => Ok(dir.join("config.toml")),
        [path] => Ok(path.clone()),
        _ => Err(ConfigError::AmbiguousConfig { paths: matches }),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("unsupported config extension for {path}; expected .toml, .yaml, .yml, .json, or .ncl")]
    UnsupportedFormat { path: PathBuf },
    #[error("parse TOML {path}: {source}")]
    ParseToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("parse YAML {path}: {source}")]
    ParseYaml {
        path: PathBuf,
        source: serde_yaml_ng::Error,
    },
    #[error("parse JSON {path}: {source}")]
    ParseJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("run `nickel export` for {path}: {source}")]
    NickelSpawn {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Nickel evaluation failed for {path}: {message}")]
    NickelExport { path: PathBuf, message: String },
    #[error("multiple config files found; keep exactly one of: {paths:?}")]
    AmbiguousConfig { paths: Vec<PathBuf> },
    #[error("run.proxy refers to unknown proxy `{0}`")]
    UnknownDefaultProxy(String),
    #[error("invalid proxy name `{0}`; use only ASCII letters, digits, '.', '_', or '-'")]
    InvalidProxyName(String),
    #[error("proxy `{name}` has invalid addr `{addr}`; expected host:port or [IPv6]:port")]
    InvalidProxyAddress { name: String, addr: String },
    #[error("proxy `{0}` has an empty auth.username")]
    EmptyAuthUsername(String),
    #[error("proxy `{name}` auth.username is {length} bytes; expected at most 255")]
    AuthUsernameTooLong { name: String, length: usize },
    #[error("proxy `{name}` passwordFile must be absolute: {path}")]
    RelativePasswordFile { name: String, path: PathBuf },
    #[error("daemon.{field} has invalid socket address `{value}`")]
    InvalidSocket { field: &'static str, value: String },
    #[error("daemon listener addresses must use distinct sockets")]
    DuplicateListeners,
    #[error("daemon.cgroup must be an absolute path under /sys/fs/cgroup: `{0}`")]
    InvalidCgroup(String),
    #[error("daemon.{field} has invalid {family} CIDR `{value}`")]
    InvalidCidr {
        field: &'static str,
        family: &'static str,
        value: String,
    },
    #[error("read passwordFile `{path}`: {source}")]
    SecretRead {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl ConfigError {
    /// Stable machine-readable category for agent and CI consumers.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Read { .. } => "config_read_failed",
            Self::UnsupportedFormat { .. } => "unsupported_config_format",
            Self::ParseToml { .. } => "invalid_toml",
            Self::ParseYaml { .. } => "invalid_yaml",
            Self::ParseJson { .. } => "invalid_json",
            Self::NickelSpawn { .. } => "nickel_unavailable",
            Self::NickelExport { .. } => "invalid_nickel",
            Self::AmbiguousConfig { .. } => "ambiguous_config",
            Self::UnknownDefaultProxy(_) => "unknown_default_proxy",
            Self::InvalidProxyName(_) => "invalid_proxy_name",
            Self::InvalidProxyAddress { .. } => "invalid_proxy_address",
            Self::EmptyAuthUsername(_) => "empty_auth_username",
            Self::AuthUsernameTooLong { .. } => "auth_username_too_long",
            Self::RelativePasswordFile { .. } => "relative_password_file",
            Self::InvalidSocket { .. } => "invalid_listener",
            Self::DuplicateListeners => "duplicate_listeners",
            Self::InvalidCgroup(_) => "invalid_cgroup",
            Self::InvalidCidr { .. } => "invalid_cidr",
            Self::SecretRead { .. } => "secret_read_failed",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeimdallConfig {
    #[serde(default, rename = "daemon")]
    pub runtime: Runtime,
    #[serde(default, rename = "proxies")]
    pub connections: BTreeMap<String, Connection>,
    #[serde(default)]
    pub run: RunConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    #[serde(default = "default_cgroup")]
    pub cgroup: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_relay_ip", rename = "relayIp")]
    pub relay_ip: Ipv4Addr,
    #[serde(default = "default_relay_ip6", rename = "relayIp6")]
    pub relay_ip6: Ipv6Addr,
    #[serde(default = "default_dns_listen", rename = "dnsListen")]
    pub dns_listen: String,
    #[serde(default = "default_fake_ip_cidr", rename = "fakeIpCidr")]
    pub fake_ip_cidr: String,
    #[serde(default = "default_fake_ip6_cidr", rename = "fakeIp6Cidr")]
    pub fake_ip6_cidr: String,
    #[serde(default = "default_api_listen", rename = "apiListen")]
    pub api_listen: String,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            cgroup: default_cgroup(),
            listen: default_listen(),
            relay_ip: default_relay_ip(),
            relay_ip6: default_relay_ip6(),
            dns_listen: default_dns_listen(),
            fake_ip_cidr: default_fake_ip_cidr(),
            fake_ip6_cidr: default_fake_ip6_cidr(),
            api_listen: default_api_listen(),
        }
    }
}

fn default_cgroup() -> String {
    "/sys/fs/cgroup/system.slice".into()
}
fn default_listen() -> String {
    "127.0.0.1:12345".into()
}
fn default_relay_ip() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}
fn default_relay_ip6() -> Ipv6Addr {
    Ipv6Addr::LOCALHOST
}
fn default_dns_listen() -> String {
    "127.0.0.1:5358".into()
}
fn default_fake_ip_cidr() -> String {
    "198.19.0.0/16".into()
}
fn default_fake_ip6_cidr() -> String {
    "fc00:198:19::/96".into()
}
fn default_api_listen() -> String {
    "127.0.0.1:9999".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Connection {
    Socks5(Socks5Connection),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Connection {
    #[serde(default)]
    pub description: Option<String>,
    pub addr: String,
    #[serde(default)]
    pub auth: Option<Socks5Auth>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Auth {
    pub username: String,
    #[serde(rename = "passwordFile")]
    pub password_file: PathBuf,
}

impl Socks5Auth {
    /// Read the configured password file and trim one trailing newline.
    ///
    /// # Errors
    /// Returns [`ConfigError::SecretRead`] when the file cannot be read.
    pub fn read_password(&self) -> Result<Vec<u8>, ConfigError> {
        let mut bytes =
            fs::read(&self.password_file).map_err(|source| ConfigError::SecretRead {
                path: self.password_file.clone(),
                source,
            })?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    #[serde(default = "default_proxy")]
    pub proxy: String,
    #[serde(default)]
    pub dns: DnsStrategy,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            proxy: default_proxy(),
            dns: DnsStrategy::default(),
        }
    }
}

fn default_proxy() -> String {
    "default".into()
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    #[default]
    Fake,
    System,
}

/// Relay choice stored for an active CLI cgroup.
#[derive(Debug, Clone)]
pub struct Decision {
    pub use_: String,
}

impl HeimdallConfig {
    /// Load any supported config format and apply the canonical validation.
    ///
    /// # Errors
    /// Returns the first read, format, parse, evaluation, or validation error.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let cfg: Self = parse_typed(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate references, names, addresses, listeners, paths, and CIDRs.
    ///
    /// # Errors
    /// Returns the first semantic schema violation.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.connections.contains_key(&self.run.proxy) {
            return Err(ConfigError::UnknownDefaultProxy(self.run.proxy.clone()));
        }

        for (name, connection) in &self.connections {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
            {
                return Err(ConfigError::InvalidProxyName(name.clone()));
            }
            match connection {
                Connection::Socks5(proxy) => {
                    if !valid_host_port(&proxy.addr) {
                        return Err(ConfigError::InvalidProxyAddress {
                            name: name.clone(),
                            addr: proxy.addr.clone(),
                        });
                    }
                    if let Some(auth) = &proxy.auth {
                        if auth.username.trim().is_empty() {
                            return Err(ConfigError::EmptyAuthUsername(name.clone()));
                        }
                        if auth.username.len() > 255 {
                            return Err(ConfigError::AuthUsernameTooLong {
                                name: name.clone(),
                                length: auth.username.len(),
                            });
                        }
                        if !auth.password_file.is_absolute() {
                            return Err(ConfigError::RelativePasswordFile {
                                name: name.clone(),
                                path: auth.password_file.clone(),
                            });
                        }
                    }
                }
            }
        }

        let listen = parse_socket("listen", &self.runtime.listen)?;
        let dns = parse_socket("dnsListen", &self.runtime.dns_listen)?;
        let api = parse_socket("apiListen", &self.runtime.api_listen)?;
        if listen == dns || listen == api || dns == api {
            return Err(ConfigError::DuplicateListeners);
        }

        let cgroup = Path::new(&self.runtime.cgroup);
        if !cgroup.is_absolute() || !cgroup.starts_with("/sys/fs/cgroup") {
            return Err(ConfigError::InvalidCgroup(self.runtime.cgroup.clone()));
        }
        validate_v4_cidr("fakeIpCidr", &self.runtime.fake_ip_cidr)?;
        validate_v6_cidr("fakeIp6Cidr", &self.runtime.fake_ip6_cidr)?;
        Ok(())
    }
}

/// Parse a supported source into a type with Serde-level unknown-field checks.
///
/// # Errors
/// Returns format-specific decoding or Nickel evaluation errors.
pub fn parse_typed<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let format = ConfigFormat::detect(path).ok_or_else(|| ConfigError::UnsupportedFormat {
        path: path.to_path_buf(),
    })?;
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    match format {
        ConfigFormat::Toml => toml::from_str(&raw).map_err(|source| ConfigError::ParseToml {
            path: path.to_path_buf(),
            source,
        }),
        ConfigFormat::Yaml => {
            serde_yaml_ng::from_str(&raw).map_err(|source| ConfigError::ParseYaml {
                path: path.to_path_buf(),
                source,
            })
        }
        ConfigFormat::Json => serde_json::from_str(&raw).map_err(|source| ConfigError::ParseJson {
            path: path.to_path_buf(),
            source,
        }),
        ConfigFormat::Nickel => {
            let json = export_nickel(path)?;
            serde_json::from_slice(&json).map_err(|source| ConfigError::ParseJson {
                path: path.to_path_buf(),
                source,
            })
        }
    }
}

fn export_nickel(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let output = Command::new("nickel")
        .args(["export", "--format", "json"])
        .arg(path)
        .output()
        .map_err(|source| ConfigError::NickelSpawn {
            path: path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(ConfigError::NickelExport {
            path: path.to_path_buf(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(output.stdout)
}

fn valid_host_port(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    if port == 0 || host.is_empty() {
        return false;
    }
    if let Some(ipv6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return ipv6.parse::<Ipv6Addr>().is_ok();
    }
    !host.contains(':')
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

fn parse_socket(field: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    let socket = value
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::InvalidSocket {
            field,
            value: value.to_string(),
        })?;
    if socket.port() == 0 {
        return Err(ConfigError::InvalidSocket {
            field,
            value: value.to_string(),
        });
    }
    Ok(socket)
}

fn validate_v4_cidr(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let Some((addr, prefix)) = value.split_once('/') else {
        return Err(invalid_cidr(field, "IPv4", value));
    };
    let (Ok(addr), Ok(prefix)) = (addr.parse::<Ipv4Addr>(), prefix.parse::<u8>()) else {
        return Err(invalid_cidr(field, "IPv4", value));
    };
    if prefix > 32
        || u32::from(addr) & !u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0) != 0
    {
        return Err(invalid_cidr(field, "IPv4", value));
    }
    Ok(())
}

fn validate_v6_cidr(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let Some((addr, prefix)) = value.split_once('/') else {
        return Err(invalid_cidr(field, "IPv6", value));
    };
    let (Ok(addr), Ok(prefix)) = (addr.parse::<Ipv6Addr>(), prefix.parse::<u8>()) else {
        return Err(invalid_cidr(field, "IPv6", value));
    };
    if prefix > 128
        || u128::from(addr) & !u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0) != 0
    {
        return Err(invalid_cidr(field, "IPv6", value));
    }
    Ok(())
}

fn invalid_cidr(field: &'static str, family: &'static str, value: &str) -> ConfigError {
    ConfigError::InvalidCidr {
        field,
        family,
        value: value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn valid_toml() -> &'static str {
        r#"
            [proxies.default]
            type = "socks5"
            addr = "127.0.0.1:1080"
        "#
    }

    fn temp_config(extension: &str, content: &str) -> PathBuf {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "heimdall-config-test-{}-{id}.{extension}",
            std::process::id()
        ));
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn loads_toml_yaml_and_json_through_one_schema() {
        let cases = [
            ("toml", valid_toml()),
            (
                "yaml",
                "proxies:\n  default:\n    type: socks5\n    addr: 127.0.0.1:1080\n",
            ),
            (
                "json",
                r#"{"proxies":{"default":{"type":"socks5","addr":"127.0.0.1:1080"}}}"#,
            ),
        ];
        for (extension, content) in cases {
            let path = temp_config(extension, content);
            let cfg = HeimdallConfig::load(&path).unwrap();
            assert_eq!(cfg.run.proxy, "default");
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn loads_nickel_through_the_same_schema() {
        let path = temp_config(
            "ncl",
            r#"{ proxies.default = { type = "socks5", addr = "127.0.0.1:1080" } }"#,
        );
        let cfg = HeimdallConfig::load(&path).unwrap();
        assert_eq!(cfg.run.proxy, "default");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_unknown_fields_in_every_data_format() {
        let cases = [
            ("toml", format!("{}\nunknown = true\n", valid_toml())),
            (
                "yaml",
                "proxies:\n  default:\n    type: socks5\n    addr: 127.0.0.1:1080\nunknown: true\n"
                    .to_string(),
            ),
            (
                "json",
                r#"{"proxies":{"default":{"type":"socks5","addr":"127.0.0.1:1080"}},"unknown":true}"#
                    .to_string(),
            ),
            (
                "ncl",
                r#"{ proxies.default = { type = "socks5", addr = "127.0.0.1:1080" }, unknown = true }"#
                    .to_string(),
            ),
        ];
        for (extension, content) in cases {
            let path = temp_config(extension, &content);
            assert!(HeimdallConfig::load(&path).is_err());
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn rejects_invalid_semantics() {
        let cfg: HeimdallConfig = toml::from_str(
            r#"
                [proxies.default]
                type = "socks5"
                addr = "missing-port"
            "#,
        )
        .unwrap();
        let error = cfg.validate().unwrap_err();
        assert!(matches!(&error, ConfigError::InvalidProxyAddress { .. }));
        assert_eq!(error.code(), "invalid_proxy_address");
    }

    #[test]
    fn rejects_auth_username_longer_than_socks5_field() {
        let source = format!(
            r#"
                [proxies.default]
                type = "socks5"
                addr = "127.0.0.1:1080"
                [proxies.default.auth]
                username = "{}"
                passwordFile = "/etc/heimdall/password"
            "#,
            "u".repeat(256)
        );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        let error = cfg.validate().unwrap_err();
        assert!(matches!(
            &error,
            ConfigError::AuthUsernameTooLong { length: 256, .. }
        ));
        assert_eq!(error.code(), "auth_username_too_long");
    }

    #[test]
    fn password_file_preserves_binary_bytes_and_trims_one_newline() {
        let path = temp_config("secret", "ignored");
        fs::write(&path, [0xff, 0x00, b'p', b'\n']).unwrap();
        let auth = Socks5Auth {
            username: "alice".into(),
            password_file: path.clone(),
        };
        assert_eq!(auth.read_password().unwrap(), [0xff, 0x00, b'p']);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_unknown_run_proxy() {
        let cfg: HeimdallConfig = toml::from_str(
            r#"
                [proxies.default]
                type = "socks5"
                addr = "127.0.0.1:1080"
                [run]
                proxy = "missing"
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::UnknownDefaultProxy(name)) if name == "missing"
        ));
    }

    #[test]
    fn rejects_ambiguous_discovery() {
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "heimdall-config-discovery-test-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("config.toml"), valid_toml()).unwrap();
        fs::write(dir.join("config.json"), "{}").unwrap();
        assert!(matches!(
            discover_config_path(&dir),
            Err(ConfigError::AmbiguousConfig { .. })
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
