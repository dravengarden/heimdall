//! Heimdall configuration schema (`/etc/heimdall/config.yaml`).
//!
//! Forward-compatible with M3 (label-based rules) and M5 (MITM): unknown
//! fields in `Rule.match` and `Connection` are deserialized but not yet
//! enforced. Today, only `runtime`, `connections`, and `routing.default`
//! drive behavior; `routing.rules` and `mitm` are parsed and validated but
//! not yet acted upon.

use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

pub const DEFAULT_PATH: &str = "/etc/heimdall/config.yaml";
pub const CONNECTION_KEY_DEFAULT: &str = "heimdall.io/connection";
pub const OBSERVE_KEY_DEFAULT: &str = "heimdall.io/observe";

/// Reserved value for `routing.*.use` (and the connection annotation) that
/// means "don't redirect through the relay; let the kernel route natively".
/// Distinct from a `Connection::Direct` upstream — system mode skips heimdall
/// entirely at the eBPF connect4 hook.
pub const SYSTEM_CONNECTION: &str = "system";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("parse {path}: {source}")]
    Parse { path: PathBuf, source: serde_yaml::Error },
    #[error("apiVersion `{0}` is not supported (expected `heimdall.io/v1alpha1`)")]
    UnsupportedApiVersion(String),
    #[error("kind `{0}` is not supported (expected `HeimdallConfig`)")]
    UnsupportedKind(String),
    #[error("connections must define `default`")]
    MissingDefaultConnection,
    #[error("routing.default.use refers to unknown connection `{0}`")]
    DefaultConnectionUnknown(String),
    #[error("routing.rules[{index}] (`{name}`) refers to unknown connection `{connection}`")]
    RuleConnectionUnknown { index: usize, name: String, connection: String },
    #[error("routing.rules[{index}] is missing a name")]
    RuleMissingName { index: usize },
    #[error("connection name `{0}` is reserved (used internally for system bypass)")]
    ReservedConnectionName(String),
    #[error("connection `{name}` has empty addr (required for type `{ty}`)")]
    EmptyAddr { name: String, ty: String },
    #[error("read passwordFile `{path}`: {source}")]
    SecretRead { path: PathBuf, source: std::io::Error },
}

// ---------------------------------------------------------------------------
// Top-level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeimdallConfig {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,

    #[serde(default)]
    pub runtime: Runtime,

    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,

    #[serde(default)]
    pub routing: Routing,
}

// ---------------------------------------------------------------------------
// runtime: eBPF + relay knobs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    #[serde(default = "default_cgroup")]
    pub cgroup: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    #[serde(default = "default_relay_ip")]
    #[serde(rename = "relayIp")]
    pub relay_ip: Ipv4Addr,

    #[serde(default, rename = "bypassCidrs")]
    pub bypass_cidrs: Vec<String>,

    /// Address the fake-IP DNS server listens on (UDP). CoreDNS is expected
    /// to forward non-cluster zones here so heimdall can return synthetic
    /// fake IPs that the relay later resolves back to hostnames.
    #[serde(default = "default_dns_listen", rename = "dnsListen")]
    pub dns_listen: String,

    /// IPv4 CIDR pool to draw fake IPs from. `198.19.0.0/16` (IETF
    /// benchmark range, RFC 2544/6815) is reserved and will not appear
    /// in real routing.
    #[serde(default = "default_fake_ip_cidr", rename = "fakeIpCidr")]
    pub fake_ip_cidr: String,

    /// State directory: sqlite flow store, blob storage, IPC socket.
    #[serde(default = "default_state_dir", rename = "stateDir")]
    pub state_dir: PathBuf,

    /// Flow retention in seconds. Default 3 days. The cleanup task
    /// runs every 6 hours and deletes rows older than this.
    #[serde(default = "default_flow_retention_secs", rename = "flowRetentionSecs")]
    pub flow_retention_secs: i64,

    /// HTTP API + future Web UI listen address.
    /// Default `127.0.0.1:9999` keeps it loopback-only; set
    /// to `0.0.0.0:9999` for LAN browser access.
    #[serde(default = "default_api_listen", rename = "apiListen")]
    pub api_listen: String,

    /// Phase B TLS plaintext tap. Off by default — turning this on
    /// scans /proc for libssl mappings at startup and attaches uprobes.
    #[serde(default)]
    pub tap: TapConfig,
}

/// Phase B (TLS plaintext tap) settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TapConfig {
    /// Master switch. When false, no /proc scan, no uprobe attach,
    /// no perf consumer threads.
    #[serde(default)]
    pub enabled: bool,

    /// When true, captured plaintext is written to the `messages`
    /// table in the flow store and exposed via the HTTP API.
    /// When false (default), tap events only show up in the
    /// daemon journal — useful for verifying probes attach without
    /// committing to disk-resident plaintext.
    #[serde(default)]
    pub persist: bool,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            cgroup: default_cgroup(),
            listen: default_listen(),
            relay_ip: default_relay_ip(),
            bypass_cidrs: Vec::new(),
            dns_listen: default_dns_listen(),
            fake_ip_cidr: default_fake_ip_cidr(),
            state_dir: default_state_dir(),
            flow_retention_secs: default_flow_retention_secs(),
            api_listen: default_api_listen(),
            tap: TapConfig::default(),
        }
    }
}

fn default_cgroup() -> String { "/sys/fs/cgroup".to_string() }
fn default_listen() -> String { "0.0.0.0:12345".to_string() }
fn default_relay_ip() -> Ipv4Addr { Ipv4Addr::new(127, 0, 0, 1) }
fn default_dns_listen() -> String { "0.0.0.0:5358".to_string() }
fn default_fake_ip_cidr() -> String { "198.19.0.0/16".to_string() }
fn default_state_dir() -> PathBuf { PathBuf::from("/var/lib/heimdall") }
fn default_flow_retention_secs() -> i64 { 3 * 86400 } // 3 days
fn default_api_listen() -> String { "127.0.0.1:9999".to_string() }

// ---------------------------------------------------------------------------
// connections: registry of named upstreams
// ---------------------------------------------------------------------------

/// Polymorphic connection — `type` is the discriminator.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Connection {
    Socks5(Socks5Connection),
    Direct(DirectConnection),
}

impl Connection {
    pub fn description(&self) -> Option<&str> {
        match self {
            Connection::Socks5(c) => c.description.as_deref(),
            Connection::Direct(c) => c.description.as_deref(),
        }
    }

    pub fn type_str(&self) -> &'static str {
        match self {
            Connection::Socks5(_) => "socks5",
            Connection::Direct(_) => "direct",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Connection {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,

    pub addr: String,

    #[serde(default)]
    pub auth: Option<Socks5Auth>,

    /// Reserved for M5. Parsed but ignored today.
    #[serde(default)]
    pub mitm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Auth {
    pub username: String,

    /// Path to a file containing the password. The file should be
    /// 0400 root:root and *not* live under /etc/<host-config>.
    #[serde(rename = "passwordFile")]
    pub password_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConnection {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
}

// ---------------------------------------------------------------------------
// routing: how heimdall picks a connection per pod
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    /// Annotation/label key whose value picks the proxy connection.
    /// Either a name in `connections:` or the reserved string `system`.
    #[serde(default = "default_connection_key", rename = "connectionKey")]
    pub connection_key: String,

    /// Annotation/label key whose value (`"true"` / `"false"`) toggles
    /// per-pod observation. Wins over rules and default.
    #[serde(default = "default_observe_key", rename = "observeKey")]
    pub observe_key: String,

    /// Admin-defined matching rules (first match wins). Used when a pod
    /// can't / shouldn't set the annotation keys itself — e.g. third-party
    /// charts, retroactive policy.
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Final fallback decision for pods not matching any rule and not
    /// carrying explicit annotations.
    #[serde(default)]
    pub default: RoutingDecision,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            connection_key: default_connection_key(),
            observe_key: default_observe_key(),
            rules: Vec::new(),
            default: RoutingDecision::default(),
        }
    }
}

fn default_connection_key() -> String { CONNECTION_KEY_DEFAULT.to_string() }
fn default_observe_key() -> String { OBSERVE_KEY_DEFAULT.to_string() }
fn default_use() -> String { "default".to_string() }
fn default_observe() -> bool { true }

/// One routing decision: which connection to use, and whether to
/// emit tap events. Both `Rule` and `Routing.default` produce one of
/// these; the runtime resolver returns it back to the relay.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingDecision {
    /// Connection name in `connections:`, or `"system"` to skip the
    /// eBPF redirect entirely.
    #[serde(default = "default_use", rename = "use")]
    pub use_: String,

    /// When false, eBPF tap programs suppress events from this pod's
    /// cgroup and userspace skips synthetic-flow logging for bypass /
    /// system connections.
    #[serde(default = "default_observe")]
    pub observe: bool,
}

impl Default for RoutingDecision {
    fn default() -> Self {
        Self { use_: default_use(), observe: default_observe() }
    }
}

impl std::fmt::Display for RoutingDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let obs = if self.observe { "observe" } else { "no-observe" };
        write!(f, "{}/{obs}", self.use_)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,

    #[serde(rename = "match")]
    pub r#match: Match,

    /// Connection name or `"system"`.
    #[serde(rename = "use")]
    pub use_: String,

    /// Whether tap events should fire for pods matching this rule.
    /// Defaults to true to match the historical "observe everything"
    /// behavior; set to false for noisy infrastructure.
    #[serde(default = "default_observe")]
    pub observe: bool,
}

impl Rule {
    pub fn decision(&self) -> RoutingDecision {
        RoutingDecision {
            use_: self.use_.clone(),
            observe: self.observe,
        }
    }
}

/// K8s LabelSelector-compatible match block, plus optional namespace filter.
/// Forward-compatible: unknown fields rejected to catch typos early.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default, rename = "matchLabels")]
    pub match_labels: BTreeMap<String, String>,

    #[serde(default, rename = "matchExpressions")]
    pub match_expressions: Vec<MatchExpression>,

    #[serde(default)]
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchExpression {
    pub key: String,
    pub operator: MatchOperator,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum MatchOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

const SUPPORTED_API_VERSION: &str = "heimdall.io/v1alpha1";
const SUPPORTED_KIND: &str = "HeimdallConfig";

impl HeimdallConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        let cfg: HeimdallConfig = serde_yaml::from_str(&raw)
            .map_err(|source| ConfigError::Parse { path: path.to_path_buf(), source })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.api_version != SUPPORTED_API_VERSION {
            return Err(ConfigError::UnsupportedApiVersion(self.api_version.clone()));
        }
        if self.kind != SUPPORTED_KIND {
            return Err(ConfigError::UnsupportedKind(self.kind.clone()));
        }

        // `system` is reserved — must NOT appear in connections:.
        if self.connections.contains_key(SYSTEM_CONNECTION) {
            return Err(ConfigError::ReservedConnectionName(SYSTEM_CONNECTION.into()));
        }

        // connections must define `default` (the implicit fallback target).
        if !self.connections.contains_key("default") {
            return Err(ConfigError::MissingDefaultConnection);
        }

        // routing.default.use must be a known connection or the reserved
        // `system` keyword.
        if !self.is_valid_use(&self.routing.default.use_) {
            return Err(ConfigError::DefaultConnectionUnknown(
                self.routing.default.use_.clone(),
            ));
        }

        // Each rule.use must be a known connection or `system`.
        for (i, rule) in self.routing.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(ConfigError::RuleMissingName { index: i });
            }
            if !self.is_valid_use(&rule.use_) {
                return Err(ConfigError::RuleConnectionUnknown {
                    index: i,
                    name: rule.name.clone(),
                    connection: rule.use_.clone(),
                });
            }
        }

        // socks5 connections must have non-empty addr
        for (name, conn) in &self.connections {
            if let Connection::Socks5(c) = conn {
                if c.addr.is_empty() {
                    return Err(ConfigError::EmptyAddr { name: name.clone(), ty: "socks5".into() });
                }
            }
        }

        Ok(())
    }

    fn is_valid_use(&self, name: &str) -> bool {
        name == SYSTEM_CONNECTION || self.connections.contains_key(name)
    }
}

impl Socks5Auth {
    /// Read the password file at `password_file`, trimming a single trailing
    /// newline if present (so `printf 'pw' > file` and `echo 'pw' > file`
    /// behave the same).
    pub fn read_password(&self) -> Result<String, ConfigError> {
        let bytes = fs::read(&self.password_file).map_err(|source| ConfigError::SecretRead {
            path: self.password_file.clone(),
            source,
        })?;
        let s = String::from_utf8_lossy(&bytes);
        Ok(s.strip_suffix('\n').unwrap_or(&s).to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    fn parse(yaml: &str) -> Result<HeimdallConfig, ConfigError> {
        let cfg: HeimdallConfig = serde_yaml::from_str(yaml)
            .map_err(|source| ConfigError::Parse { path: PathBuf::from("<test>"), source })?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn minimal_valid_config() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default:
                type: socks5
                addr: 127.0.0.1:20170
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.routing.default.use_, "default");
        assert!(cfg.routing.default.observe);
    }

    #[test]
    fn full_schema_with_rules() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            runtime:
              cgroup: /sys/fs/cgroup/kubepods
              listen: 0.0.0.0:12345
              relayIp: 10.244.0.41
              bypassCidrs: [100.64.0.0/10]
            connections:
              default:
                type: socks5
                addr: 127.0.0.1:20170
              corp:
                description: Mac LAN proxy
                type: socks5
                addr: <UPSTREAM_IP>:1080
                auth:
                  username: draven
                  passwordFile: /etc/heimdall/secrets/corp.pw
            routing:
              connectionKey: heimdall.io/connection
              observeKey: heimdall.io/observe
              rules:
                - name: cluster-infra
                  match: { namespaces: [kube-system] }
                  use: system
                  observe: false
                - name: corp-family
                  match:
                    matchLabels: { family: corp }
                    matchExpressions:
                      - { key: env, operator: In, values: [prod, stg] }
                  use: corp
                  observe: true
              default:
                use: default
                observe: true
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.connections.len(), 2);
        assert_eq!(cfg.routing.rules.len(), 2);
        assert_eq!(cfg.routing.rules[0].use_, "system");
        assert!(!cfg.routing.rules[0].observe);
        assert_eq!(
            cfg.routing.rules[1].r#match.match_labels.get("family"),
            Some(&"corp".to_string())
        );
    }

    #[test]
    fn rejects_unknown_connection_in_default() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default:
                type: socks5
                addr: 127.0.0.1:20170
            routing:
              default:
                use: nonexistent
                observe: true
        "#};
        assert!(matches!(parse(yaml), Err(ConfigError::DefaultConnectionUnknown(_))));
    }

    #[test]
    fn rejects_unknown_connection_in_rule() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            routing:
              rules:
                - name: r1
                  match: { matchLabels: { x: y } }
                  use: ghost
        "#};
        assert!(matches!(parse(yaml), Err(ConfigError::RuleConnectionUnknown { .. })));
    }

    #[test]
    fn accepts_system_use_value() {
        // `system` is reserved and need not appear in connections:.
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            routing:
              rules:
                - name: cluster-infra
                  match: { namespaces: [kube-system] }
                  use: system
                  observe: false
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.routing.rules[0].use_, "system");
    }

    #[test]
    fn rejects_user_naming_a_connection_system() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
              system: { type: direct }
        "#};
        assert!(matches!(parse(yaml), Err(ConfigError::ReservedConnectionName(_))));
    }

    #[test]
    fn rejects_wrong_api_version() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v999
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: x:1 }
        "#};
        assert!(matches!(parse(yaml), Err(ConfigError::UnsupportedApiVersion(_))));
    }

    #[test]
    fn rejects_unknown_field_typo() {
        // matchLables (typo) should fail loudly — that's why we deny_unknown_fields
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: x:1 }
            routing:
              rules:
                - name: r1
                  match: { matchLables: { x: y } }
                  use: default
        "#};
        assert!(parse(yaml).is_err());
    }
}
