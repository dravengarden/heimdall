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
pub const ANNOTATION_KEY_DEFAULT: &str = "heimdall.io/connection";

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
    #[error("routing.default refers to unknown connection `{0}`")]
    DefaultConnectionUnknown(String),
    #[error("routing.rules[{index}] (`{name}`) refers to unknown connection `{connection}`")]
    RuleConnectionUnknown { index: usize, name: String, connection: String },
    #[error("routing.rules[{index}] is missing a name")]
    RuleMissingName { index: usize },
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
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            cgroup: default_cgroup(),
            listen: default_listen(),
            relay_ip: default_relay_ip(),
            bypass_cidrs: Vec::new(),
        }
    }
}

fn default_cgroup() -> String { "/sys/fs/cgroup".to_string() }
fn default_listen() -> String { "0.0.0.0:12345".to_string() }
fn default_relay_ip() -> Ipv4Addr { Ipv4Addr::new(127, 0, 0, 1) }

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
    /// Pod annotation key; if a pod has this annotation pointing at a known
    /// connection, that wins over rules + default.
    #[serde(default = "default_annotation_key", rename = "annotationKey")]
    pub annotation_key: String,

    /// Admin-defined label-matching rules. First match wins.
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Final fallback connection name. Must reference an entry in
    /// `connections` (validated at load time).
    #[serde(default = "default_default_connection")]
    pub default: String,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            annotation_key: default_annotation_key(),
            rules: Vec::new(),
            default: default_default_connection(),
        }
    }
}

fn default_annotation_key() -> String { ANNOTATION_KEY_DEFAULT.to_string() }
fn default_default_connection() -> String { "default".to_string() }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,

    #[serde(rename = "match")]
    pub r#match: Match,

    /// Name of a connection in the registry.
    #[serde(rename = "use")]
    pub use_: String,
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

        // connections.default must exist
        if !self.connections.contains_key("default")
            && !self.connections.contains_key(&self.routing.default)
        {
            // If routing.default is also missing from connections, fail early.
            // (Most users will have a connection literally named "default".)
            return Err(ConfigError::MissingDefaultConnection);
        }

        // routing.default must reference a known connection
        if !self.connections.contains_key(&self.routing.default) {
            return Err(ConfigError::DefaultConnectionUnknown(self.routing.default.clone()));
        }

        // Each rule.use must reference a known connection
        for (i, rule) in self.routing.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(ConfigError::RuleMissingName { index: i });
            }
            if !self.connections.contains_key(&rule.use_) {
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

    /// The connection used when no annotation and no rule matches.
    pub fn default_connection(&self) -> &Connection {
        // Validated at load: routing.default exists in connections.
        self.connections.get(&self.routing.default).expect("validated")
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
        assert_eq!(cfg.routing.default, "default");
        assert!(matches!(cfg.default_connection(), Connection::Socks5(_)));
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
              bypass:
                type: direct
            routing:
              annotationKey: heimdall.io/connection
              rules:
                - name: corp-family
                  match:
                    matchLabels: { family: corp }
                    matchExpressions:
                      - { key: env, operator: In, values: [prod, stg] }
                  use: corp
              default: default
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.connections.len(), 3);
        assert_eq!(cfg.routing.rules.len(), 1);
        assert_eq!(cfg.routing.rules[0].r#match.match_labels.get("family"), Some(&"corp".to_string()));
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
              default: nonexistent
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
