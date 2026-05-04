//! Heimdall configuration schema.
//!
//! Single config file at `/etc/heimdall/heimdall.{yaml,json,toml,ncl}`
//! declares everything: runtime knobs, named upstream `connections`,
//! and `podRouting.rules` that map K8s pod selectors directly to a
//! connection name (or the reserved `system` tag for eBPF bypass).
//!
//! There is no destination-side routing — heimdall is a per-pod
//! proxy chooser, not a per-domain router. If you need destination-
//! based switching, build it into the upstream SOCKS5 server.
//!
//! Pod selectors mirror K8s `LabelSelector` exactly (`namespaces` +
//! `matchLabels` + `matchExpressions`) plus optional `all` / `any` /
//! `not` boolean composition.

use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use regex::Regex;
use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

pub const DEFAULT_DIR: &str = "/etc/heimdall";
pub const ROUTING_KEY_DEFAULT: &str = "heimdall.io/routing";
pub const OBSERVE_KEY_DEFAULT: &str = "heimdall.io/observe";

/// Probe `/etc/heimdall/heimdall.{ncl,toml,json,yaml}` and return the
/// first one that exists. Falls back to `heimdall.ncl` (the canonical
/// recommended format) if none are present so help text and error
/// messages have something to display.
pub fn default_config_path() -> PathBuf {
    let dir = Path::new(DEFAULT_DIR);
    for ext in ["ncl", "toml", "json", "yaml"] {
        let p = dir.join(format!("heimdall.{ext}"));
        if p.exists() {
            return p;
        }
    }
    dir.join("heimdall.ncl")
}

/// Reserved `use` value — when a pod resolves to `system`, the eBPF
/// connect4 hook skips redirection entirely. Cannot be used as a
/// connection name.
pub const SYSTEM_TAG: &str = "system";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("parse {path}: {source}")]
    Parse { path: PathBuf, source: serde_yaml::Error },
    #[error("parse {path}: {source}")]
    ParseJson { path: PathBuf, source: serde_json::Error },
    #[error("parse {path}: {source}")]
    ParseToml { path: PathBuf, source: toml::de::Error },
    #[error("apiVersion `{0}` is not supported (expected `heimdall.io/v1alpha1`)")]
    UnsupportedApiVersion(String),
    #[error("kind `{0}` is not supported (expected `HeimdallConfig`)")]
    UnsupportedKind(String),
    #[error("connections must define `default`")]
    MissingDefaultConnection,
    #[error("podRouting.default.use refers to unknown connection `{0}`")]
    DefaultRoutingUnknown(String),
    #[error("podRouting.rules[{index}] (`{name}`) refers to unknown connection `{tag}`")]
    RuleRoutingUnknown { index: usize, name: String, tag: String },
    #[error("connection name `{0}` is reserved")]
    ReservedConnectionName(String),
    #[error("connection `{name}` has empty addr (required for type `{ty}`)")]
    EmptyAddr { name: String, ty: String },
    #[error("read passwordFile `{path}`: {source}")]
    SecretRead { path: PathBuf, source: std::io::Error },
    #[error("regex compilation failed: {pattern}: {source}")]
    Regex { pattern: String, source: regex::Error },
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

    #[serde(rename = "podRouting", default)]
    pub pod_routing: PodRouting,

    /// Defaults for `heimdall <subcommand>` invocations (currently
    /// only `cli.run` is consumed). Optional — empty config = empty
    /// defaults; subcommand will fall back to compiled-in values.
    #[serde(default)]
    pub cli: Cli,
}

// ---------------------------------------------------------------------------
// runtime
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    #[serde(default = "default_cgroup")]
    pub cgroup: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_relay_ip", rename = "relayIp")]
    pub relay_ip: Ipv4Addr,
    #[serde(default, rename = "bypassCidrs")]
    pub bypass_cidrs: Vec<String>,

    #[serde(default = "default_dns_listen", rename = "dnsListen")]
    pub dns_listen: String,
    #[serde(default = "default_fake_ip_cidr", rename = "fakeIpCidr")]
    pub fake_ip_cidr: String,

    #[serde(default = "default_state_dir", rename = "stateDir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_flow_retention_secs", rename = "flowRetentionSecs")]
    pub flow_retention_secs: i64,
    #[serde(default = "default_api_listen", rename = "apiListen")]
    pub api_listen: String,
    #[serde(default)]
    pub tap: TapConfig,
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

fn default_cgroup() -> String { "/sys/fs/cgroup".into() }
fn default_listen() -> String { "0.0.0.0:12345".into() }
fn default_relay_ip() -> Ipv4Addr { Ipv4Addr::new(127, 0, 0, 1) }
fn default_dns_listen() -> String { "0.0.0.0:5358".into() }
fn default_fake_ip_cidr() -> String { "198.19.0.0/16".into() }
fn default_state_dir() -> PathBuf { PathBuf::from("/var/lib/heimdall") }
fn default_flow_retention_secs() -> i64 { 3 * 86400 }
fn default_api_listen() -> String { "127.0.0.1:9999".into() }

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TapConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub persist: bool,
}

// ---------------------------------------------------------------------------
// connections
// ---------------------------------------------------------------------------

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
    #[serde(default)]
    pub mitm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Auth {
    pub username: String,
    #[serde(rename = "passwordFile")]
    pub password_file: PathBuf,
}

impl Socks5Auth {
    pub fn read_password(&self) -> Result<String, ConfigError> {
        let bytes = fs::read(&self.password_file).map_err(|source| ConfigError::SecretRead {
            path: self.password_file.clone(),
            source,
        })?;
        let s = String::from_utf8_lossy(&bytes);
        Ok(s.strip_suffix('\n').unwrap_or(&s).to_string())
    }
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
// MatchValue — string with optional Xray-style prefix dispatch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum MatchValue {
    Exact(String),
    Regex(Regex),
    Prefix(String),
    Suffix(String),
    Keyword(String),
}

impl MatchValue {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        if let Some(pat) = s.strip_prefix("regexp:") {
            let re = Regex::new(pat).map_err(|source| ConfigError::Regex {
                pattern: pat.to_string(),
                source,
            })?;
            Ok(MatchValue::Regex(re))
        } else if let Some(p) = s.strip_prefix("prefix:") {
            Ok(MatchValue::Prefix(p.to_string()))
        } else if let Some(p) = s.strip_prefix("suffix:") {
            Ok(MatchValue::Suffix(p.to_string()))
        } else if let Some(p) = s.strip_prefix("keyword:") {
            Ok(MatchValue::Keyword(p.to_string()))
        } else {
            Ok(MatchValue::Exact(s.to_string()))
        }
    }

    pub fn matches(&self, target: &str) -> bool {
        match self {
            MatchValue::Exact(s) => target == s,
            MatchValue::Regex(re) => re.is_match(target),
            MatchValue::Prefix(p) => target.starts_with(p),
            MatchValue::Suffix(s) => target.ends_with(s),
            MatchValue::Keyword(k) => target.contains(k),
        }
    }
}

impl<'de> Deserialize<'de> for MatchValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MatchValue::parse(&s).map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// MatchExpression — K8s LabelSelector compatible
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchExpression {
    pub key: String,
    pub operator: MatchOperator,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum MatchOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

impl MatchExpression {
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        let val = labels.get(&self.key);
        match self.operator {
            MatchOperator::Exists => val.is_some(),
            MatchOperator::DoesNotExist => val.is_none(),
            MatchOperator::In => val
                .map(|v| self.values.iter().any(|x| x == v))
                .unwrap_or(false),
            MatchOperator::NotIn => val
                .map(|v| !self.values.iter().any(|x| x == v))
                .unwrap_or(true),
        }
    }
}

// ---------------------------------------------------------------------------
// MatchTarget trait + MatchCond evaluator
// ---------------------------------------------------------------------------

pub trait MatchTarget {
    fn pod_namespace(&self) -> Option<&str>;
    fn pod_labels(&self) -> &BTreeMap<String, String>;
}

/// Recursive boolean condition over pod selectors. Field-level AND
/// across populated fields, value-level OR within each list, plus
/// explicit `all` / `any` / `not` for arbitrary boolean composition.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchCond {
    #[serde(default)]
    pub namespaces: Vec<MatchValue>,
    #[serde(default, rename = "matchLabels")]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default, rename = "matchExpressions")]
    pub match_expressions: Vec<MatchExpression>,

    #[serde(default)]
    pub all: Vec<MatchCond>,
    #[serde(default)]
    pub any: Vec<MatchCond>,
    #[serde(default)]
    pub not: Option<Box<MatchCond>>,
}

impl MatchCond {
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
            && self.match_labels.is_empty()
            && self.match_expressions.is_empty()
            && self.all.is_empty()
            && self.any.is_empty()
            && self.not.is_none()
    }

    pub fn evaluate(&self, target: &dyn MatchTarget) -> bool {
        if self.is_empty() {
            return true;
        }

        if !self.namespaces.is_empty() {
            let ns = match target.pod_namespace() {
                Some(s) => s,
                None => return false,
            };
            if !self.namespaces.iter().any(|m| m.matches(ns)) {
                return false;
            }
        }

        if !self.match_labels.is_empty() {
            let labels = target.pod_labels();
            for (k, v) in &self.match_labels {
                match labels.get(k) {
                    Some(actual) if actual == v => continue,
                    _ => return false,
                }
            }
        }

        if !self.match_expressions.is_empty() {
            let labels = target.pod_labels();
            for expr in &self.match_expressions {
                if !expr.matches(labels) {
                    return false;
                }
            }
        }

        if !self.all.is_empty() && !self.all.iter().all(|c| c.evaluate(target)) {
            return false;
        }
        if !self.any.is_empty() && !self.any.iter().any(|c| c.evaluate(target)) {
            return false;
        }
        if let Some(n) = &self.not {
            if n.evaluate(target) {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// podRouting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodRouting {
    #[serde(default = "default_routing_key", rename = "routingKey")]
    pub routing_key: String,
    #[serde(default = "default_observe_key", rename = "observeKey")]
    pub observe_key: String,
    #[serde(default)]
    pub rules: Vec<PodRule>,
    #[serde(default)]
    pub default: PodDecision,
}

impl Default for PodRouting {
    fn default() -> Self {
        Self {
            routing_key: default_routing_key(),
            observe_key: default_observe_key(),
            rules: Vec::new(),
            default: PodDecision::default(),
        }
    }
}

fn default_routing_key() -> String { ROUTING_KEY_DEFAULT.into() }
fn default_observe_key() -> String { OBSERVE_KEY_DEFAULT.into() }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodRule {
    #[serde(default)]
    pub name: Option<String>,
    /// When None or empty, the rule matches every pod (catchall).
    #[serde(default, rename = "match")]
    pub match_: Option<MatchCond>,
    /// Connection name (must exist in `connections`) or the
    /// reserved `system` keyword.
    #[serde(rename = "use")]
    pub use_: String,
    /// When None, falls back to `PodRouting.default.observe`.
    #[serde(default)]
    pub observe: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodDecision {
    #[serde(rename = "use", default = "default_pod_use")]
    pub use_: String,
    #[serde(default)]
    pub observe: bool,
}

impl Default for PodDecision {
    fn default() -> Self {
        Self {
            use_: default_pod_use(),
            observe: false,
        }
    }
}

fn default_pod_use() -> String { "default".into() }

// ---------------------------------------------------------------------------
// cli — defaults for `heimdall <subcommand>` invocations
// ---------------------------------------------------------------------------
//
// Lets every default knob for CLI subcommands live in the same
// /etc/heimdall/heimdall.ncl as routing — no separate ~/.config/heimdall/
// file. Each subcommand hangs its config under `cli.<subcmd>`. Today
// only `cli.run` is consumed (by the planned proxychains-style
// `heimdall run`); adding a new subcommand later means adding a new
// optional field here without breaking existing configs.

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cli {
    #[serde(default)]
    pub run: CliRun,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliRun {
    /// Baseline applied when no `--profile` flag is given.
    #[serde(rename = "default", default)]
    pub default: CliRunProfile,

    /// Named profiles selectable via `--profile NAME`.
    #[serde(default)]
    pub profiles: BTreeMap<String, CliRunProfile>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliRunProfile {
    /// Connection name (or reserved `system`). None = inherit.
    pub connection: Option<String>,

    /// Capture plaintext via the tap. None = inherit.
    pub observe: Option<bool>,

    /// DNS resolution strategy for the wrapped command.
    pub dns: Option<DnsStrategy>,

    /// Hard timeout in seconds; 0 = no timeout.
    pub timeout: Option<u64>,

    /// Extra bypass CIDRs merged with daemon-global bypass list.
    #[serde(rename = "extraBypass")]
    pub extra_bypass: Option<Vec<String>>,

    /// Free-form label; surfaces on the flow log entries for this run.
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// Use heimdall's fake-IP DNS resolver. The relay reverses to a
    /// hostname before forwarding via SOCKS5 ATYP=0x03.
    Fake,
    /// Bypass fake-IP; let the wrapped command's libc resolver hit
    /// whatever it usually hits (host's /etc/resolv.conf).
    System,
}

impl Default for DnsStrategy {
    fn default() -> Self { DnsStrategy::Fake }
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

const SUPPORTED_API_VERSION: &str = "heimdall.io/v1alpha1";
const SUPPORTED_KIND: &str = "HeimdallConfig";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Json,
    Toml,
    Nickel,
}

impl Format {
    pub fn detect(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "yaml" | "yml" => Some(Format::Yaml),
            "json" => Some(Format::Json),
            "toml" => Some(Format::Toml),
            "ncl" => Some(Format::Nickel),
            _ => None,
        }
    }
}

impl HeimdallConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let cfg: HeimdallConfig = parse_typed(path)?;
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

        if self.connections.contains_key(SYSTEM_TAG) {
            return Err(ConfigError::ReservedConnectionName(SYSTEM_TAG.into()));
        }

        if !self.connections.contains_key("default") {
            return Err(ConfigError::MissingDefaultConnection);
        }

        for (name, conn) in &self.connections {
            if let Connection::Socks5(c) = conn {
                if c.addr.is_empty() {
                    return Err(ConfigError::EmptyAddr {
                        name: name.clone(),
                        ty: "socks5".into(),
                    });
                }
            }
        }

        // Each rule's `use` must be `system` or a known connection.
        for (i, rule) in self.pod_routing.rules.iter().enumerate() {
            if !self.is_valid_use(&rule.use_) {
                return Err(ConfigError::RuleRoutingUnknown {
                    index: i,
                    name: rule.name.clone().unwrap_or_default(),
                    tag: rule.use_.clone(),
                });
            }
        }
        if !self.is_valid_use(&self.pod_routing.default.use_) {
            return Err(ConfigError::DefaultRoutingUnknown(
                self.pod_routing.default.use_.clone(),
            ));
        }

        Ok(())
    }

    fn is_valid_use(&self, use_: &str) -> bool {
        use_ == SYSTEM_TAG || self.connections.contains_key(use_)
    }
}

pub fn parse_typed<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let format = Format::detect(path).unwrap_or(Format::Yaml);
    match format {
        Format::Yaml => {
            let raw = fs::read_to_string(path)
                .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
            serde_yaml::from_str(&raw)
                .map_err(|source| ConfigError::Parse { path: path.to_path_buf(), source })
        }
        Format::Json => {
            let raw = fs::read_to_string(path)
                .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
            serde_json::from_str(&raw)
                .map_err(|source| ConfigError::ParseJson { path: path.to_path_buf(), source })
        }
        Format::Toml => {
            let raw = fs::read_to_string(path)
                .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
            toml::from_str(&raw)
                .map_err(|source| ConfigError::ParseToml { path: path.to_path_buf(), source })
        }
        Format::Nickel => {
            let json = run_nickel_export(path)?;
            serde_json::from_str(&json)
                .map_err(|source| ConfigError::ParseJson { path: path.to_path_buf(), source })
        }
    }
}

fn run_nickel_export(path: &Path) -> Result<String, ConfigError> {
    use std::process::Command;
    let out = Command::new("nickel")
        .arg("export")
        .arg("-f")
        .arg("json")
        .arg(path)
        .output()
        .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
    if !out.status.success() {
        return Err(ConfigError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::other(format!(
                "nickel export failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    fn parse(yaml: &str) -> Result<HeimdallConfig, ConfigError> {
        let cfg: HeimdallConfig = serde_yaml::from_str(yaml).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<test>"),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn minimal_config() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.pod_routing.default.use_, "default");
    }

    #[test]
    fn match_value_prefixes() {
        assert!(MatchValue::parse("kube-system").unwrap().matches("kube-system"));
        assert!(MatchValue::parse("regexp:^cattle-.*$").unwrap().matches("cattle-system"));
        assert!(MatchValue::parse("prefix:cattle-").unwrap().matches("cattle-system"));
        assert!(MatchValue::parse("suffix:-system").unwrap().matches("cattle-system"));
        assert!(MatchValue::parse("keyword:tle-sys").unwrap().matches("cattle-system"));
    }

    #[test]
    fn match_expressions_all_operators() {
        let labels: BTreeMap<String, String> = [
            ("app".to_string(), "rancher".to_string()),
            ("tier".to_string(), "backend".to_string()),
        ]
        .into_iter()
        .collect();

        let in_op = MatchExpression {
            key: "app".into(),
            operator: MatchOperator::In,
            values: vec!["rancher".into(), "fleet".into()],
        };
        assert!(in_op.matches(&labels));

        let notin = MatchExpression {
            key: "app".into(),
            operator: MatchOperator::NotIn,
            values: vec!["mysql".into()],
        };
        assert!(notin.matches(&labels));

        let exists = MatchExpression {
            key: "tier".into(),
            operator: MatchOperator::Exists,
            values: vec![],
        };
        assert!(exists.matches(&labels));

        let absent = MatchExpression {
            key: "missing".into(),
            operator: MatchOperator::DoesNotExist,
            values: vec![],
        };
        assert!(absent.matches(&labels));
    }

    struct TestPod {
        ns: &'static str,
        labels: BTreeMap<String, String>,
    }

    impl MatchTarget for TestPod {
        fn pod_namespace(&self) -> Option<&str> {
            Some(self.ns)
        }
        fn pod_labels(&self) -> &BTreeMap<String, String> {
            &self.labels
        }
    }

    fn pod(ns: &'static str, labels: &[(&str, &str)]) -> TestPod {
        TestPod {
            ns,
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn cond_yaml(s: &str) -> MatchCond {
        serde_yaml::from_str(s).unwrap()
    }

    #[test]
    fn evaluate_namespaces_and_match_labels() {
        let p = pod("opik", &[("app.kubernetes.io/name", "mysql")]);
        let c = cond_yaml(indoc! {r#"
            namespaces: [opik, kube-system]
            matchLabels:
              "app.kubernetes.io/name": mysql
        "#});
        assert!(c.evaluate(&p));
    }

    #[test]
    fn evaluate_match_expressions() {
        let p = pod("cattle-fleet-system", &[("app", "fleet-agent")]);
        let c = cond_yaml(indoc! {"
            matchExpressions:
              - { key: app, operator: In, values: [fleet-agent, gitjob] }
        "});
        assert!(c.evaluate(&p));
    }

    #[test]
    fn evaluate_any_or() {
        let p = pod("cattle-system", &[("app", "rancher")]);
        let c = cond_yaml(indoc! {"
            any:
              - namespaces: [cattle-system]
                matchLabels: { app: rancher }
              - namespaces: [cattle-fleet-system]
        "});
        assert!(c.evaluate(&p));
    }

    #[test]
    fn evaluate_all_and_not() {
        let p_app = pod("opik", &[("app.kubernetes.io/name", "opik")]);
        let p_db = pod("opik", &[("app.kubernetes.io/name", "mysql")]);
        let c = cond_yaml(indoc! {r#"
            all:
              - namespaces: [opik]
              - not:
                  matchExpressions:
                    - { key: "app.kubernetes.io/name", operator: In, values: [mysql, redis] }
        "#});
        assert!(c.evaluate(&p_app));
        assert!(!c.evaluate(&p_db));
    }

    #[test]
    fn rejects_reserved_system() {
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
    fn rejects_unknown_use_in_rule() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            podRouting:
              rules:
                - match: { namespaces: [foo] }
                  use: ghost
        "#};
        assert!(matches!(parse(yaml), Err(ConfigError::RuleRoutingUnknown { .. })));
    }

    #[test]
    fn accepts_use_system() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            podRouting:
              rules:
                - match: { namespaces: [kube-system] }
                  use: system
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.pod_routing.rules[0].use_, "system");
    }

    #[test]
    fn format_detect() {
        assert_eq!(Format::detect(Path::new("a.yaml")), Some(Format::Yaml));
        assert_eq!(Format::detect(Path::new("a.yml")), Some(Format::Yaml));
        assert_eq!(Format::detect(Path::new("a.json")), Some(Format::Json));
        assert_eq!(Format::detect(Path::new("a.toml")), Some(Format::Toml));
        assert_eq!(Format::detect(Path::new("a.ncl")), Some(Format::Nickel));
        assert_eq!(Format::detect(Path::new("a")), None);
    }
}
