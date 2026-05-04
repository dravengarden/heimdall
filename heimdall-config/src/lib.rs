//! Heimdall configuration schema.
//!
//! Two-level config:
//!
//!   1. **Main config** (`/etc/heimdall/config.{yaml,json,ncl}`) — declares
//!      `connections:` (named upstreams) and `podRouting:` (which routing
//!      file each pod uses, plus the observe flag).
//!
//!   2. **Routing files** (`/etc/heimdall/routing/<tag>.{yaml,json,ncl}`) —
//!      each is a self-contained Xray-subset routing config that maps
//!      destination matchers to an `outboundTag` referencing
//!      `connections:`. The `tag` part of the filename is referenced by
//!      `podRouting.rules[].use`.
//!
//! Both pod selectors and destination matchers share the same recursive
//! `MatchCond` shape (with field-level AND, value-level OR, and explicit
//! `all` / `any` / `not` operators for arbitrary boolean composition).
//! Match values support a Xray-style prefix syntax for regex / prefix /
//! suffix / keyword matching.

use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use ipnet::Ipv4Net;
use regex::Regex;
use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

pub const DEFAULT_PATH: &str = "/etc/heimdall/config.yaml";
pub const CONNECTION_KEY_DEFAULT: &str = "heimdall.io/routing";
pub const OBSERVE_KEY_DEFAULT: &str = "heimdall.io/observe";

/// Reserved tag for `podRouting.rules[].use` (and the routing annotation
/// value) — when a pod resolves to `system`, the eBPF connect4 hook
/// skips redirection entirely. Cannot be used as a routing-file name
/// nor as a connection name.
pub const SYSTEM_TAG: &str = "system";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("parse {path}: {source}")]
    Parse { path: PathBuf, source: serde_yaml::Error },
    #[error("parse {path}: {source}")]
    ParseJson { path: PathBuf, source: serde_json::Error },
    #[error("apiVersion `{0}` is not supported (expected `heimdall.io/v1alpha1`)")]
    UnsupportedApiVersion(String),
    #[error("kind `{0}` is not supported (expected `HeimdallConfig`)")]
    UnsupportedKind(String),
    #[error("connections must define `default`")]
    MissingDefaultConnection,
    #[error("podRouting.default.use refers to unknown routing tag `{0}`")]
    DefaultRoutingUnknown(String),
    #[error("podRouting.rules[{index}] (`{name}`) refers to unknown routing tag `{tag}`")]
    RuleRoutingUnknown { index: usize, name: String, tag: String },
    #[error("connection name `{0}` is reserved")]
    ReservedConnectionName(String),
    #[error("connection `{name}` has empty addr (required for type `{ty}`)")]
    EmptyAddr { name: String, ty: String },
    #[error("read passwordFile `{path}`: {source}")]
    SecretRead { path: PathBuf, source: std::io::Error },
    #[error("regex compilation failed: {pattern}: {source}")]
    Regex { pattern: String, source: regex::Error },
    #[error("invalid CIDR `{value}`: {reason}")]
    InvalidCidr { value: String, reason: String },
    #[error("invalid port spec `{value}`: {reason}")]
    InvalidPort { value: String, reason: String },
    #[error("invalid label expression `{value}`: {reason}")]
    InvalidLabel { value: String, reason: String },
    #[error("routing file `{path}` references unknown outboundTag `{tag}`")]
    UnknownOutboundTag { path: PathBuf, tag: String },
}

// ---------------------------------------------------------------------------
// Top-level main config
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
}

// ---------------------------------------------------------------------------
// runtime — eBPF + relay knobs
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

    #[serde(default = "default_routing_dir", rename = "routingDir")]
    pub routing_dir: PathBuf,

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
            routing_dir: default_routing_dir(),
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
fn default_routing_dir() -> PathBuf { PathBuf::from("/etc/heimdall/routing") }
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
// connections — named upstream registry
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
// MatchValue — string with prefix dispatch
// ---------------------------------------------------------------------------

/// A single value matcher used by all string-shaped fields (namespace,
/// app, label values, domain). Default is exact match; prefixes
/// `regexp:` / `prefix:` / `suffix:` / `keyword:` switch behavior.
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
        } else if s.starts_with("domain:") || s.starts_with("subdomain:")
            || s.starts_with("full:") || s.starts_with("geosite:")
            || s.starts_with("geoip:")
        {
            // Xray-specific prefixes — keep as Exact so the matcher
            // evaluator can dispatch (or warn) per type. Stored verbatim.
            Ok(MatchValue::Exact(s.to_string()))
        } else {
            Ok(MatchValue::Exact(s.to_string()))
        }
    }

    /// Test whether `target` satisfies this matcher.
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
// LabelExpr — "key=value", "key=*", "key" semantics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LabelExpr {
    pub key: String,
    pub value: LabelValueMatcher,
}

#[derive(Debug, Clone)]
pub enum LabelValueMatcher {
    /// Key must exist with any value (`"key"` or `"key=*"`).
    Exists,
    /// Value must match (supports MatchValue prefix syntax).
    Match(MatchValue),
}

impl LabelExpr {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s.split_once('=') {
            Some((k, "*")) | Some((k, "")) => Ok(LabelExpr {
                key: k.to_string(),
                value: LabelValueMatcher::Exists,
            }),
            Some((k, v)) => Ok(LabelExpr {
                key: k.to_string(),
                value: LabelValueMatcher::Match(MatchValue::parse(v)?),
            }),
            None => {
                // bare "key" → key exists
                if s.is_empty() {
                    return Err(ConfigError::InvalidLabel {
                        value: s.to_string(),
                        reason: "empty label expression".into(),
                    });
                }
                Ok(LabelExpr {
                    key: s.to_string(),
                    value: LabelValueMatcher::Exists,
                })
            }
        }
    }

    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match labels.get(&self.key) {
            None => false,
            Some(v) => match &self.value {
                LabelValueMatcher::Exists => true,
                LabelValueMatcher::Match(m) => m.matches(v),
            },
        }
    }
}

impl<'de> Deserialize<'de> for LabelExpr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        LabelExpr::parse(&s).map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// IpCidr / PortSpec — destination matchers
// ---------------------------------------------------------------------------

/// Wraps `Ipv4Net` for serde + `geoip:` prefix tolerance (Xray compat —
/// we don't support geoip databases, so those are dropped at parse time
/// with a warning).
#[derive(Debug, Clone)]
pub enum IpCidr {
    Net(Ipv4Net),
    /// Xray's `geoip:cn` style — recognized but skipped. Kept so we can
    /// warn at load time without failing.
    GeoIp(String),
}

impl IpCidr {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        if let Some(name) = s.strip_prefix("geoip:") {
            return Ok(IpCidr::GeoIp(name.to_string()));
        }
        // Try as CIDR; accept bare IP as /32.
        if let Ok(net) = s.parse::<Ipv4Net>() {
            return Ok(IpCidr::Net(net));
        }
        if let Ok(addr) = s.parse::<Ipv4Addr>() {
            return Ok(IpCidr::Net(Ipv4Net::new(addr, 32).unwrap()));
        }
        Err(ConfigError::InvalidCidr {
            value: s.to_string(),
            reason: "not a valid IPv4 CIDR or geoip: prefix".into(),
        })
    }

    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        match self {
            IpCidr::Net(net) => net.contains(&ip),
            IpCidr::GeoIp(_) => false, // unsupported; skip
        }
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        IpCidr::parse(&s).map_err(de::Error::custom)
    }
}

/// Xray-style port spec: `"443"`, `"80,443"`, `"1000-2000"`, or any
/// combination of the above.
#[derive(Debug, Clone, Default)]
pub struct PortSpec {
    pub points: Vec<u16>,
    pub ranges: Vec<(u16, u16)>,
}

impl PortSpec {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let mut spec = PortSpec::default();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((lo, hi)) = part.split_once('-') {
                let lo: u16 = lo.trim().parse().map_err(|_| ConfigError::InvalidPort {
                    value: s.to_string(),
                    reason: format!("invalid range start: {lo}"),
                })?;
                let hi: u16 = hi.trim().parse().map_err(|_| ConfigError::InvalidPort {
                    value: s.to_string(),
                    reason: format!("invalid range end: {hi}"),
                })?;
                if lo > hi {
                    return Err(ConfigError::InvalidPort {
                        value: s.to_string(),
                        reason: format!("range {lo}-{hi} is reversed"),
                    });
                }
                spec.ranges.push((lo, hi));
            } else {
                let p: u16 = part.parse().map_err(|_| ConfigError::InvalidPort {
                    value: s.to_string(),
                    reason: format!("invalid port: {part}"),
                })?;
                spec.points.push(p);
            }
        }
        Ok(spec)
    }

    pub fn matches(&self, port: u16) -> bool {
        if self.points.iter().any(|p| *p == port) {
            return true;
        }
        if self.ranges.iter().any(|(lo, hi)| port >= *lo && port <= *hi) {
            return true;
        }
        false
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PortSpec::parse(&s).map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// MatchTarget trait + evaluator
// ---------------------------------------------------------------------------

/// Anything a `MatchCond` can be evaluated against. Pod info implements
/// `pod_*` methods; connection-destination info implements `dst_*` and
/// `network`. A field-method returning `None` means "this attribute
/// doesn't apply to this target" — matchers that reference such a
/// field then evaluate to `false`.
pub trait MatchTarget {
    fn pod_namespace(&self) -> Option<&str> {
        None
    }
    fn pod_label(&self, _key: &str) -> Option<&str> {
        None
    }
    /// Used by the `app:` shorthand — checks both the modern Helm
    /// label and the legacy `app` label. Default reads them via
    /// `pod_label`.
    fn pod_app_value(&self) -> Option<&str> {
        self.pod_label("app.kubernetes.io/name")
            .or_else(|| self.pod_label("app"))
    }

    fn dst_host(&self) -> Option<&str> {
        None
    }
    fn dst_ip(&self) -> Option<Ipv4Addr> {
        None
    }
    fn dst_port(&self) -> Option<u16> {
        None
    }
    fn network(&self) -> Option<&str> {
        Some("tcp")
    }
}

impl MatchCond {
    /// Evaluate this condition against a target. An empty condition
    /// evaluates to `true` (catchall).
    pub fn evaluate(&self, target: &dyn MatchTarget) -> bool {
        if self.is_empty() {
            return true;
        }

        // Field-level matchers (implicit AND across fields).
        if !self.namespace.is_empty() {
            let ns = match target.pod_namespace() {
                Some(s) => s,
                None => return false,
            };
            if !self.namespace.iter().any(|m| m.matches(ns)) {
                return false;
            }
        }

        if !self.app.is_empty() {
            let app = match target.pod_app_value() {
                Some(s) => s,
                None => return false,
            };
            if !self.app.iter().any(|m| m.matches(app)) {
                return false;
            }
        }

        if !self.label.is_empty() {
            // Build a small map view via the trait — every label expr
            // checks key existence + optional value match.
            for expr in &self.label {
                let val = target.pod_label(&expr.key);
                let ok = match (val, &expr.value) {
                    (None, _) => false,
                    (Some(_), LabelValueMatcher::Exists) => true,
                    (Some(v), LabelValueMatcher::Match(m)) => m.matches(v),
                };
                if !ok {
                    return false;
                }
            }
        }

        if !self.domain.is_empty() {
            let host = match target.dst_host() {
                Some(s) => s,
                None => return false,
            };
            if !self.domain.iter().any(|m| domain_match(m, host)) {
                return false;
            }
        }

        if !self.ip.is_empty() {
            let ip = match target.dst_ip() {
                Some(i) => i,
                None => return false,
            };
            if !self.ip.iter().any(|c| c.matches(ip)) {
                return false;
            }
        }

        if let Some(spec) = &self.port {
            let p = match target.dst_port() {
                Some(p) => p,
                None => return false,
            };
            if !spec.matches(p) {
                return false;
            }
        }

        if let Some(net) = &self.network {
            let actual = target.network().unwrap_or("tcp");
            // Xray accepts comma-separated network list ("tcp,udp")
            if !net.split(',').map(str::trim).any(|n| n == actual) {
                return false;
            }
        }

        // Boolean composition (AND through, OR within `any`, negate `not`).
        if !self.all.is_empty() {
            if !self.all.iter().all(|c| c.evaluate(target)) {
                return false;
            }
        }
        if !self.any.is_empty() {
            if !self.any.iter().any(|c| c.evaluate(target)) {
                return false;
            }
        }
        if let Some(n) = &self.not {
            if n.evaluate(target) {
                return false;
            }
        }

        true
    }
}

/// Domain match with Xray-style prefix dispatch on the matcher value.
/// `MatchValue::Exact("domain:foo.com")` style strings are interpreted
/// here (the parser stored them verbatim so the eval can apply Xray
/// semantics).
fn domain_match(m: &MatchValue, host: &str) -> bool {
    match m {
        MatchValue::Exact(s) => {
            if let Some(rest) = s.strip_prefix("domain:") {
                host == rest || host.ends_with(&format!(".{rest}"))
            } else if let Some(rest) = s.strip_prefix("subdomain:") {
                host.ends_with(&format!(".{rest}"))
            } else if let Some(rest) = s.strip_prefix("full:") {
                host == rest
            } else if s.starts_with("geosite:") || s.starts_with("geoip:") {
                false // not supported; warn at load time, never match at eval
            } else {
                // Bare exact (no Xray prefix) — strict equality.
                host == s
            }
        }
        MatchValue::Regex(re) => re.is_match(host),
        MatchValue::Prefix(p) => host.starts_with(p),
        MatchValue::Suffix(s) => host.ends_with(s),
        MatchValue::Keyword(k) => host.contains(k),
    }
}

// ---------------------------------------------------------------------------
// MatchCond — recursive boolean condition
// ---------------------------------------------------------------------------

/// Recursive condition with implicit AND between fields, OR within each
/// list field, and explicit `all`/`any`/`not` for arbitrary boolean
/// composition. Used by both pod selectors and routing-file rules; per-
/// use-case fields apply where relevant.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchCond {
    // ── Pod selectors ─────────────────────────────────────────────
    #[serde(default)]
    pub namespace: Vec<MatchValue>,
    #[serde(default)]
    pub app: Vec<MatchValue>,
    #[serde(default)]
    pub label: Vec<LabelExpr>,

    // ── Destination matchers ──────────────────────────────────────
    #[serde(default)]
    pub domain: Vec<MatchValue>,
    #[serde(default)]
    pub ip: Vec<IpCidr>,
    #[serde(default)]
    pub port: Option<PortSpec>,
    #[serde(default)]
    pub network: Option<String>,

    // ── Boolean composition ───────────────────────────────────────
    #[serde(default)]
    pub all: Vec<MatchCond>,
    #[serde(default)]
    pub any: Vec<MatchCond>,
    #[serde(default)]
    pub not: Option<Box<MatchCond>>,
}

impl MatchCond {
    /// True when no matcher fields are populated — acts as catchall.
    pub fn is_empty(&self) -> bool {
        self.namespace.is_empty()
            && self.app.is_empty()
            && self.label.is_empty()
            && self.domain.is_empty()
            && self.ip.is_empty()
            && self.port.is_none()
            && self.network.is_none()
            && self.all.is_empty()
            && self.any.is_empty()
            && self.not.is_none()
    }
}

// ---------------------------------------------------------------------------
// podRouting — top-level pod → routing-tag mapping
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

fn default_routing_key() -> String { CONNECTION_KEY_DEFAULT.into() }
fn default_observe_key() -> String { OBSERVE_KEY_DEFAULT.into() }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodRule {
    #[serde(default)]
    pub name: Option<String>,
    /// When None or empty, the rule matches every pod (catchall).
    #[serde(default, rename = "match")]
    pub match_: Option<MatchCond>,
    /// Routing tag — either a routing-file name or the reserved `system`.
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
// Routing files (Xray subset) — destination-side rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingFile {
    #[serde(default = "default_domain_strategy", rename = "domainStrategy")]
    pub domain_strategy: DomainStrategy,
    #[serde(default)]
    pub rules: Vec<XrayRule>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum DomainStrategy {
    AsIs,
    /// Parsed but treated as AsIs (we always have both domain + IP via
    /// fake-IP DNS, so the resolution-order strategy doesn't apply).
    IPIfNonMatch,
    IPOnDemand,
}

fn default_domain_strategy() -> DomainStrategy { DomainStrategy::AsIs }

/// One destination-routing rule. `MatchCond` is flattened into the rule
/// per Xray convention (matchers and outcome at the same level).
/// `outboundTag` is the only required field.
#[derive(Debug, Clone, Deserialize)]
pub struct XrayRule {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,

    // Inline matcher fields (Xray flat style)
    #[serde(flatten)]
    pub matcher: MatchCond,

    #[serde(rename = "outboundTag")]
    pub outbound_tag: String,
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

const SUPPORTED_API_VERSION: &str = "heimdall.io/v1alpha1";
const SUPPORTED_KIND: &str = "HeimdallConfig";

/// Detected file format based on extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Json,
    Nickel,
}

impl Format {
    pub fn detect(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "yaml" | "yml" => Some(Format::Yaml),
            "json" => Some(Format::Json),
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

        // `system` is reserved as a tag; don't allow as a connection name.
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
        Ok(())
    }
}

/// Parse a file into the target type using format detected by extension.
/// For Nickel files, shells out to the `nickel` CLI to evaluate to JSON.
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
        Format::Nickel => {
            let json = run_nickel_export(path)?;
            serde_json::from_str(&json)
                .map_err(|source| ConfigError::ParseJson { path: path.to_path_buf(), source })
        }
    }
}

/// Shell out to `nickel export -f json <path>`. The Nickel binary must
/// be in `PATH`; on NixOS, add `pkgs.nickel` to the heimdall service's
/// environment.
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

impl RoutingFile {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        parse_typed(path.as_ref())
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
        assert!(matches!(MatchValue::parse("kube-system").unwrap(), MatchValue::Exact(_)));
        assert!(matches!(MatchValue::parse("regexp:cattle-.*").unwrap(), MatchValue::Regex(_)));
        assert!(matches!(MatchValue::parse("prefix:cattle-").unwrap(), MatchValue::Prefix(_)));
        assert!(matches!(MatchValue::parse("suffix:-system").unwrap(), MatchValue::Suffix(_)));
        assert!(matches!(MatchValue::parse("keyword:fleet").unwrap(), MatchValue::Keyword(_)));

        assert!(MatchValue::parse("kube-system").unwrap().matches("kube-system"));
        assert!(!MatchValue::parse("kube-system").unwrap().matches("kube-public"));
        assert!(MatchValue::parse("regexp:^cattle-.*$").unwrap().matches("cattle-system"));
        assert!(MatchValue::parse("prefix:cattle-").unwrap().matches("cattle-system"));
        assert!(MatchValue::parse("suffix:-system").unwrap().matches("cattle-system"));
        assert!(MatchValue::parse("keyword:tle-sys").unwrap().matches("cattle-system"));
    }

    #[test]
    fn label_expr() {
        let labels: BTreeMap<String, String> = [
            ("app".to_string(), "rancher".to_string()),
            ("tier".to_string(), "backend".to_string()),
        ]
        .into_iter()
        .collect();

        assert!(LabelExpr::parse("app=rancher").unwrap().matches(&labels));
        assert!(!LabelExpr::parse("app=ghost").unwrap().matches(&labels));
        assert!(LabelExpr::parse("tier=*").unwrap().matches(&labels));
        assert!(LabelExpr::parse("missing=*").unwrap().matches(&labels) == false);
        assert!(LabelExpr::parse("app=regexp:^ranch.*$").unwrap().matches(&labels));
    }

    #[test]
    fn port_spec() {
        let p = PortSpec::parse("80,443,1000-2000").unwrap();
        assert!(p.matches(80));
        assert!(p.matches(443));
        assert!(p.matches(1500));
        assert!(!p.matches(81));
        assert!(!p.matches(2001));
    }

    #[test]
    fn ip_cidr() {
        let n = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(n.matches("10.1.2.3".parse().unwrap()));
        assert!(!n.matches("11.1.2.3".parse().unwrap()));

        let geo = IpCidr::parse("geoip:cn").unwrap();
        // unsupported; never matches but parses.
        assert!(!geo.matches("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn pod_rule_with_boolean() {
        let yaml = indoc! {r#"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            podRouting:
              rules:
                - name: opik-non-data
                  match:
                    all:
                      - namespace: [opik]
                      - not:
                          app: [mysql, redis]
                  use: default
                  observe: true
              default:
                use: default
                observe: false
        "#};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.pod_routing.rules.len(), 1);
        let r = &cfg.pod_routing.rules[0];
        assert_eq!(r.name.as_deref(), Some("opik-non-data"));
        let m = r.match_.as_ref().unwrap();
        assert_eq!(m.all.len(), 2);
        assert!(m.all[0].namespace.len() == 1);
        assert!(m.all[1].not.is_some());
    }

    #[test]
    fn rejects_reserved_system_as_connection() {
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
    fn routing_file_parses() {
        let yaml = indoc! {r#"
            domainStrategy: AsIs
            rules:
              - domain: ["regexp:.*\\.corp\\..*"]
                outboundTag: corp
              - ip: ["10.0.0.0/8"]
                outboundTag: direct
              - outboundTag: default
        "#};
        let f: RoutingFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(f.rules.len(), 3);
        assert_eq!(f.rules[2].outbound_tag, "default");
    }

    #[test]
    fn format_detect() {
        assert_eq!(Format::detect(Path::new("config.yaml")), Some(Format::Yaml));
        assert_eq!(Format::detect(Path::new("config.yml")), Some(Format::Yaml));
        assert_eq!(Format::detect(Path::new("config.json")), Some(Format::Json));
        assert_eq!(Format::detect(Path::new("config.ncl")), Some(Format::Nickel));
        assert_eq!(Format::detect(Path::new("config")), None);
    }

    // ── MatchCond evaluator ────────────────────────────────────────────

    struct TestPod {
        ns: &'static str,
        labels: BTreeMap<String, String>,
    }

    impl MatchTarget for TestPod {
        fn pod_namespace(&self) -> Option<&str> {
            Some(self.ns)
        }
        fn pod_label(&self, key: &str) -> Option<&str> {
            self.labels.get(key).map(|s| s.as_str())
        }
    }

    struct TestDst {
        host: Option<&'static str>,
        ip: Option<Ipv4Addr>,
        port: u16,
    }

    impl MatchTarget for TestDst {
        fn dst_host(&self) -> Option<&str> {
            self.host
        }
        fn dst_ip(&self) -> Option<Ipv4Addr> {
            self.ip
        }
        fn dst_port(&self) -> Option<u16> {
            Some(self.port)
        }
    }

    fn pod(ns: &'static str, labels: &[(&str, &str)]) -> TestPod {
        TestPod {
            ns,
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn cond_yaml(s: &str) -> MatchCond {
        serde_yaml::from_str(s).unwrap()
    }

    #[test]
    fn evaluate_namespace_and_app() {
        let p = pod("opik", &[("app.kubernetes.io/name", "mysql")]);
        let c = cond_yaml(indoc! {"
            namespace: [opik, kube-system]
            app: [mysql, redis]
        "});
        assert!(c.evaluate(&p));

        let c2 = cond_yaml(indoc! {"
            namespace: [opik]
            app: [postgres]
        "});
        assert!(!c2.evaluate(&p));
    }

    #[test]
    fn evaluate_app_falls_back_to_legacy_app_label() {
        let p = pod("cattle-system", &[("app", "rancher")]);
        let c = cond_yaml(indoc! {"
            app: [rancher]
        "});
        assert!(c.evaluate(&p));
    }

    #[test]
    fn evaluate_label_with_value_regex() {
        let p = pod("opik", &[("version", "v3.2.1")]);
        let c = cond_yaml(indoc! {r#"
            label: ["version=regexp:^v3\\..*"]
        "#});
        assert!(c.evaluate(&p));
    }

    #[test]
    fn evaluate_any_or() {
        let p = pod("cattle-system", &[("app", "rancher")]);
        let c = cond_yaml(indoc! {"
            any:
              - namespace: [cattle-system]
                label: [app=rancher]
              - namespace: [cattle-fleet-system]
        "});
        assert!(c.evaluate(&p));

        let p2 = pod("default", &[]);
        assert!(!c.evaluate(&p2));
    }

    #[test]
    fn evaluate_all_and_not() {
        let p_app = pod("opik", &[("app.kubernetes.io/name", "opik")]);
        let p_db = pod("opik", &[("app.kubernetes.io/name", "mysql")]);
        let c = cond_yaml(indoc! {"
            all:
              - namespace: [opik]
              - not:
                  app: [mysql, redis, minio]
        "});
        assert!(c.evaluate(&p_app));
        assert!(!c.evaluate(&p_db));
    }

    #[test]
    fn evaluate_destination_domain() {
        let dst = TestDst {
            host: Some("api.corp.com"),
            ip: None,
            port: 443,
        };
        let c = cond_yaml(indoc! {r#"
            domain:
              - "regexp:.*\\.corp\\..*"
              - "domain:googleapis.com"
        "#});
        assert!(c.evaluate(&dst));

        let dst2 = TestDst {
            host: Some("example.com"),
            ip: None,
            port: 443,
        };
        assert!(!c.evaluate(&dst2));
    }

    #[test]
    fn evaluate_destination_ip_and_port() {
        let dst = TestDst {
            host: None,
            ip: "10.1.2.3".parse().ok(),
            port: 8443,
        };
        let c = cond_yaml(indoc! {r#"
            ip: ["10.0.0.0/8"]
            port: "443,8443"
        "#});
        assert!(c.evaluate(&dst));

        let c2 = cond_yaml(indoc! {r#"
            ip: ["192.168.0.0/16"]
        "#});
        assert!(!c2.evaluate(&dst));
    }

    #[test]
    fn evaluate_empty_is_catchall() {
        let p = pod("anywhere", &[]);
        let c = MatchCond::default();
        assert!(c.evaluate(&p));
    }

    #[test]
    fn evaluate_pod_field_returns_false_on_dst_only() {
        // A pod target lacks dst_host; a domain matcher should fail closed.
        let p = pod("opik", &[]);
        let c = cond_yaml(indoc! {r#"
            domain: ["domain:foo.com"]
        "#});
        assert!(!c.evaluate(&p));
    }
}
