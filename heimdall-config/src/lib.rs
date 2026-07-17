//! Heimdall configuration schema.
//!
//! Single config file at `/etc/heimdall/heimdall.{yaml,json,toml,ncl}`
//! declares everything: runtime knobs, named upstream `connections`,
//! and `routing.rules` that map systemd-unit selectors directly to a
//! connection name (or the reserved `system` tag for eBPF bypass).
//!
//! There is no destination-side routing — heimdall is a per-cgroup
//! proxy chooser, not a per-domain router. If you need destination-
//! based switching, build it into the upstream SOCKS5 server.
//!
//! Selectors match the systemd identity heimdall derives from a
//! process's cgroup path: the `units` it belongs to (e.g.
//! `nginx.service`, a transient `*.scope`) and the enclosing `slices`
//! (e.g. `system.slice`, `user.slice`). Each list entry is a
//! `MatchValue` (exact / `regexp:` / `prefix:` / `suffix:` /
//! `keyword:`), plus optional `all` / `any` / `not` boolean
//! composition.

use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

pub const DEFAULT_DIR: &str = "/etc/heimdall";

/// Probe `/etc/heimdall/heimdall.{ncl,toml,json,yaml}` and return the
/// first one that exists. Falls back to `heimdall.ncl` (the canonical
/// recommended format) if none are present so help text and error
/// messages have something to display.
#[must_use]
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

/// Reserved `use` value — when a unit resolves to `system`, the eBPF
/// connect4 hook skips redirection entirely. Cannot be used as a
/// connection name. Orthogonal to `system.slice`: this is a routing
/// tag, not a slice name.
pub const SYSTEM_TAG: &str = "system";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("parse {path}: {source}")]
    ParseJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("parse {path}: {source}")]
    ParseToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("apiVersion `{0}` is not supported (expected `heimdall.io/v1alpha1`)")]
    UnsupportedApiVersion(String),
    #[error("kind `{0}` is not supported (expected `HeimdallConfig`)")]
    UnsupportedKind(String),
    #[error("connections must define `default`")]
    MissingDefaultConnection,
    #[error("routing.default.use refers to unknown connection `{0}`")]
    DefaultRoutingUnknown(String),
    #[error("routing.rules[{index}] (`{name}`) refers to unknown connection `{tag}`")]
    RuleRoutingUnknown {
        index: usize,
        name: String,
        tag: String,
    },
    #[error("connection name `{0}` is reserved")]
    ReservedConnectionName(String),
    #[error("connection `{name}` has empty addr (required for type `{ty}`)")]
    EmptyAddr { name: String, ty: String },
    #[error("read passwordFile `{path}`: {source}")]
    SecretRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("regex compilation failed: {pattern}: {source}")]
    Regex {
        pattern: String,
        source: regex::Error,
    },
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
    /// IPv6 relay address. When set, the daemon attaches a `connect6`
    /// eBPF program that rewrites IPv6 `connect()` destinations to this
    /// address + port (`runtime.listen`'s port). When `None`, IPv6
    /// connections fall through to whatever the host normally does
    /// with them. Defaults to `::1` so dual-stack works out of the
    /// box on hosts where the relay binds `[::]`.
    #[serde(default = "default_relay_ip6", rename = "relayIp6")]
    pub relay_ip6: Ipv6Addr,
    #[serde(default, rename = "bypassCidrs")]
    pub bypass_cidrs: Vec<String>,

    #[serde(default = "default_dns_listen", rename = "dnsListen")]
    pub dns_listen: String,
    #[serde(default = "default_fake_ip_cidr", rename = "fakeIpCidr")]
    pub fake_ip_cidr: String,
    /// Optional IPv6 fake-IP CIDR. When set, the fake-IP DNS server
    /// answers AAAA queries with synthetic addresses from this pool
    /// (paired with the existing IPv4 pool); the relay reverses these
    /// to hostnames at SOCKS5 ATYP=0x03 time. When None, AAAA queries
    /// stay empty-NOERROR (forcing resolver fallback to A) — the
    /// pre-IPv6 behaviour.
    ///
    /// Default uses the v4-mapped `fc00:198:19::/96` ULA range to mirror
    /// the v4 pool 1:1 visually (`fc00:198:19::a.b.c.d`).
    #[serde(default = "default_fake_ip6_cidr", rename = "fakeIp6Cidr")]
    pub fake_ip6_cidr: String,

    #[serde(default = "default_state_dir", rename = "stateDir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_flow_retention_secs", rename = "flowRetentionSecs")]
    pub flow_retention_secs: i64,
    #[serde(default = "default_api_listen", rename = "apiListen")]
    pub api_listen: String,
    #[serde(default)]
    pub tap: TapConfig,

    /// What to do with cgroups under the attached subtree that aren't
    /// (yet) classified by the policy engine. `redirect` (default)
    /// routes all such traffic through the heimdall relay, then to the
    /// `default` connection — current behaviour. `bypass` lets it skip
    /// the relay entirely (fail-open emergency override).
    ///
    /// Switching to `bypass` is a runbook step for when heimdall is
    /// misbehaving and you need traffic to flow direct without
    /// stopping the daemon (which would also lose tap visibility).
    #[serde(default, rename = "defaultEgressPolicy")]
    pub default_egress_policy: DefaultEgressPolicy,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            cgroup: default_cgroup(),
            listen: default_listen(),
            relay_ip: default_relay_ip(),
            relay_ip6: default_relay_ip6(),
            bypass_cidrs: Vec::new(),
            dns_listen: default_dns_listen(),
            fake_ip_cidr: default_fake_ip_cidr(),
            fake_ip6_cidr: default_fake_ip6_cidr(),
            state_dir: default_state_dir(),
            flow_retention_secs: default_flow_retention_secs(),
            api_listen: default_api_listen(),
            tap: TapConfig::default(),
            default_egress_policy: DefaultEgressPolicy::default(),
        }
    }
}

/// Policy for unclassified cgroups in the attached subtree. Drives the
/// value the daemon writes to the `DEFAULT_POLICY_MAP` BPF map at
/// startup.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultEgressPolicy {
    /// Route through heimdall (current behaviour) — `REDIRECT_OFF`
    /// stays unset, so the eBPF programs redirect every `connect()`
    /// to the relay, which then either fakes-IP-resolves or routes
    /// to the `default` connection.
    #[default]
    Redirect,
    /// Skip heimdall entirely — `REDIRECT_OFF` set, `OBSERVE_OFF` set,
    /// `NO_BYPASS_LOG` set. Traffic flows direct, heimdall sees
    /// nothing. Use when something's wrong with the relay or
    /// upstream and you need to fail-open without stopping the
    /// daemon (which would also drop tap visibility).
    Bypass,
}

// On a systemd host, services live under system.slice and interactive
// / `heimdall run` processes under user.slice. The daemon attaches the
// primary cgroup target here plus user.slice as a secondary (see
// main.rs); system.slice is the default primary.
fn default_cgroup() -> String {
    "/sys/fs/cgroup/system.slice".into()
}
fn default_listen() -> String {
    "0.0.0.0:12345".into()
}
fn default_relay_ip() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}
fn default_relay_ip6() -> Ipv6Addr {
    Ipv6Addr::LOCALHOST
}
fn default_dns_listen() -> String {
    "0.0.0.0:5358".into()
}
fn default_fake_ip_cidr() -> String {
    "198.19.0.0/16".into()
}
fn default_fake_ip6_cidr() -> String {
    "fc00:198:19::/96".into()
}
fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/heimdall")
}
fn default_flow_retention_secs() -> i64 {
    3 * 86400
}
fn default_api_listen() -> String {
    "127.0.0.1:9999".into()
}

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
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        match self {
            Connection::Socks5(c) => c.description.as_deref(),
            Connection::Direct(c) => c.description.as_deref(),
        }
    }

    #[must_use]
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
    /// Read the configured password file and trim one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SecretRead`] when the file cannot be read.
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
    /// Parse an exact or prefixed match expression.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Regex`] for an invalid `regexp:` pattern.
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

    #[must_use]
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
// MatchTarget trait + MatchCond evaluator
// ---------------------------------------------------------------------------

/// The systemd identity a routing rule evaluates against. Both axes
/// are derived from the process's cgroup path; either may be absent
/// for a cgroup that isn't a recognizable unit/slice.
pub trait MatchTarget {
    /// Leaf unit name (e.g. `nginx.service`, `run-r1234.scope`).
    fn unit_name(&self) -> Option<&str>;
    /// Enclosing slice (e.g. `system.slice`, `user.slice`).
    fn slice(&self) -> Option<&str>;
}

/// Recursive boolean condition over unit selectors. Field-level AND
/// across populated fields, value-level OR within each list, plus
/// explicit `all` / `any` / `not` for arbitrary boolean composition.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchCond {
    /// Match the leaf unit name.
    #[serde(default)]
    pub units: Vec<MatchValue>,
    /// Match the enclosing slice.
    #[serde(default)]
    pub slices: Vec<MatchValue>,

    #[serde(default)]
    pub all: Vec<MatchCond>,
    #[serde(default)]
    pub any: Vec<MatchCond>,
    #[serde(default)]
    pub not: Option<Box<MatchCond>>,
}

impl MatchCond {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
            && self.slices.is_empty()
            && self.all.is_empty()
            && self.any.is_empty()
            && self.not.is_none()
    }

    #[must_use]
    pub fn evaluate(&self, target: &dyn MatchTarget) -> bool {
        if self.is_empty() {
            return true;
        }

        if !self.units.is_empty() {
            let Some(unit) = target.unit_name() else {
                return false;
            };
            if !self.units.iter().any(|m| m.matches(unit)) {
                return false;
            }
        }

        if !self.slices.is_empty() {
            let Some(slice) = target.slice() else {
                return false;
            };
            if !self.slices.iter().any(|m| m.matches(slice)) {
                return false;
            }
        }

        if !self.all.is_empty() && !self.all.iter().all(|c| c.evaluate(target)) {
            return false;
        }
        if !self.any.is_empty() && !self.any.iter().any(|c| c.evaluate(target)) {
            return false;
        }
        if let Some(n) = &self.not
            && n.evaluate(target)
        {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub default: Decision,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub name: Option<String>,
    /// When None or empty, the rule matches every unit (catchall).
    #[serde(default, rename = "match")]
    pub match_: Option<MatchCond>,
    /// Connection name (must exist in `connections`) or the
    /// reserved `system` keyword.
    #[serde(rename = "use")]
    pub use_: String,
    /// When None, falls back to `Routing.default.observe`.
    #[serde(default)]
    pub observe: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    #[serde(rename = "use", default = "default_use")]
    pub use_: String,
    #[serde(default)]
    pub observe: bool,
}

impl Default for Decision {
    fn default() -> Self {
        Self {
            use_: default_use(),
            observe: false,
        }
    }
}

fn default_use() -> String {
    "default".into()
}

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

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// Use heimdall's fake-IP DNS resolver. The relay reverses to a
    /// hostname before forwarding via SOCKS5 ATYP=0x03.
    #[default]
    Fake,
    /// Bypass fake-IP; let the wrapped command's libc resolver hit
    /// whatever it usually hits (host's /etc/resolv.conf).
    System,
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
    #[must_use]
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
    /// Load and validate a configuration file.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when reading, parsing, or validation fails.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let cfg: HeimdallConfig = parse_typed(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate schema identifiers, connection references, and routing rules.
    ///
    /// # Errors
    ///
    /// Returns the first violated configuration invariant.
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
            if let Connection::Socks5(c) = conn
                && c.addr.is_empty()
            {
                return Err(ConfigError::EmptyAddr {
                    name: name.clone(),
                    ty: "socks5".into(),
                });
            }
        }

        // Each rule's `use` must be `system` or a known connection.
        for (i, rule) in self.routing.rules.iter().enumerate() {
            if !self.is_valid_use(&rule.use_) {
                return Err(ConfigError::RuleRoutingUnknown {
                    index: i,
                    name: rule.name.clone().unwrap_or_default(),
                    tag: rule.use_.clone(),
                });
            }
        }
        if !self.is_valid_use(&self.routing.default.use_) {
            return Err(ConfigError::DefaultRoutingUnknown(
                self.routing.default.use_.clone(),
            ));
        }

        Ok(())
    }

    fn is_valid_use(&self, use_: &str) -> bool {
        use_ == SYSTEM_TAG || self.connections.contains_key(use_)
    }
}

/// Parse a supported configuration format into the requested type.
///
/// # Errors
///
/// Returns a [`ConfigError`] when the file cannot be read or decoded.
pub fn parse_typed<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let format = Format::detect(path).unwrap_or(Format::Yaml);
    match format {
        Format::Yaml => {
            let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?;
            serde_yaml::from_str(&raw).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })
        }
        Format::Json => {
            let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?;
            serde_json::from_str(&raw).map_err(|source| ConfigError::ParseJson {
                path: path.to_path_buf(),
                source,
            })
        }
        Format::Toml => {
            let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?;
            toml::from_str(&raw).map_err(|source| ConfigError::ParseToml {
                path: path.to_path_buf(),
                source,
            })
        }
        Format::Nickel => {
            let json = run_nickel_export(path)?;
            serde_json::from_str(&json).map_err(|source| ConfigError::ParseJson {
                path: path.to_path_buf(),
                source,
            })
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
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
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
        let cfg: HeimdallConfig =
            serde_yaml::from_str(yaml).map_err(|source| ConfigError::Parse {
                path: PathBuf::from("<test>"),
                source,
            })?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn minimal_config() {
        let yaml = indoc! {r"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
        "};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.routing.default.use_, "default");
    }

    #[test]
    fn match_value_prefixes() {
        assert!(
            MatchValue::parse("nginx.service")
                .unwrap()
                .matches("nginx.service")
        );
        assert!(
            MatchValue::parse("regexp:^postgres.*\\.service$")
                .unwrap()
                .matches("postgresql.service")
        );
        assert!(
            MatchValue::parse("prefix:docker-")
                .unwrap()
                .matches("docker-abc.scope")
        );
        assert!(
            MatchValue::parse("suffix:.scope")
                .unwrap()
                .matches("run-r1.scope")
        );
        assert!(
            MatchValue::parse("keyword:nginx")
                .unwrap()
                .matches("nginx.service")
        );
    }

    struct TestUnit {
        unit: &'static str,
        slice: &'static str,
    }

    impl MatchTarget for TestUnit {
        fn unit_name(&self) -> Option<&str> {
            Some(self.unit)
        }
        fn slice(&self) -> Option<&str> {
            Some(self.slice)
        }
    }

    fn cond_yaml(s: &str) -> MatchCond {
        serde_yaml::from_str(s).unwrap()
    }

    #[test]
    fn evaluate_units_and_slices() {
        let u = TestUnit {
            unit: "nginx.service",
            slice: "system.slice",
        };
        let c = cond_yaml(indoc! {r"
            units: [nginx.service, caddy.service]
            slices: [system.slice]
        "});
        assert!(c.evaluate(&u));

        let c2 = cond_yaml("slices: [user.slice]");
        assert!(!c2.evaluate(&u));
    }

    #[test]
    fn evaluate_unit_prefix() {
        let u = TestUnit {
            unit: "docker-abc123.scope",
            slice: "system.slice",
        };
        let c = cond_yaml("units: [prefix:docker-]");
        assert!(c.evaluate(&u));
    }

    #[test]
    fn evaluate_any_or() {
        let u = TestUnit {
            unit: "rancher.service",
            slice: "system.slice",
        };
        let c = cond_yaml(indoc! {"
            any:
              - units: [rancher.service]
              - units: [fleet.service]
        "});
        assert!(c.evaluate(&u));
    }

    #[test]
    fn evaluate_all_and_not() {
        let app = TestUnit {
            unit: "app.service",
            slice: "system.slice",
        };
        let db = TestUnit {
            unit: "mysql.service",
            slice: "system.slice",
        };
        let c = cond_yaml(indoc! {r"
            all:
              - slices: [system.slice]
              - not:
                  units: [mysql.service, redis.service]
        "});
        assert!(c.evaluate(&app));
        assert!(!c.evaluate(&db));
    }

    #[test]
    fn rejects_reserved_system() {
        let yaml = indoc! {r"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
              system: { type: direct }
        "};
        assert!(matches!(
            parse(yaml),
            Err(ConfigError::ReservedConnectionName(_))
        ));
    }

    #[test]
    fn rejects_unknown_use_in_rule() {
        let yaml = indoc! {r"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            routing:
              rules:
                - match: { slices: [system.slice] }
                  use: ghost
        "};
        assert!(matches!(
            parse(yaml),
            Err(ConfigError::RuleRoutingUnknown { .. })
        ));
    }

    #[test]
    fn accepts_use_system() {
        let yaml = indoc! {r"
            apiVersion: heimdall.io/v1alpha1
            kind: HeimdallConfig
            connections:
              default: { type: socks5, addr: 127.0.0.1:20170 }
            routing:
              rules:
                - match: { units: [sshd.service] }
                  use: system
        "};
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.routing.rules[0].use_, "system");
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
