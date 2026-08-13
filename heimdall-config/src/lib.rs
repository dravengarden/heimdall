//! Strict, format-independent configuration for the Heimdall CLI wrapper.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, MapAccess, Visitor},
};
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
/// # Errors
/// Returns [`ConfigError::AmbiguousConfig`] when multiple candidates exist.
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
    pub hint: String,
}

impl ConfigDiagnostic {
    fn new(
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            path: path.into(),
            message: message.into(),
            hint: hint.into(),
        }
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
    #[error("configuration has {count} semantic error(s)")]
    Validation {
        count: usize,
        diagnostics: Vec<ConfigDiagnostic>,
    },
    #[error("read password_file `{path}`: {source}")]
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
            Self::Validation { .. } => "config_validation_failed",
            Self::SecretRead { .. } => "secret_read_failed",
        }
    }

    /// Return actionable diagnostics for every error category.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<ConfigDiagnostic> {
        if let Self::Validation { diagnostics, .. } = self {
            return diagnostics.clone();
        }
        vec![ConfigDiagnostic::new(
            self.code(),
            "$",
            self.to_string(),
            self.hint(),
        )]
    }

    /// Render the same stable diagnostics as readable CLI repair instructions.
    #[must_use]
    pub fn actionable_message(&self) -> String {
        self.diagnostics()
            .into_iter()
            .map(|item| {
                format!(
                    "{} at {}: {}\nfix: {}",
                    item.code, item.path, item.message, item.hint
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    fn hint(&self) -> &'static str {
        match self {
            Self::Read { .. } => "Create the file or pass the intended path with --config.",
            Self::UnsupportedFormat { .. } => {
                "Use exactly one .toml, .yaml/.yml, .json, or .ncl configuration file."
            }
            Self::ParseToml { .. } => "Fix the TOML syntax at the reported line and column.",
            Self::ParseYaml { .. } => "Fix the YAML syntax and use strings for enum values.",
            Self::ParseJson { .. } => "Fix the JSON syntax at the reported line and column.",
            Self::NickelSpawn { .. } => "Install Nickel or use the packaged Heimdall binary.",
            Self::NickelExport { .. } => "Fix the Nickel contract or evaluation error.",
            Self::AmbiguousConfig { .. } => {
                "Keep one discovered config file and remove stale peers."
            }
            Self::Validation { .. } => "Apply each diagnostic and validate again.",
            Self::SecretRead { .. } => {
                "Use an absolute readable password_file with restricted permissions."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeimdallConfig {
    pub version: u32,
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub decrypt: FeatureConfig,
    #[serde(default)]
    pub daemon: Runtime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    pub default_policy: String,
    #[serde(default, deserialize_with = "deserialize_strict_map")]
    pub outbounds: BTreeMap<String, Outbound>,
    #[serde(deserialize_with = "deserialize_strict_map")]
    pub policies: BTreeMap<String, ProxyPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Outbound {
    Socks5(Socks5Outbound),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Outbound {
    pub server: String,
    pub server_port: u16,
    pub network: Vec<Network>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
    #[serde(default)]
    pub auth: Option<Socks5Auth>,
}

fn default_connect_timeout() -> String {
    "10s".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Auth {
    pub username: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyPolicy {
    pub dns: DnsConfig,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    #[serde(rename = "final")]
    pub final_: FinalActions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub mode: DnsMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    Fake,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalActions {
    pub tcp: Action,
    pub udp: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
    pub action: Action,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    #[serde(default)]
    pub network: Vec<Network>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub port: Vec<u16>,
    #[serde(default)]
    pub port_range: Vec<PortRange>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Action {
    Route {
        outbound: String,
    },
    Direct,
    Reject {
        #[serde(default)]
        method: RejectMethod,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RejectMethod {
    #[default]
    Refused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureConfig {
    pub mode: FeatureMode,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            mode: FeatureMode::Off,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureMode {
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    pub mode: CaptureMode,
    #[serde(default = "default_capture_directory")]
    pub directory: PathBuf,
    #[serde(default = "default_capture_max_bytes")]
    pub max_bytes_per_flow: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            mode: CaptureMode::Off,
            directory: default_capture_directory(),
            max_bytes_per_flow: default_capture_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMode {
    Off,
    On,
}

fn default_capture_directory() -> PathBuf {
    "/var/lib/heimdall/captures".into()
}

const fn default_capture_max_bytes() -> u64 {
    1_048_576
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    #[serde(default = "default_cgroup")]
    pub cgroup: String,
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
    #[serde(default = "default_fake_ip_cidr")]
    pub fake_ip_cidr: String,
    #[serde(default = "default_fake_ip6_cidr")]
    pub fake_ip6_cidr: String,
    #[serde(default = "default_api_listen")]
    pub api_listen: String,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            cgroup: default_cgroup(),
            dns_port: default_dns_port(),
            fake_ip_cidr: default_fake_ip_cidr(),
            fake_ip6_cidr: default_fake_ip6_cidr(),
            api_listen: default_api_listen(),
        }
    }
}

fn default_cgroup() -> String {
    "/sys/fs/cgroup/system.slice".into()
}
const fn default_dns_port() -> u16 {
    5358
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

/// Policy selected for an active CLI cgroup.
#[derive(Debug, Clone)]
pub struct Decision {
    pub policy: String,
}

impl HeimdallConfig {
    /// Load a supported format and run the canonical semantic validation.
    ///
    /// # Errors
    /// Returns a parse/evaluation error or all semantic diagnostics.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let cfg: Self = parse_typed(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate the full reference graph and every executable policy invariant.
    ///
    /// # Errors
    /// Returns all semantic diagnostics in deterministic path order.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();
        if self.version != 1 {
            push(
                &mut errors,
                "unsupported_config_version",
                "$.version",
                format!("configuration version {} is not supported", self.version),
                "Set version to 1.",
            );
        }

        if !valid_name(&self.proxy.default_policy) {
            invalid_name(
                &mut errors,
                "$.proxy.default_policy",
                &self.proxy.default_policy,
            );
        } else if !self.proxy.policies.contains_key(&self.proxy.default_policy) {
            push(
                &mut errors,
                "unknown_default_policy",
                "$.proxy.default_policy",
                format!(
                    "default policy `{}` is not declared",
                    self.proxy.default_policy
                ),
                format!("Choose one of: {}.", join_keys(&self.proxy.policies)),
            );
        }

        for (name, outbound) in &self.proxy.outbounds {
            let base = format!("$.proxy.outbounds.{name}");
            if !valid_name(name) {
                invalid_name(&mut errors, &base, name);
            }
            match outbound {
                Outbound::Socks5(socks) => validate_socks5(&mut errors, &base, socks),
            }
        }

        for (name, policy) in &self.proxy.policies {
            let base = format!("$.proxy.policies.{name}");
            if !valid_name(name) {
                invalid_name(&mut errors, &base, name);
            }
            validate_policy(&mut errors, &base, policy, &self.proxy.outbounds);
        }

        validate_capture(&mut errors, &self.capture);

        validate_runtime(&mut errors, &self.daemon);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation {
                count: errors.len(),
                diagnostics: errors,
            })
        }
    }

    #[must_use]
    pub fn default_policy(&self) -> &ProxyPolicy {
        self.proxy
            .policies
            .get(&self.proxy.default_policy)
            .expect("strict validation resolved default_policy")
    }

    #[must_use]
    pub fn policy(&self, name: &str) -> Option<&ProxyPolicy> {
        self.proxy.policies.get(name)
    }
}

impl Socks5Outbound {
    #[must_use]
    pub fn address(&self) -> String {
        if self.server.contains(':') {
            format!("[{}]:{}", self.server, self.server_port)
        } else {
            format!("{}:{}", self.server, self.server_port)
        }
    }

    #[must_use]
    pub fn connect_timeout_value(&self) -> Duration {
        parse_duration(&self.connect_timeout).expect("strict validation accepted connect_timeout")
    }
}

impl ProxyPolicy {
    #[must_use]
    pub const fn dns_hijack(&self) -> bool {
        matches!(self.dns.mode, DnsMode::Fake)
    }

    #[must_use]
    pub fn decide_tcp(&self, domain: Option<&str>, ip: Option<IpAddr>, port: u16) -> &Action {
        self.explain(Network::Tcp, domain, ip, port).1
    }

    #[must_use]
    pub fn decide_udp(&self, domain: Option<&str>, ip: Option<IpAddr>, port: u16) -> &Action {
        self.explain(Network::Udp, domain, ip, port).1
    }

    #[must_use]
    pub fn rejects_all_udp(&self) -> bool {
        matches!(self.final_.udp, Action::Reject { .. })
            && self.rules.iter().all(|rule| {
                !rule.matcher.network.contains(&Network::Udp)
                    || matches!(rule.action, Action::Reject { .. })
            })
    }

    /// Return the first matching TCP rule and the selected action.
    #[must_use]
    pub fn explain_tcp(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> (Option<&RouteRule>, &Action) {
        self.explain(Network::Tcp, domain, ip, port)
    }

    /// Return the first matching UDP rule and the selected action.
    #[must_use]
    pub fn explain_udp(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> (Option<&RouteRule>, &Action) {
        self.explain(Network::Udp, domain, ip, port)
    }

    fn explain(
        &self,
        network: Network,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> (Option<&RouteRule>, &Action) {
        self.rules
            .iter()
            .find(|rule| rule.matcher.matches(network, domain, ip, port))
            .map_or_else(
                || {
                    let final_action = match network {
                        Network::Tcp => &self.final_.tcp,
                        Network::Udp => &self.final_.udp,
                    };
                    (None, final_action)
                },
                |rule| (Some(rule), &rule.action),
            )
    }
}

impl RuleMatch {
    fn matches(
        &self,
        network: Network,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> bool {
        if !self.network.contains(&network) {
            return false;
        }
        let has_domains = !self.domain.is_empty() || !self.domain_suffix.is_empty();
        if has_domains {
            let Some(domain) = domain else { return false };
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if !self.domain.iter().any(|item| item == &domain)
                && !self
                    .domain_suffix
                    .iter()
                    .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
            {
                return false;
            }
        }
        if !self.ip_cidr.is_empty() {
            let Some(ip) = ip else { return false };
            if !self.ip_cidr.iter().any(|cidr| cidr_contains(cidr, ip)) {
                return false;
            }
        }
        if (!self.port.is_empty() || !self.port_range.is_empty())
            && !self.port.contains(&port)
            && !self
                .port_range
                .iter()
                .any(|range| (range.start..=range.end).contains(&port))
        {
            return false;
        }
        true
    }
}

fn validate_socks5(errors: &mut Vec<ConfigDiagnostic>, base: &str, socks: &Socks5Outbound) {
    if !valid_server(&socks.server) {
        push(
            errors,
            "invalid_outbound_server",
            format!("{base}.server"),
            format!("`{}` is not a valid hostname or IP address", socks.server),
            "Use a hostname, IPv4 address, or unbracketed IPv6 address.",
        );
    }
    if socks.server_port == 0 {
        push(
            errors,
            "invalid_outbound_port",
            format!("{base}.server_port"),
            "server_port must be between 1 and 65535",
            "Set the SOCKS5 listener port, commonly 1080.",
        );
    }
    if socks.network.is_empty() {
        push(
            errors,
            "empty_outbound_network",
            format!("{base}.network"),
            "network must contain at least one protocol",
            "Use [\"tcp\"], [\"udp\"], or [\"tcp\", \"udp\"].",
        );
    }
    let unique: BTreeSet<_> = socks.network.iter().collect();
    if unique.len() != socks.network.len() {
        push(
            errors,
            "duplicate_outbound_network",
            format!("{base}.network"),
            "network contains duplicate values",
            "Remove duplicate protocol names.",
        );
    }
    if parse_duration(&socks.connect_timeout).is_none() {
        push(
            errors,
            "invalid_duration",
            format!("{base}.connect_timeout"),
            format!("`{}` is not a supported duration", socks.connect_timeout),
            "Use a positive duration such as 500ms, 10s, or 2m.",
        );
    }
    if let Some(auth) = &socks.auth {
        if auth.username.is_empty() {
            push(
                errors,
                "empty_auth_username",
                format!("{base}.auth.username"),
                "SOCKS5 username must not be empty",
                "Set a 1..=255-byte username or remove auth.",
            );
        } else if auth.username.len() > 255 {
            push(
                errors,
                "auth_username_too_long",
                format!("{base}.auth.username"),
                format!(
                    "username is {} bytes; SOCKS5 permits at most 255",
                    auth.username.len()
                ),
                "Shorten the username to 255 bytes or fewer.",
            );
        }
        if !auth.password_file.is_absolute() {
            push(
                errors,
                "relative_password_file",
                format!("{base}.auth.password_file"),
                format!("`{}` is not absolute", auth.password_file.display()),
                "Use an absolute path readable by the daemon.",
            );
        }
    }
}

fn validate_policy(
    errors: &mut Vec<ConfigDiagnostic>,
    base: &str,
    policy: &ProxyPolicy,
    outbounds: &BTreeMap<String, Outbound>,
) {
    let mut names = BTreeSet::new();
    for (index, rule) in policy.rules.iter().enumerate() {
        let rule_path = format!("{base}.rules[{index}]");
        if !valid_name(&rule.name) {
            invalid_name(errors, &format!("{rule_path}.name"), &rule.name);
        } else if !names.insert(&rule.name) {
            push(
                errors,
                "duplicate_rule_name",
                format!("{rule_path}.name"),
                format!("rule name `{}` is duplicated in this policy", rule.name),
                "Give every rule a unique stable name for explain output.",
            );
        }
        validate_match(
            errors,
            &format!("{rule_path}.match"),
            &rule.matcher,
            policy.dns.mode,
        );
        validate_action(
            errors,
            &format!("{rule_path}.action"),
            &rule.action,
            outbounds,
            &rule.matcher.network,
        );
    }
    validate_action(
        errors,
        &format!("{base}.final.tcp"),
        &policy.final_.tcp,
        outbounds,
        &[Network::Tcp],
    );
    validate_action(
        errors,
        &format!("{base}.final.udp"),
        &policy.final_.udp,
        outbounds,
        &[Network::Udp],
    );
}

fn validate_match(
    errors: &mut Vec<ConfigDiagnostic>,
    base: &str,
    matcher: &RuleMatch,
    dns_mode: DnsMode,
) {
    validate_unique_match_values(errors, base, "network", &matcher.network);
    validate_unique_match_values(errors, base, "domain", &matcher.domain);
    validate_unique_match_values(errors, base, "domain_suffix", &matcher.domain_suffix);
    validate_unique_match_values(errors, base, "ip_cidr", &matcher.ip_cidr);
    validate_unique_match_values(errors, base, "port", &matcher.port);
    validate_unique_match_values(errors, base, "port_range", &matcher.port_range);

    let empty = matcher.network.is_empty()
        && matcher.domain.is_empty()
        && matcher.domain_suffix.is_empty()
        && matcher.ip_cidr.is_empty()
        && matcher.port.is_empty()
        && matcher.port_range.is_empty();
    if empty {
        push(
            errors,
            "empty_rule_match",
            base,
            "a rule must have at least one matcher",
            "Move catch-all behavior to final or add explicit match fields.",
        );
    }
    if matcher.network.is_empty() {
        push(
            errors,
            "empty_rule_network",
            format!("{base}.network"),
            "every ordered rule must select at least one network",
            "Use [\"tcp\"], [\"udp\"], or [\"tcp\", \"udp\"].",
        );
    }
    let has_domain = !matcher.domain.is_empty() || !matcher.domain_suffix.is_empty();
    if has_domain && !matcher.ip_cidr.is_empty() {
        push(
            errors,
            "mixed_destination_matchers",
            base,
            "domain and ip_cidr matchers cannot appear in one rule",
            "Split the rule into separate domain and IP rules with the same action.",
        );
    }
    if has_domain && dns_mode == DnsMode::System {
        push(
            errors,
            "domain_rule_requires_fake_dns",
            base,
            "domain rules cannot be evaluated with dns.mode = system",
            "Use dns.mode = fake or replace domain rules with ip_cidr rules.",
        );
    }
    for (field, values) in [
        ("domain", &matcher.domain),
        ("domain_suffix", &matcher.domain_suffix),
    ] {
        for (index, value) in values.iter().enumerate() {
            if !valid_domain(value) {
                push(
                    errors,
                    "invalid_domain_matcher",
                    format!("{base}.{field}[{index}]"),
                    format!("`{value}` is not a canonical ASCII domain"),
                    "Use lowercase ASCII labels without a leading or trailing dot.",
                );
            }
        }
    }
    for (index, cidr) in matcher.ip_cidr.iter().enumerate() {
        if parse_cidr(cidr).is_none() {
            push(
                errors,
                "invalid_ip_cidr",
                format!("{base}.ip_cidr[{index}]"),
                format!("`{cidr}` is not a canonical IPv4 or IPv6 CIDR"),
                "Use a network address such as 10.0.0.0/8 or 2001:db8::/32.",
            );
        }
    }
    for (index, port) in matcher.port.iter().enumerate() {
        if *port == 0 {
            push(
                errors,
                "invalid_port",
                format!("{base}.port[{index}]"),
                "port 0 is not a routable destination matcher",
                "Use a destination port between 1 and 65535.",
            );
        }
    }
    for (index, range) in matcher.port_range.iter().enumerate() {
        if range.start == 0 || range.start > range.end {
            push(
                errors,
                "invalid_port_range",
                format!("{base}.port_range[{index}]"),
                format!("invalid range {}..={}", range.start, range.end),
                "Use 1 <= start <= end <= 65535.",
            );
        }
    }
}

fn validate_unique_match_values<T: Ord>(
    errors: &mut Vec<ConfigDiagnostic>,
    base: &str,
    field: &str,
    values: &[T],
) {
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        push(
            errors,
            "duplicate_match_value",
            format!("{base}.{field}"),
            format!("{field} contains duplicate values"),
            "Remove duplicate values; each matcher list is a set.",
        );
    }
}

fn validate_action(
    errors: &mut Vec<ConfigDiagnostic>,
    path: &str,
    action: &Action,
    outbounds: &BTreeMap<String, Outbound>,
    networks: &[Network],
) {
    if let Action::Route { outbound } = action {
        let Some(target) = outbounds.get(outbound) else {
            push(
                errors,
                "unknown_outbound",
                format!("{path}.outbound"),
                format!("outbound `{outbound}` is not declared"),
                format!("Choose one of: {}.", join_keys(outbounds)),
            );
            return;
        };
        let Outbound::Socks5(socks) = target;
        for network in networks {
            if !socks.network.contains(network) {
                push(
                    errors,
                    "outbound_network_mismatch",
                    format!("{path}.outbound"),
                    format!("outbound `{outbound}` does not enable {network:?}"),
                    format!(
                        "Add `{}` to $.proxy.outbounds.{outbound}.network or choose another outbound.",
                        match network {
                            Network::Tcp => "tcp",
                            Network::Udp => "udp",
                        }
                    ),
                );
            }
        }
    }
}

fn validate_capture(errors: &mut Vec<ConfigDiagnostic>, capture: &CaptureConfig) {
    if !capture.directory.is_absolute() {
        push(
            errors,
            "relative_capture_directory",
            "$.capture.directory",
            format!("`{}` is not absolute", capture.directory.display()),
            "Use an absolute directory writable only by the daemon, such as /var/lib/heimdall/captures.",
        );
    }
    if capture.max_bytes_per_flow == 0 || capture.max_bytes_per_flow > 67_108_864 {
        push(
            errors,
            "invalid_capture_limit",
            "$.capture.max_bytes_per_flow",
            format!(
                "{} is outside the supported 1..=67108864 byte range",
                capture.max_bytes_per_flow
            ),
            "Choose a per-flow limit between 1 byte and 64 MiB.",
        );
    }
}

fn validate_runtime(errors: &mut Vec<ConfigDiagnostic>, runtime: &Runtime) {
    let api = validated_socket(errors, "$.daemon.api_listen", &runtime.api_listen);
    if runtime.dns_port == 0 {
        push(
            errors,
            "invalid_dns_port",
            "$.daemon.dns_port",
            "dns_port must be between 1 and 65535",
            "Use an unused local port such as 5358.",
        );
    }
    if let Some(api) = api {
        if !api.ip().is_loopback() {
            push(
                errors,
                "non_loopback_control_listener",
                "$.daemon.api_listen",
                "the control API must bind a loopback address",
                "Use 127.0.0.1:9999 or [::1]:9999.",
            );
        }
        if api.port() == runtime.dns_port || api.port() == heimdall_common::RELAY_PORT {
            push(
                errors,
                "duplicate_daemon_port",
                "$.daemon.api_listen",
                "the control API port conflicts with an internal listener",
                "Use a port distinct from daemon.dns_port and 12345.",
            );
        }
    }
    if runtime.dns_port == heimdall_common::RELAY_PORT {
        push(
            errors,
            "duplicate_daemon_port",
            "$.daemon.dns_port",
            "DNS cannot use the internal relay port 12345",
            "Use an unused local port such as 5358.",
        );
    }
    let cgroup = Path::new(&runtime.cgroup);
    if !cgroup.is_absolute() || !cgroup.starts_with("/sys/fs/cgroup") {
        push(
            errors,
            "invalid_cgroup",
            "$.daemon.cgroup",
            format!(
                "`{}` is not an absolute path under /sys/fs/cgroup",
                runtime.cgroup
            ),
            "Use an absolute cgroup v2 path under /sys/fs/cgroup.",
        );
    }
    if !matches!(parse_cidr(&runtime.fake_ip_cidr), Some(Cidr::V4(_, prefix)) if prefix <= 30) {
        push(
            errors,
            "invalid_fake_ip_cidr",
            "$.daemon.fake_ip_cidr",
            format!("`{}` is not a canonical IPv4 CIDR", runtime.fake_ip_cidr),
            "Use a canonical IPv4 network with at least four addresses, such as 198.19.0.0/16.",
        );
    }
    if !matches!(parse_cidr(&runtime.fake_ip6_cidr), Some(Cidr::V6(_, prefix)) if prefix <= 124) {
        push(
            errors,
            "invalid_fake_ip6_cidr",
            "$.daemon.fake_ip6_cidr",
            format!("`{}` is not a canonical IPv6 CIDR", runtime.fake_ip6_cidr),
            "Use a canonical IPv6 network with at least sixteen addresses, such as fc00:198:19::/96.",
        );
    }
}

fn validated_socket(
    errors: &mut Vec<ConfigDiagnostic>,
    path: &str,
    value: &str,
) -> Option<SocketAddr> {
    match value.parse::<SocketAddr>() {
        Ok(socket) if socket.port() != 0 => Some(socket),
        _ => {
            push(
                errors,
                "invalid_daemon_listener",
                path,
                format!("`{value}` is not a nonzero socket address"),
                "Use IPv4:port or [IPv6]:port with a port between 1 and 65535.",
            );
            None
        }
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn invalid_name(errors: &mut Vec<ConfigDiagnostic>, path: &str, value: &str) {
    push(
        errors,
        "invalid_name",
        path,
        format!("`{value}` is not a valid stable name"),
        "Use ASCII letters, digits, '.', '_', or '-'.",
    );
}

fn valid_server(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || valid_domain(value)
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value == value.to_ascii_lowercase()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn parse_duration(value: &str) -> Option<Duration> {
    let (digits, factor) = if let Some(raw) = value.strip_suffix("ms") {
        (raw, 1_u64)
    } else if let Some(raw) = value.strip_suffix('s') {
        (raw, 1_000)
    } else if let Some(raw) = value.strip_suffix('m') {
        (raw, 60_000)
    } else {
        return None;
    };
    let amount = digits.parse::<u64>().ok()?;
    let millis = amount.checked_mul(factor)?;
    (millis > 0).then(|| Duration::from_millis(millis))
}

#[derive(Clone, Copy)]
enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

fn parse_cidr(value: &str) -> Option<Cidr> {
    let (address, prefix) = value.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) if prefix <= 32 => {
            let bits = u32::from(ip);
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            (bits & !mask == 0).then_some(Cidr::V4(bits, prefix))
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let bits = u128::from(ip);
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            (bits & !mask == 0).then_some(Cidr::V6(bits, prefix))
        }
        _ => None,
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    match (parse_cidr(cidr), ip) {
        (Some(Cidr::V4(network, prefix)), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(ip) & mask == network
        }
        (Some(Cidr::V6(network, prefix)), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(ip) & mask == network
        }
        _ => false,
    }
}

fn join_keys<T>(map: &BTreeMap<String, T>) -> String {
    if map.is_empty() {
        "<none>".into()
    } else {
        map.keys().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn deserialize_strict_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct StrictMapVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T> Visitor<'de> for StrictMapVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = BTreeMap<String, T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, T>()? {
                if values.insert(key.clone(), value).is_some() {
                    return Err(A::Error::custom(format!("duplicate key `{key}`")));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(StrictMapVisitor(std::marker::PhantomData))
}

fn push(
    errors: &mut Vec<ConfigDiagnostic>,
    code: impl Into<String>,
    path: impl Into<String>,
    message: impl Into<String>,
    hint: impl Into<String>,
) {
    errors.push(ConfigDiagnostic::new(code, path, message, hint));
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn valid_toml() -> &'static str {
        r#"
            version = 1

            [proxy]
            default_policy = "default"

            [proxy.outbounds.default]
            type = "socks5"
            server = "127.0.0.1"
            server_port = 1080
            network = ["tcp"]

            [proxy.policies.default.dns]
            mode = "fake"

            [proxy.policies.default.final]
            tcp = { type = "route", outbound = "default" }
            udp = { type = "reject", method = "refused" }

            [capture]
            mode = "off"

            [decrypt]
            mode = "off"
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
                r#"version: 1
proxy:
  default_policy: default
  outbounds:
    default:
      type: socks5
      server: 127.0.0.1
      server_port: 1080
      network: [tcp]
  policies:
    default:
      dns: { mode: fake }
      rules: []
      final:
        tcp: { type: route, outbound: default }
        udp: { type: reject, method: refused }
capture: { mode: "on", directory: /var/lib/heimdall/captures, max_bytes_per_flow: 4096 }
decrypt: { mode: "off" }
"#,
            ),
            (
                "json",
                r#"{"version":1,"proxy":{"default_policy":"default","outbounds":{"default":{"type":"socks5","server":"127.0.0.1","server_port":1080,"network":["tcp"]}},"policies":{"default":{"dns":{"mode":"fake"},"rules":[],"final":{"tcp":{"type":"route","outbound":"default"},"udp":{"type":"reject","method":"refused"}}}}},"capture":{"mode":"on","directory":"/var/lib/heimdall/captures","max_bytes_per_flow":4096},"decrypt":{"mode":"off"}}"#,
            ),
        ];
        for (extension, content) in cases {
            let path = temp_config(extension, content);
            let cfg = HeimdallConfig::load(&path).unwrap();
            assert_eq!(cfg.proxy.default_policy, "default");
            if extension != "toml" {
                assert_eq!(cfg.capture.mode, CaptureMode::On);
                assert_eq!(cfg.capture.max_bytes_per_flow, 4096);
            }
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn loads_nickel_through_the_same_schema() {
        let path = temp_config(
            "ncl",
            r#"{
              version = 1,
              proxy = {
                default_policy = "default",
                outbounds.default = {
                  type = "socks5",
                  server = "127.0.0.1",
                  server_port = 1080,
                  network = ["tcp"],
                },
                policies.default = {
                  dns.mode = "fake",
                  rules = [],
                  final = {
                    tcp = { type = "route", outbound = "default" },
                    udp = { type = "reject", method = "refused" },
                  },
                },
              },
              capture = {
                mode = "on",
                directory = "/var/lib/heimdall/captures",
                max_bytes_per_flow = 4096,
              },
              decrypt.mode = "off",
            }"#,
        );
        let cfg = HeimdallConfig::load(&path).unwrap();
        assert_eq!(cfg.proxy.default_policy, "default");
        assert_eq!(cfg.capture.mode, CaptureMode::On);
        assert_eq!(cfg.capture.max_bytes_per_flow, 4096);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_duplicate_named_objects() {
        let path = temp_config(
            "json",
            r#"{
              "version": 1,
              "proxy": {
                "default_policy": "default",
                "outbounds": {
                  "default": {"type":"socks5","server":"127.0.0.1","server_port":1080,"network":["tcp"]},
                  "default": {"type":"socks5","server":"127.0.0.1","server_port":1081,"network":["tcp"]}
                },
                "policies": {
                  "default": {
                    "dns":{"mode":"fake"},
                    "rules":[],
                    "final":{"tcp":{"type":"route","outbound":"default"},"udp":{"type":"reject","method":"refused"}}
                  }
                }
              }
            }"#,
        );
        assert!(matches!(
            HeimdallConfig::load(&path),
            Err(ConfigError::ParseJson { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_duplicate_rule_match_values() {
        let source = valid_toml().replace(
            "[proxy.policies.default.final]",
            r#"[[proxy.policies.default.rules]]
name = "duplicate-port"
match = { network = ["tcp"], port = [443, 443] }
action = { type = "direct" }

[proxy.policies.default.final]"#,
        );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        let diagnostics = cfg.validate().unwrap_err().diagnostics();
        assert!(diagnostics.iter().any(|item| {
            item.code == "duplicate_match_value"
                && item.path == "$.proxy.policies.default.rules[0].match.port"
        }));
    }

    #[test]
    fn accepts_enabled_capture_with_explicit_storage_limits() {
        let source = valid_toml().replace(
            "[capture]\n            mode = \"off\"",
            "[capture]\n            mode = \"on\"\n            directory = \"/var/lib/heimdall/captures\"\n            max_bytes_per_flow = 4096",
        );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.capture.mode, CaptureMode::On);
        assert_eq!(cfg.capture.max_bytes_per_flow, 4096);
    }

    #[test]
    fn capture_diagnostics_are_machine_repairable() {
        let source = valid_toml().replace(
            "[capture]\n            mode = \"off\"",
            "[capture]\n            mode = \"on\"\n            directory = \"relative\"\n            max_bytes_per_flow = 0",
        );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        let diagnostics = cfg.validate().unwrap_err().diagnostics();
        assert!(diagnostics.iter().any(|item| {
            item.code == "relative_capture_directory" && item.path == "$.capture.directory"
        }));
        assert!(diagnostics.iter().any(|item| {
            item.code == "invalid_capture_limit" && item.path == "$.capture.max_bytes_per_flow"
        }));
    }

    #[test]
    fn rejects_fake_pools_too_small_for_stable_allocation() {
        let cfg: HeimdallConfig = toml::from_str(
            &valid_toml().replace(
                "[capture]",
                "[daemon]\nfake_ip_cidr = \"198.19.0.0/31\"\nfake_ip6_cidr = \"fc00:198:19::/125\"\n\n[capture]",
            ),
        )
        .unwrap();
        let diagnostics = cfg.validate().unwrap_err().diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "invalid_fake_ip_cidr")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "invalid_fake_ip6_cidr")
        );
    }

    #[test]
    fn rejects_exposed_or_conflicting_daemon_ports() {
        let cfg: HeimdallConfig = toml::from_str(&valid_toml().replace(
            "[capture]",
            "[daemon]\ndns_port = 12345\napi_listen = \"0.0.0.0:12345\"\n\n[capture]",
        ))
        .unwrap();
        let diagnostics = cfg.validate().unwrap_err().diagnostics();
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "non_loopback_control_listener")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "duplicate_daemon_port")
        );
    }

    #[test]
    fn reports_multiple_actionable_semantic_errors() {
        let source = valid_toml()
            .replace(
                "default_policy = \"default\"",
                "default_policy = \"missing\"",
            )
            .replace("server_port = 1080", "server_port = 0")
            .replace("network = [\"tcp\"]", "network = [\"tcp\", \"tcp\"]");
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        let error = cfg.validate().unwrap_err();
        let diagnostics = error.diagnostics();
        assert!(diagnostics.len() >= 3);
        assert!(
            diagnostics
                .iter()
                .all(|item| !item.path.is_empty() && !item.hint.is_empty())
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "unknown_default_policy")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "invalid_outbound_port")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "duplicate_outbound_network")
        );
    }

    #[test]
    fn rejects_domain_rules_with_system_dns() {
        let source = valid_toml()
            .replace("mode = \"fake\"", "mode = \"system\"")
            .replace(
                "[proxy.policies.default.final]",
                r#"[[proxy.policies.default.rules]]
name = "internal"
action = { type = "route", outbound = "default" }
[proxy.policies.default.rules.match]
network = ["tcp"]
domain_suffix = ["internal.example.com"]

[proxy.policies.default.final]"#,
            );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        assert!(
            cfg.validate()
                .unwrap_err()
                .diagnostics()
                .iter()
                .any(|item| item.code == "domain_rule_requires_fake_dns")
        );
    }

    #[test]
    fn ordered_rules_choose_route_direct_or_final() {
        let cfg: HeimdallConfig = toml::from_str(&valid_toml().replace(
            "[proxy.policies.default.final]",
            r#"[[proxy.policies.default.rules]]
name = "internal"
action = { type = "direct" }
[proxy.policies.default.rules.match]
network = ["tcp"]
domain_suffix = ["internal.example.com"]

[[proxy.policies.default.rules]]
name = "private-ip"
action = { type = "reject", method = "refused" }
[proxy.policies.default.rules.match]
network = ["tcp"]
ip_cidr = ["10.0.0.0/8"]

[proxy.policies.default.final]"#,
        ))
        .unwrap();
        cfg.validate().unwrap();
        let policy = cfg.default_policy();
        let (rule, action) = policy.explain_tcp(Some("api.internal.example.com"), None, 443);
        assert_eq!(rule.map(|rule| rule.name.as_str()), Some("internal"));
        assert!(matches!(action, Action::Direct));
        assert!(matches!(
            policy.decide_tcp(Some("api.internal.example.com"), None, 443),
            Action::Direct
        ));
        assert!(matches!(
            policy.decide_tcp(None, Some("10.1.2.3".parse().unwrap()), 443),
            Action::Reject { .. }
        ));
        assert!(matches!(
            policy.decide_tcp(None, Some("203.0.113.10".parse().unwrap()), 443),
            Action::Route { outbound } if outbound == "default"
        ));
        assert!(
            policy
                .explain_tcp(None, Some("203.0.113.10".parse().unwrap()), 443)
                .0
                .is_none()
        );
    }

    #[test]
    fn ordered_udp_rules_choose_route_or_final() {
        let source = valid_toml()
            .replace("network = [\"tcp\"]", "network = [\"tcp\", \"udp\"]")
            .replace(
                "[proxy.policies.default.final]",
                r#"[[proxy.policies.default.rules]]
name = "dns-over-udp"
action = { type = "route", outbound = "default" }
[proxy.policies.default.rules.match]
network = ["udp"]
port = [853]

[proxy.policies.default.final]"#,
            );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        cfg.validate().unwrap();
        let policy = cfg.default_policy();
        let (rule, action) = policy.explain_udp(None, Some("203.0.113.10".parse().unwrap()), 853);
        assert_eq!(rule.map(|rule| rule.name.as_str()), Some("dns-over-udp"));
        assert!(matches!(action, Action::Route { outbound } if outbound == "default"));
        assert!(matches!(
            policy.decide_udp(None, Some("203.0.113.10".parse().unwrap()), 443),
            Action::Reject { .. }
        ));
    }

    #[test]
    fn rejects_udp_route_to_tcp_only_outbound() {
        let source = valid_toml().replace(
            "udp = { type = \"reject\", method = \"refused\" }",
            "udp = { type = \"route\", outbound = \"default\" }",
        );
        let cfg: HeimdallConfig = toml::from_str(&source).unwrap();
        let diagnostics = cfg.validate().unwrap_err().diagnostics();
        assert!(diagnostics.iter().any(|item| {
            item.code == "outbound_network_mismatch"
                && item.path == "$.proxy.policies.default.final.udp.outbound"
        }));
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
