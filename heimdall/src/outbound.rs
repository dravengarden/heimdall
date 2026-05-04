//! Routing-file registry — loads and evaluates `routing/<tag>.{yaml,json,ncl}`
//! to pick a connection's `outboundTag`.
//!
//! Each pod's tag (resolved by `router::resolve_pod_decision`) names a
//! routing file. When the relay accepts a connection, this module
//! evaluates the file's rules against the destination (and optionally
//! the pod, via the same MatchCond fields) and returns the
//! `outboundTag` of the first matching rule.

use std::{
    collections::HashMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use heimdall_config::{Format, HeimdallConfig, MatchTarget, RoutingFile, SYSTEM_TAG};
use tracing::{info, warn};

use crate::pod::PodInfo;

/// All routing files loaded at startup, keyed by tag (filename minus
/// extension).
pub struct Registry {
    files: HashMap<String, Loaded>,
}

struct Loaded {
    #[allow(dead_code)]
    path: PathBuf,
    file: RoutingFile,
}

impl Registry {
    /// Scan `dir` for `*.yaml` / `*.json` / `*.ncl` files, parse each,
    /// and validate that every `outboundTag` references a real
    /// connection name.
    pub fn load(dir: &Path, cfg: &HeimdallConfig) -> Result<Self> {
        let mut files = HashMap::new();
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "routing dir not readable; using empty registry");
                return Ok(Self { files });
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let format = match Format::detect(&path) {
                Some(f) => f,
                None => continue,
            };
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if stem == SYSTEM_TAG {
                anyhow::bail!(
                    "routing file `{}` uses reserved tag `{}`",
                    path.display(),
                    SYSTEM_TAG
                );
            }

            let file: RoutingFile = match heimdall_config::parse_typed(&path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "load routing file {}: {e}",
                        path.display()
                    ));
                }
            };

            // Cross-validate outboundTag against connections.
            for rule in &file.rules {
                if !cfg.connections.contains_key(&rule.outbound_tag)
                    && rule.outbound_tag != SYSTEM_TAG
                {
                    anyhow::bail!(
                        "{}: rule references unknown outboundTag `{}`",
                        path.display(),
                        rule.outbound_tag
                    );
                }
                // Type check
                if let Some(t) = &rule.r#type {
                    if t != "field" {
                        warn!(
                            path = %path.display(),
                            r#type = t,
                            "rule type `{t}` not supported, treating as `field`",
                            t = t
                        );
                    }
                }
            }

            info!(
                tag = stem,
                path = %path.display(),
                format = ?format,
                rules = file.rules.len(),
                "routing file loaded"
            );
            files.insert(stem, Loaded { path, file });
        }

        // Cross-validate podRouting.rules and podRouting.default `use`
        // values against the loaded set.
        for rule in &cfg.pod_routing.rules {
            check_use_known(&rule.use_, &files)?;
        }
        check_use_known(&cfg.pod_routing.default.use_, &files)?;

        Ok(Self { files })
    }

    /// Resolve a destination to an outbound tag using the named
    /// routing file. Returns `None` if the tag isn't found (caller
    /// should fall back to a sane default), or `Some(SYSTEM_TAG)` if
    /// the tag itself is `system`.
    pub fn resolve(
        &self,
        tag: &str,
        pod: Option<&PodInfo>,
        dst_host: Option<&str>,
        dst_ip: Option<Ipv4Addr>,
        dst_port: u16,
    ) -> Option<String> {
        if tag == SYSTEM_TAG {
            return Some(SYSTEM_TAG.into());
        }

        let loaded = self.files.get(tag)?;

        let target = ConnTarget {
            pod,
            dst_host,
            dst_ip,
            dst_port,
        };

        for rule in &loaded.file.rules {
            if rule.matcher.evaluate(&target) {
                return Some(rule.outbound_tag.clone());
            }
        }
        // No rule matched (rare — most files end with a catchall).
        // Fall back to "default" for safety.
        warn!(
            tag,
            host = ?dst_host,
            "no rule matched in routing file; falling back to `default`"
        );
        Some("default".into())
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }
}

/// Evaluation target combining pod identity (for heimdall-extension
/// pod fields in routing files) with connection destination.
struct ConnTarget<'a> {
    pod: Option<&'a PodInfo>,
    dst_host: Option<&'a str>,
    dst_ip: Option<Ipv4Addr>,
    dst_port: u16,
}

impl<'a> MatchTarget for ConnTarget<'a> {
    fn pod_namespace(&self) -> Option<&str> {
        self.pod.map(|p| p.namespace.as_str())
    }
    fn pod_label(&self, key: &str) -> Option<&str> {
        self.pod.and_then(|p| p.labels.get(key).map(|s| s.as_str()))
    }
    fn dst_host(&self) -> Option<&str> {
        self.dst_host
    }
    fn dst_ip(&self) -> Option<Ipv4Addr> {
        self.dst_ip
    }
    fn dst_port(&self) -> Option<u16> {
        Some(self.dst_port)
    }
}

fn check_use_known(use_: &str, files: &HashMap<String, Loaded>) -> Result<()> {
    if use_ == SYSTEM_TAG {
        return Ok(());
    }
    if !files.contains_key(use_) {
        anyhow::bail!(
            "podRouting references unknown routing tag `{}` (no such file in routing/)",
            use_
        );
    }
    Ok(())
}

