//! Pod-side routing decisions.
//!
//! Resolves `(use, observe)` for a pod by walking
//! `podRouting.rules` (first match wins) with the new
//! `MatchCond`-based schema, then falling back to
//! `podRouting.default`. Annotation overrides take precedence over
//! both rules and default.
//!
//! `use` is the **routing tag** — either a routing-file name (e.g.
//! `default`, `cluster`, `conviva`) or the reserved `system` keyword.
//! Destination-side resolution (`outboundTag`) happens in
//! `outbound.rs`.

use heimdall_config::{HeimdallConfig, MatchTarget, PodDecision, SYSTEM_TAG};

use crate::pod::PodInfo;

/// Bridge `PodInfo` to the schema's `MatchTarget` trait so MatchCond
/// can evaluate against the in-memory pod cache.
struct PodMatchTarget<'a> {
    info: &'a PodInfo,
}

impl<'a> MatchTarget for PodMatchTarget<'a> {
    fn pod_namespace(&self) -> Option<&str> {
        Some(&self.info.namespace)
    }
    fn pod_labels(&self) -> &std::collections::BTreeMap<String, String> {
        &self.info.labels
    }
}

/// Resolve the pod-side decision. Returns `(use_tag, observe)`.
///
/// Resolution order (each axis independently):
///   1. annotation `routingKey` / `observeKey` — take precedence
///   2. first matching rule in `podRouting.rules`
///   3. `podRouting.default`
pub fn resolve_pod_decision(cfg: &HeimdallConfig, pod: Option<&PodInfo>) -> PodDecision {
    let Some(pod) = pod else {
        return cfg.pod_routing.default.clone();
    };

    let target = PodMatchTarget { info: pod };

    let use_ = resolve_use(cfg, pod, &target);
    let observe = resolve_observe(cfg, pod, &target);
    PodDecision { use_, observe }
}

fn resolve_use(cfg: &HeimdallConfig, pod: &PodInfo, target: &PodMatchTarget<'_>) -> String {
    let key = &cfg.pod_routing.routing_key;

    if let Some(v) = pod.annotations.get(key) {
        if is_known_use(cfg, v) {
            return v.clone();
        }
    }
    if let Some(v) = pod.labels.get(key) {
        if is_known_use(cfg, v) {
            return v.clone();
        }
    }

    for rule in &cfg.pod_routing.rules {
        let cond_match = match &rule.match_ {
            None => true, // catchall when match block omitted
            Some(c) => c.evaluate(target),
        };
        if cond_match && is_known_use(cfg, &rule.use_) {
            return rule.use_.clone();
        }
    }

    cfg.pod_routing.default.use_.clone()
}

fn resolve_observe(
    cfg: &HeimdallConfig,
    pod: &PodInfo,
    target: &PodMatchTarget<'_>,
) -> bool {
    let key = &cfg.pod_routing.observe_key;
    if let Some(v) = pod.annotations.get(key) {
        if let Some(b) = parse_bool(v) {
            return b;
        }
    }
    if let Some(v) = pod.labels.get(key) {
        if let Some(b) = parse_bool(v) {
            return b;
        }
    }

    for rule in &cfg.pod_routing.rules {
        let cond_match = match &rule.match_ {
            None => true,
            Some(c) => c.evaluate(target),
        };
        if cond_match {
            if let Some(o) = rule.observe {
                return o;
            }
            // Rule matched but didn't specify observe → fall through to default.
            break;
        }
    }
    cfg.pod_routing.default.observe
}

/// `use` is valid if it's `system` or a known routing-file tag.
/// We don't have the routing-file registry here, so we accept anything
/// non-empty plus `system`; cross-validation against the loaded
/// routing files happens in `outbound::Registry::validate`.
fn is_known_use(_cfg: &HeimdallConfig, name: &str) -> bool {
    !name.is_empty() && (name == SYSTEM_TAG || name.chars().all(|c| !c.is_whitespace()))
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_config::{
        Connection, HeimdallConfig, PodDecision, PodRouting, PodRule, Runtime, Socks5Connection,
    };
    use std::collections::BTreeMap;

    fn make_cfg() -> HeimdallConfig {
        let mut connections = BTreeMap::new();
        connections.insert(
            "default".into(),
            Connection::Socks5(Socks5Connection {
                description: None,
                owner: None,
                addr: "127.0.0.1:20170".into(),
                auth: None,
                mitm: false,
            }),
        );

        // A single rule using the new MatchCond schema.
        let match_yaml = r#"
namespaces: [cattle-system]
matchLabels:
  app: rancher
"#;
        let m: heimdall_config::MatchCond = serde_yaml::from_str(match_yaml).unwrap();
        let rules = vec![PodRule {
            name: Some("rancher".into()),
            match_: Some(m),
            use_: "default".into(),
            observe: Some(true),
        }];

        HeimdallConfig {
            api_version: "heimdall.io/v1alpha1".into(),
            kind: "HeimdallConfig".into(),
            runtime: Runtime::default(),
            connections,
            pod_routing: PodRouting {
                routing_key: "heimdall.io/routing".into(),
                observe_key: "heimdall.io/observe".into(),
                rules,
                default: PodDecision { use_: "default".into(), observe: false },
            },
        }
    }

    fn pod_with(ns: &str, labels: &[(&str, &str)], annotations: &[(&str, &str)]) -> PodInfo {
        PodInfo {
            uid: "u".into(),
            namespace: ns.into(),
            name: "n".into(),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            annotations: annotations.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn default_when_no_pod() {
        let cfg = make_cfg();
        let d = resolve_pod_decision(&cfg, None);
        assert_eq!(d.use_, "default");
        assert!(!d.observe);
    }

    #[test]
    fn rule_matches() {
        let cfg = make_cfg();
        let p = pod_with("cattle-system", &[("app", "rancher")], &[]);
        let d = resolve_pod_decision(&cfg, Some(&p));
        assert_eq!(d.use_, "default");
        assert!(d.observe);
    }

    #[test]
    fn no_rule_match_falls_back_to_default() {
        let cfg = make_cfg();
        let p = pod_with("opik", &[("app.kubernetes.io/name", "mysql")], &[]);
        let d = resolve_pod_decision(&cfg, Some(&p));
        assert_eq!(d.use_, "default");
        assert!(!d.observe);
    }

    #[test]
    fn annotation_overrides() {
        let cfg = make_cfg();
        let p = pod_with(
            "default",
            &[],
            &[
                ("heimdall.io/routing", "system"),
                ("heimdall.io/observe", "true"),
            ],
        );
        let d = resolve_pod_decision(&cfg, Some(&p));
        assert_eq!(d.use_, "system");
        assert!(d.observe);
    }
}
