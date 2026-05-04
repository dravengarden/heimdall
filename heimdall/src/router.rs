//! Routing decision: pick a connection name AND observe flag for each pod.
//!
//! Two orthogonal axes:
//!   - `use`: connection name (any in `connections:`) or the reserved
//!     `system` keyword (skip eBPF redirect entirely).
//!   - `observe`: tap-on or tap-off for this pod's cgroup.
//!
//! Resolution order for each axis (independent):
//!
//!   1. Pod **annotation** at the relevant key
//!      (`routing.connectionKey` for `use`, `routing.observeKey` for
//!      `observe`).
//!   2. Pod **label** at the same key.
//!   3. `routing.rules` first match — both axes come from the same rule.
//!   4. `routing.default` — `use` and `observe` from the default block.
//!
//! Annotations win over labels if both are set, because annotations are
//! generally harder to set accidentally via templating.

use heimdall_config::{HeimdallConfig, Match, MatchExpression, MatchOperator, Rule, RoutingDecision, SYSTEM_CONNECTION};

use crate::pod::PodInfo;

/// Decide both the connection (`use`) and observation flag for a pod.
/// Falls back to `cfg.routing.default` when nothing else matches.
pub fn resolve_decision(cfg: &HeimdallConfig, pod: Option<&PodInfo>) -> RoutingDecision {
    let Some(pod) = pod else {
        return cfg.routing.default.clone();
    };

    // Walk both axes independently. Each gets its own per-axis lookup
    // (annotation → label → rule → default). Combining them at the end
    // means a pod can carry just `heimdall.io/observe: false` without
    // also having to spell out a connection.
    let use_ = resolve_use(cfg, pod);
    let observe = resolve_observe(cfg, pod);

    RoutingDecision { use_, observe }
}

fn resolve_use(cfg: &HeimdallConfig, pod: &PodInfo) -> String {
    let key = &cfg.routing.connection_key;

    if let Some(name) = pod.annotations.get(key) {
        if is_valid_use_name(cfg, name) {
            return name.clone();
        }
    }
    if let Some(name) = pod.labels.get(key) {
        if is_valid_use_name(cfg, name) {
            return name.clone();
        }
    }

    for rule in &cfg.routing.rules {
        if rule_matches(rule, pod) {
            return rule.use_.clone();
        }
    }

    cfg.routing.default.use_.clone()
}

fn resolve_observe(cfg: &HeimdallConfig, pod: &PodInfo) -> bool {
    let key = &cfg.routing.observe_key;

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

    for rule in &cfg.routing.rules {
        if rule_matches(rule, pod) {
            return rule.observe;
        }
    }

    cfg.routing.default.observe
}

fn is_valid_use_name(cfg: &HeimdallConfig, name: &str) -> bool {
    name == SYSTEM_CONNECTION || cfg.connections.contains_key(name)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn rule_matches(rule: &Rule, pod: &PodInfo) -> bool {
    let m = &rule.r#match;
    if !match_namespaces(m, pod) {
        return false;
    }
    if !match_labels(m, pod) {
        return false;
    }
    if !match_expressions(m, pod) {
        return false;
    }
    true
}

fn match_namespaces(m: &Match, pod: &PodInfo) -> bool {
    if m.namespaces.is_empty() {
        return true;
    }
    m.namespaces.iter().any(|n| n == &pod.namespace)
}

fn match_labels(m: &Match, pod: &PodInfo) -> bool {
    m.match_labels
        .iter()
        .all(|(k, v)| pod.labels.get(k).map(|pv| pv == v).unwrap_or(false))
}

fn match_expressions(m: &Match, pod: &PodInfo) -> bool {
    m.match_expressions.iter().all(|e| match_expr(e, pod))
}

fn match_expr(e: &MatchExpression, pod: &PodInfo) -> bool {
    let val = pod.labels.get(&e.key);
    match e.operator {
        MatchOperator::Exists => val.is_some(),
        MatchOperator::DoesNotExist => val.is_none(),
        MatchOperator::In => val.map(|v| e.values.iter().any(|x| x == v)).unwrap_or(false),
        MatchOperator::NotIn => val.map(|v| !e.values.iter().any(|x| x == v)).unwrap_or(true),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_config::{
        Connection, HeimdallConfig, Match, MatchExpression, MatchOperator, Routing, Rule,
        RoutingDecision, Runtime, Socks5Connection,
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
        connections.insert(
            "corp".into(),
            Connection::Socks5(Socks5Connection {
                description: None,
                owner: None,
                addr: "<UPSTREAM_IP>:1080".into(),
                auth: None,
                mitm: false,
            }),
        );

        let mut legacy_labels = BTreeMap::new();
        legacy_labels.insert("app.kubernetes.io/part-of".into(), "corp".into());

        let rules = vec![
            Rule {
                name: "noisy-controllers".into(),
                r#match: Match {
                    match_labels: BTreeMap::new(),
                    match_expressions: vec![],
                    namespaces: vec!["kube-system".into()],
                },
                use_: "system".into(),
                observe: false,
            },
            Rule {
                name: "legacy-corp".into(),
                r#match: Match {
                    match_labels: legacy_labels,
                    match_expressions: vec![],
                    namespaces: vec![],
                },
                use_: "corp".into(),
                observe: true,
            },
        ];

        HeimdallConfig {
            api_version: "heimdall.io/v1alpha1".into(),
            kind: "HeimdallConfig".into(),
            runtime: Runtime::default(),
            connections,
            routing: Routing {
                connection_key: "heimdall.io/connection".into(),
                observe_key: "heimdall.io/observe".into(),
                rules,
                default: RoutingDecision { use_: "default".into(), observe: true },
            },
        }
    }

    fn pod_with(labels: &[(&str, &str)], annotations: &[(&str, &str)]) -> PodInfo {
        PodInfo {
            uid: "u".into(),
            namespace: "ns".into(),
            name: "n".into(),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            annotations: annotations.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn no_pod_returns_default() {
        let cfg = make_cfg();
        let d = resolve_decision(&cfg, None);
        assert_eq!(d.use_, "default");
        assert!(d.observe);
    }

    #[test]
    fn nothing_matches_returns_default() {
        let cfg = make_cfg();
        let pod = pod_with(&[("env", "prod")], &[]);
        let d = resolve_decision(&cfg, Some(&pod));
        assert_eq!(d.use_, "default");
        assert!(d.observe);
    }

    #[test]
    fn annotation_selects_system_and_observe_off() {
        let cfg = make_cfg();
        let pod = pod_with(
            &[],
            &[
                ("heimdall.io/connection", "system"),
                ("heimdall.io/observe", "false"),
            ],
        );
        let d = resolve_decision(&cfg, Some(&pod));
        assert_eq!(d.use_, "system");
        assert!(!d.observe);
    }

    #[test]
    fn observe_axis_independent_of_connection_axis() {
        let cfg = make_cfg();
        // Just turn observe off via annotation; let `use` come from default.
        let pod = pod_with(&[], &[("heimdall.io/observe", "false")]);
        let d = resolve_decision(&cfg, Some(&pod));
        assert_eq!(d.use_, "default");
        assert!(!d.observe);
    }

    #[test]
    fn rule_provides_both_axes_when_no_annotations() {
        let cfg = make_cfg();
        let pod = PodInfo {
            namespace: "kube-system".into(),
            ..Default::default()
        };
        let d = resolve_decision(&cfg, Some(&pod));
        assert_eq!(d.use_, "system");
        assert!(!d.observe);
    }

    #[test]
    fn legacy_rule_observes_by_default() {
        let cfg = make_cfg();
        let pod = pod_with(&[("app.kubernetes.io/part-of", "corp")], &[]);
        let d = resolve_decision(&cfg, Some(&pod));
        assert_eq!(d.use_, "corp");
        assert!(d.observe);
    }

    #[test]
    fn invalid_use_in_annotation_falls_through() {
        let cfg = make_cfg();
        let pod = pod_with(
            &[("heimdall.io/connection", "corp")],
            &[("heimdall.io/connection", "ghost")],
        );
        // ghost is not in connections and not "system" → falls back to label.
        let d = resolve_decision(&cfg, Some(&pod));
        assert_eq!(d.use_, "corp");
    }

    #[test]
    fn invalid_observe_value_falls_through() {
        let cfg = make_cfg();
        let pod = pod_with(
            &[],
            &[("heimdall.io/observe", "maybe")],
        );
        // unparseable → falls through to default (observe: true).
        let d = resolve_decision(&cfg, Some(&pod));
        assert!(d.observe);
    }

    #[test]
    fn match_expression_in() {
        let mut cfg = make_cfg();
        cfg.routing.rules[1].r#match.match_labels.clear();
        cfg.routing.rules[1].r#match.match_expressions = vec![MatchExpression {
            key: "env".into(),
            operator: MatchOperator::In,
            values: vec!["prod".into(), "stg".into()],
        }];
        let p_prod = pod_with(&[("env", "prod")], &[]);
        assert_eq!(resolve_decision(&cfg, Some(&p_prod)).use_, "corp");
        let p_dev = pod_with(&[("env", "dev")], &[]);
        assert_eq!(resolve_decision(&cfg, Some(&p_dev)).use_, "default");
    }
}
