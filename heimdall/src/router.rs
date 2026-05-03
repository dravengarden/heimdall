//! Routing engine: pick a connection name for each pod.
//!
//! Resolution order (matches /etc/<host-config>/docs/heimdall.md):
//!
//!   1. Pod **annotation** at `routing.selectorKey`
//!      (default `heimdall.io/connection`) → use that connection.
//!   2. Pod **label** at the same `routing.selectorKey` → use that connection.
//!   3. `routing.rules` first match wins
//!      (admin-defined; for pods that can't set the selectorKey themselves).
//!   4. `routing.default`.
//!
//! Annotation wins over label if both are set, because annotations are
//! generally harder to set accidentally via templating.

use heimdall_config::{HeimdallConfig, Match, MatchExpression, MatchOperator, Rule};

use crate::pod::PodInfo;

/// Decide which connection name to use for a pod.
/// Falls back to `cfg.routing.default` if nothing matches.
///
/// Returns `String` (not `&str`) because the chosen name might come from
/// either `cfg` (rule / default) or from `pod` (annotation/label value),
/// which have unrelated lifetimes at the call site.
pub fn resolve_connection(cfg: &HeimdallConfig, pod: Option<&PodInfo>) -> String {
    let Some(pod) = pod else {
        return cfg.routing.default.clone();
    };

    let key = &cfg.routing.selector_key;

    // 1. Annotation override (chart-author explicit, hardest to set by accident).
    if let Some(name) = pod.annotations.get(key) {
        if cfg.connections.contains_key(name) {
            return name.clone();
        }
    }

    // 2. Label (chart-author declarative; also queryable by other tools).
    if let Some(name) = pod.labels.get(key) {
        if cfg.connections.contains_key(name) {
            return name.clone();
        }
    }

    // 3. Admin-defined rules — first match wins.
    for rule in &cfg.routing.rules {
        if rule_matches(rule, pod) {
            return rule.use_.clone();
        }
    }

    // 4. Default.
    cfg.routing.default.clone()
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
        Connection, DirectConnection, HeimdallConfig, Match, MatchExpression, MatchOperator,
        Routing, Rule, Runtime, Socks5Connection,
    };
    use std::collections::BTreeMap;

    fn make_cfg() -> HeimdallConfig {
        let mut connections = BTreeMap::new();
        connections.insert(
            "default".to_string(),
            Connection::Socks5(Socks5Connection {
                description: None,
                owner: None,
                addr: "127.0.0.1:20170".into(),
                auth: None,
                mitm: false,
            }),
        );
        connections.insert(
            "corp".to_string(),
            Connection::Socks5(Socks5Connection {
                description: None,
                owner: None,
                addr: "<UPSTREAM_IP>:1080".into(),
                auth: None,
                mitm: false,
            }),
        );
        connections.insert(
            "bypass".to_string(),
            Connection::Direct(DirectConnection { description: None, owner: None }),
        );

        // Admin-defined fallback rule for pods that can't set selectorKey.
        let mut legacy_labels = BTreeMap::new();
        legacy_labels.insert("app.kubernetes.io/part-of".into(), "corp".into());

        let rules = vec![Rule {
            name: "legacy-corp".into(),
            r#match: Match {
                match_labels: legacy_labels,
                match_expressions: vec![],
                namespaces: vec![],
            },
            use_: "corp".into(),
        }];

        HeimdallConfig {
            api_version: "heimdall.io/v1alpha1".into(),
            kind: "HeimdallConfig".into(),
            runtime: Runtime::default(),
            connections,
            routing: Routing {
                selector_key: "heimdall.io/connection".into(),
                rules,
                default: "default".into(),
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
        assert_eq!(resolve_connection(&cfg, None), "default");
    }

    #[test]
    fn nothing_matches_returns_default() {
        let cfg = make_cfg();
        let pod = pod_with(&[("env", "prod")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "default");
    }

    #[test]
    fn label_selector_key_picks_connection() {
        let cfg = make_cfg();
        let pod = pod_with(&[("heimdall.io/connection", "corp")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "corp");
    }

    #[test]
    fn annotation_selector_key_picks_connection() {
        let cfg = make_cfg();
        let pod = pod_with(&[], &[("heimdall.io/connection", "bypass")]);
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "bypass");
    }

    #[test]
    fn annotation_wins_over_label_when_both_set() {
        let cfg = make_cfg();
        let pod = pod_with(
            &[("heimdall.io/connection", "corp")],
            &[("heimdall.io/connection", "bypass")],
        );
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "bypass");
    }

    #[test]
    fn unknown_connection_in_annotation_falls_through() {
        let cfg = make_cfg();
        let pod = pod_with(
            &[("heimdall.io/connection", "corp")],
            &[("heimdall.io/connection", "ghost")],
        );
        // annotation = ghost (unknown) → fall through to label = corp
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "corp");
    }

    #[test]
    fn unknown_connection_in_label_falls_through_to_rules() {
        let cfg = make_cfg();
        let pod = pod_with(
            &[
                ("heimdall.io/connection", "ghost"),
                ("app.kubernetes.io/part-of", "corp"),
            ],
            &[],
        );
        // label says ghost (unknown) → falls to rule matching part-of=corp → corp
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "corp");
    }

    #[test]
    fn rule_matches_when_no_selector_key() {
        let cfg = make_cfg();
        let pod = pod_with(&[("app.kubernetes.io/part-of", "corp")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "corp");
    }

    #[test]
    fn match_expression_in() {
        let mut cfg = make_cfg();
        cfg.routing.rules[0].r#match.match_labels.clear();
        cfg.routing.rules[0].r#match.match_expressions = vec![MatchExpression {
            key: "env".into(),
            operator: MatchOperator::In,
            values: vec!["prod".into(), "stg".into()],
        }];

        let p_prod = pod_with(&[("env", "prod")], &[]);
        let p_dev = pod_with(&[("env", "dev")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&p_prod)), "corp");
        assert_eq!(resolve_connection(&cfg, Some(&p_dev)), "default");
    }

    #[test]
    fn namespace_filter() {
        let mut cfg = make_cfg();
        cfg.routing.rules[0].r#match.namespaces = vec!["corp-prod".into()];

        let p_in = PodInfo {
            namespace: "corp-prod".into(),
            labels: [("app.kubernetes.io/part-of".into(), "corp".into())].into(),
            ..Default::default()
        };
        let p_out = PodInfo {
            namespace: "default".into(),
            labels: [("app.kubernetes.io/part-of".into(), "corp".into())].into(),
            ..Default::default()
        };
        assert_eq!(resolve_connection(&cfg, Some(&p_in)), "corp");
        assert_eq!(resolve_connection(&cfg, Some(&p_out)), "default");
    }
}
