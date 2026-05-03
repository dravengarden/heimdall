//! Routing engine: pick a connection name for each pod.
//!
//! Resolution order (matches the doc at /etc/nixos/docs/heimdall.md):
//!
//!   1. Pod annotation (`routing.annotationKey`, default `heimdall.io/connection`)
//!      — if set and points to a known connection, wins outright.
//!   2. `routing.rules` — first label/expression match wins.
//!   3. `routing.default`.

use heimdall_config::{HeimdallConfig, Match, MatchExpression, MatchOperator, Rule};

use crate::pod::PodInfo;

/// Decide which connection name to use for a pod.
/// Falls back to `cfg.routing.default` if no annotation or rule matches.
///
/// Returns `String` (not `&str`) because the chosen name might come from
/// either `cfg` (rule / default) or from `pod` (annotation value), and
/// those have unrelated lifetimes at the call site.
pub fn resolve_connection(cfg: &HeimdallConfig, pod: Option<&PodInfo>) -> String {
    // No pod identity → default. (Connections from outside k8s, or cgroup
    // resolver missed, or informer hasn't synced yet.)
    let Some(pod) = pod else {
        return cfg.routing.default.clone();
    };

    // 1. Annotation override.
    if let Some(name) = pod.annotations.get(&cfg.routing.annotation_key) {
        if cfg.connections.contains_key(name) {
            return name.clone();
        }
        // Annotation present but unknown connection: fall through to rules.
    }

    // 2. Rules — first match wins.
    for rule in &cfg.routing.rules {
        if rule_matches(rule, pod) {
            return rule.use_.clone();
        }
    }

    // 3. Default.
    cfg.routing.default.clone()
}

fn rule_matches(rule: &Rule, pod: &PodInfo) -> bool {
    let m = &rule.r#match;

    // Empty match block matches everything (unusual but legal).
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
            "conviva".to_string(),
            Connection::Socks5(Socks5Connection {
                description: None,
                owner: None,
                addr: "192.168.0.155:1080".into(),
                auth: None,
                mitm: false,
            }),
        );
        connections.insert(
            "bypass".to_string(),
            Connection::Direct(DirectConnection { description: None, owner: None }),
        );

        let mut conviva_labels = BTreeMap::new();
        conviva_labels.insert("family".to_string(), "conviva".to_string());

        let rules = vec![Rule {
            name: "conviva-family".into(),
            r#match: Match {
                match_labels: conviva_labels,
                match_expressions: vec![],
                namespaces: vec![],
            },
            use_: "conviva".into(),
        }];

        HeimdallConfig {
            api_version: "heimdall.io/v1alpha1".into(),
            kind: "HeimdallConfig".into(),
            runtime: Runtime::default(),
            connections,
            routing: Routing {
                annotation_key: "heimdall.io/connection".into(),
                rules,
                default: "default".into(),
            },
        }
    }

    fn make_pod(labels: &[(&str, &str)], annotations: &[(&str, &str)]) -> PodInfo {
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
    fn no_match_returns_default() {
        let cfg = make_cfg();
        let pod = make_pod(&[("env", "prod")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "default");
    }

    #[test]
    fn label_match_wins() {
        let cfg = make_cfg();
        let pod = make_pod(&[("family", "conviva")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "conviva");
    }

    #[test]
    fn annotation_overrides_rule() {
        let cfg = make_cfg();
        let pod = make_pod(
            &[("family", "conviva")],
            &[("heimdall.io/connection", "bypass")],
        );
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "bypass");
    }

    #[test]
    fn unknown_annotation_falls_through_to_rule() {
        let cfg = make_cfg();
        let pod = make_pod(
            &[("family", "conviva")],
            &[("heimdall.io/connection", "ghost")],
        );
        assert_eq!(resolve_connection(&cfg, Some(&pod)), "conviva");
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

        let p_prod = make_pod(&[("env", "prod")], &[]);
        let p_dev = make_pod(&[("env", "dev")], &[]);
        assert_eq!(resolve_connection(&cfg, Some(&p_prod)), "conviva");
        assert_eq!(resolve_connection(&cfg, Some(&p_dev)), "default");
    }

    #[test]
    fn namespace_filter() {
        let mut cfg = make_cfg();
        cfg.routing.rules[0].r#match.namespaces = vec!["conviva-prod".into()];

        let p_in = PodInfo {
            namespace: "conviva-prod".into(),
            labels: [("family".to_string(), "conviva".to_string())].into(),
            ..Default::default()
        };
        let p_out = PodInfo {
            namespace: "default".into(),
            labels: [("family".to_string(), "conviva".to_string())].into(),
            ..Default::default()
        };
        assert_eq!(resolve_connection(&cfg, Some(&p_in)), "conviva");
        assert_eq!(resolve_connection(&cfg, Some(&p_out)), "default");
    }
}
