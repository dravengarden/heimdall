//! Unit-side routing decisions.
//!
//! Resolves `(use, observe)` for a process's systemd identity by
//! walking `routing.rules` (first match wins) against the unit/slice
//! `MatchCond` grammar, then falling back to `routing.default`.
//!
//! `use` is either a connection name from `connections:` or the
//! reserved `system` keyword (eBPF bypass — skip the relay entirely).

use heimdall_config::{Decision, HeimdallConfig, MatchTarget};

use crate::unit::UnitInfo;

/// Bridge `UnitInfo` to the schema's `MatchTarget` trait so MatchCond
/// can evaluate against the resolved identity.
struct UnitMatchTarget<'a> {
    info: &'a UnitInfo,
}

impl<'a> MatchTarget for UnitMatchTarget<'a> {
    fn unit_name(&self) -> Option<&str> {
        self.info.unit.as_deref()
    }
    fn slice(&self) -> Option<&str> {
        self.info.slice.as_deref()
    }
}

/// Resolve the decision for a unit. Returns `(use_, observe)`.
///
/// Resolution order (each axis independently):
///   1. first matching rule in `routing.rules`
///   2. `routing.default`
pub fn resolve_decision(cfg: &HeimdallConfig, unit: Option<&UnitInfo>) -> Decision {
    let Some(unit) = unit else {
        return cfg.routing.default.clone();
    };

    let target = UnitMatchTarget { info: unit };

    Decision {
        use_: resolve_use(cfg, &target),
        observe: resolve_observe(cfg, &target),
    }
}

fn resolve_use(cfg: &HeimdallConfig, target: &UnitMatchTarget<'_>) -> String {
    for rule in &cfg.routing.rules {
        let cond_match = match &rule.match_ {
            None => true, // catchall when match block omitted
            Some(c) => c.evaluate(target),
        };
        if cond_match {
            return rule.use_.clone();
        }
    }
    cfg.routing.default.use_.clone()
}

fn resolve_observe(cfg: &HeimdallConfig, target: &UnitMatchTarget<'_>) -> bool {
    for rule in &cfg.routing.rules {
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
    cfg.routing.default.observe
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_config::{
        Connection, Decision, HeimdallConfig, Routing, Rule, Runtime, Socks5Connection,
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

        // A single rule using the unit/slice MatchCond schema.
        let match_yaml = r#"
units: [nginx.service]
slices: [system.slice]
"#;
        let m: heimdall_config::MatchCond = serde_yaml::from_str(match_yaml).unwrap();
        let rules = vec![Rule {
            name: Some("nginx".into()),
            match_: Some(m),
            use_: "default".into(),
            observe: Some(true),
        }];

        HeimdallConfig {
            api_version: "heimdall.io/v1alpha1".into(),
            kind: "HeimdallConfig".into(),
            runtime: Runtime::default(),
            connections,
            routing: Routing {
                rules,
                default: Decision { use_: "default".into(), observe: false },
            },
            cli: Default::default(),
        }
    }

    fn unit(unit: &str, slice: &str) -> UnitInfo {
        UnitInfo {
            unit: Some(unit.into()),
            slice: Some(slice.into()),
        }
    }

    #[test]
    fn default_when_no_unit() {
        let cfg = make_cfg();
        let d = resolve_decision(&cfg, None);
        assert_eq!(d.use_, "default");
        assert!(!d.observe);
    }

    #[test]
    fn rule_matches() {
        let cfg = make_cfg();
        let u = unit("nginx.service", "system.slice");
        let d = resolve_decision(&cfg, Some(&u));
        assert_eq!(d.use_, "default");
        assert!(d.observe);
    }

    #[test]
    fn no_rule_match_falls_back_to_default() {
        let cfg = make_cfg();
        let u = unit("mysql.service", "system.slice");
        let d = resolve_decision(&cfg, Some(&u));
        assert_eq!(d.use_, "default");
        assert!(!d.observe);
    }
}
