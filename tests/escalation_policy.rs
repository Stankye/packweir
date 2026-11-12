use chrono::{DateTime, Duration, Utc};
use packweir::{
    config::{CommandScanner, Config},
    explain,
    identity::{self, DeliveryScope},
    model::{Decision, Evidence, Outcome, evidence_fingerprint},
    policy::{
        AgentEscalation, EffectivePolicy, EscalationState, OutcomeCondition, Policy,
        PolicyRequirements, PolicyScope,
    },
};
use serde_json::json;

fn rule(check: &str, outcomes: &[Outcome]) -> AgentEscalation {
    AgentEscalation {
        when_any: vec![OutcomeCondition {
            check: check.into(),
            outcomes: outcomes.to_vec(),
        }],
    }
}

fn policy() -> Policy {
    Policy {
        trust_agent: true,
        agent_escalation: Some(rule("heuristics", &[Outcome::Inconclusive])),
        ..Policy::default()
    }
}

fn evidence(check: &str, outcome: Outcome, now: DateTime<Utc>) -> Evidence {
    Evidence {
        subject: "artifact".into(),
        check: check.into(),
        tool_version: "fixture-v1".into(),
        configuration: "configuration".into(),
        outcome,
        created_at: now - Duration::seconds(10),
        expires_at: now + Duration::hours(1),
        details: if check == "agent" {
            json!({"model":"local/model@revision", "prompt_digest":"a".repeat(64),
                "toolset_digest":"b".repeat(64), "evidence_digest":"c".repeat(64), "trace_digest":"d".repeat(64)})
        } else {
            json!({})
        },
        references: vec![],
    }
}

fn evaluate(policy: &Policy, evidence: &[Evidence], now: DateTime<Utc>) -> Decision {
    let mut evidence = evidence.to_vec();
    let ordinary: Vec<_> = evidence
        .iter()
        .filter(|e| e.check != "agent")
        .cloned()
        .collect();
    for agent in evidence
        .iter_mut()
        .filter(|e| e.check == "agent" && e.outcome == Outcome::Pass)
    {
        if policy.agent_escalation.is_some() && agent.details.get("packweir_inputs").is_none() {
            bind_inputs(agent, &ordinary);
        }
    }
    policy.evaluate("artifact", "configuration", &evidence, now)
}

fn bind_inputs(agent: &mut Evidence, findings: &[Evidence]) {
    let map: std::collections::BTreeMap<_, _> = findings
        .iter()
        .filter(|e| e.check != "agent")
        .map(|e| (e.check.clone(), evidence_fingerprint(e)))
        .collect();
    agent.details["packweir_inputs"] = json!({"version":1,"findings":map});
}

fn state(policy: &Policy, evidence: &[Evidence], now: DateTime<Utc>) -> EscalationState {
    policy.escalation_state("artifact", "configuration", evidence, now)
}

#[test]
fn conditional_agent_is_required_only_after_an_upstream_match() {
    let now = Utc::now();
    let policy = policy();
    let inventory = evidence("inventory", Outcome::Pass, now);
    let clear = evidence("heuristics", Outcome::Pass, now);
    let suspicious = evidence("heuristics", Outcome::Inconclusive, now);
    let skipped = evidence("agent", Outcome::Skipped, now);
    assert_eq!(
        state(&policy, std::slice::from_ref(&clear), now),
        EscalationState::NotTriggered
    );
    assert_eq!(
        evaluate(&policy, &[inventory.clone(), clear, skipped.clone()], now),
        Decision::Approved
    );
    assert_eq!(
        state(&policy, std::slice::from_ref(&suspicious), now),
        EscalationState::Triggered {
            checks: vec!["heuristics".into()]
        }
    );
    assert_eq!(
        evaluate(
            &policy,
            &[inventory.clone(), suspicious.clone(), skipped],
            now
        ),
        Decision::Pending(vec!["agent".into()])
    );
    assert_eq!(
        evaluate(
            &policy,
            &[inventory, suspicious, evidence("agent", Outcome::Pass, now)],
            now
        ),
        Decision::Approved
    );
}

#[test]
fn every_condition_needs_current_bound_input_even_when_another_matches() {
    let now = Utc::now();
    let mut policy = policy();
    policy
        .agent_escalation
        .as_mut()
        .unwrap()
        .when_any
        .push(OutcomeCondition {
            check: "source_posture".into(),
            outcomes: vec![Outcome::Error],
        });
    let suspicious = evidence("heuristics", Outcome::Inconclusive, now);
    let valid = evidence("source_posture", Outcome::Pass, now);
    let mut expired = valid.clone();
    expired.expires_at = now;
    let mut future = valid.clone();
    future.created_at = now + Duration::seconds(1);
    let mut wrong_subject = valid.clone();
    wrong_subject.subject = "other".into();
    let mut wrong_configuration = valid.clone();
    wrong_configuration.configuration = "other".into();
    let skipped = evidence("source_posture", Outcome::Skipped, now);
    for additional in [
        vec![],
        vec![expired],
        vec![future],
        vec![wrong_subject],
        vec![wrong_configuration],
        vec![skipped],
    ] {
        let mut findings = vec![
            suspicious.clone(),
            evidence("agent", Outcome::Pass, now),
            evidence("inventory", Outcome::Pass, now),
        ];
        findings.extend(additional);
        assert_eq!(
            state(&policy, &findings, now),
            EscalationState::Unresolved {
                checks: vec!["source_posture".into()]
            }
        );
        assert_eq!(
            evaluate(&policy, &findings, now),
            Decision::Pending(vec!["agent_escalation:source_posture".into()])
        );
    }
    assert_eq!(
        state(&policy, &[suspicious, valid], now),
        EscalationState::Triggered {
            checks: vec!["heuristics".into()]
        }
    );
}

#[test]
fn latest_input_controls_the_condition_and_invalid_latest_does_not_revive_old_results() {
    let now = Utc::now();
    let policy = policy();
    let old = evidence("heuristics", Outcome::Inconclusive, now);
    let mut latest = evidence("heuristics", Outcome::Pass, now);
    latest.created_at = now - Duration::seconds(1);
    assert_eq!(
        state(&policy, &[latest.clone(), old.clone()], now),
        EscalationState::NotTriggered
    );
    latest.expires_at = now;
    assert_eq!(
        state(&policy, &[old, latest], now),
        EscalationState::Unresolved {
            checks: vec!["heuristics".into()]
        }
    );
}

#[test]
fn conflicting_latest_inputs_are_unresolved_independent_of_evidence_order() {
    let now = Utc::now();
    let policy = policy();
    let suspicious = evidence("heuristics", Outcome::Inconclusive, now);
    let clear = evidence("heuristics", Outcome::Pass, now);
    for inputs in [
        vec![suspicious.clone(), clear.clone()],
        vec![clear, suspicious],
    ] {
        assert_eq!(
            state(&policy, &inputs, now),
            EscalationState::Unresolved {
                checks: vec!["heuristics".into()]
            }
        );
    }
    let valid = evidence("heuristics", Outcome::Pass, now);
    let mut expired = valid.clone();
    expired.expires_at = now;
    for inputs in [vec![valid.clone(), expired.clone()], vec![expired, valid]] {
        assert_eq!(
            state(&policy, &inputs, now),
            EscalationState::Unresolved {
                checks: vec!["heuristics".into()]
            }
        );
    }
}

#[test]
fn mandatory_and_denial_checks_resolve_latest_ties_without_order_dependent_approval() {
    let now = Utc::now();
    let policy = Policy::default();
    let pass = evidence("inventory", Outcome::Pass, now);
    for other in [Outcome::Fail, Outcome::Error] {
        let conflicting = evidence("inventory", other, now);
        let expected = if other == Outcome::Fail {
            Decision::Denied(vec!["inventory".into()])
        } else {
            Decision::Pending(vec!["inventory".into()])
        };
        for findings in [
            vec![pass.clone(), conflicting.clone()],
            vec![conflicting, pass.clone()],
        ] {
            assert_eq!(evaluate(&policy, &findings, now), expected);
        }
    }
    let mut policy = policy;
    policy.deny_on_failure.push("optional".into());
    for other in [Outcome::Fail, Outcome::Error] {
        let pass = evidence("optional", Outcome::Pass, now);
        let conflicting = evidence("optional", other, now);
        let expected = if other == Outcome::Fail {
            Decision::Denied(vec!["optional".into()])
        } else {
            Decision::Approved
        };
        for findings in [
            vec![pass.clone(), conflicting.clone()],
            vec![conflicting, pass],
        ] {
            let mut findings = findings;
            findings.push(evidence("inventory", Outcome::Pass, now));
            assert_eq!(evaluate(&policy, &findings, now), expected);
        }
    }
}

#[test]
fn agent_skip_cannot_disable_conditions_or_replace_unconditional_checks() {
    let now = Utc::now();
    let mut policy = policy();
    let findings = vec![
        evidence("inventory", Outcome::Pass, now),
        evidence("agent", Outcome::Skipped, now),
    ];
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["agent_escalation:heuristics".into()])
    );
    policy.required.push("agent".into());
    assert!(policy.agent_always_required());
    let mut findings = findings;
    findings.push(evidence("heuristics", Outcome::Pass, now));
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["agent".into()])
    );
}

#[test]
fn conditional_agent_keeps_trust_binding_and_nonpass_requirements() {
    let now = Utc::now();
    let mut policy = policy();
    let base = vec![
        evidence("inventory", Outcome::Pass, now),
        evidence("heuristics", Outcome::Inconclusive, now),
    ];
    for outcome in [
        Outcome::Inconclusive,
        Outcome::Unsupported,
        Outcome::Error,
        Outcome::Skipped,
    ] {
        let mut findings = base.clone();
        findings.push(evidence("agent", outcome, now));
        assert_eq!(
            evaluate(&policy, &findings, now),
            Decision::Pending(vec!["agent".into()])
        );
    }
    let mut findings = base.clone();
    let mut unbound = evidence("agent", Outcome::Pass, now);
    unbound.details = json!({});
    findings.push(unbound);
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["agent".into()])
    );
    let mut findings = base;
    findings.push(evidence("agent", Outcome::Pass, now));
    policy.trust_agent = false;
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["agent".into()])
    );
    policy.trust_agent = true;
    findings.last_mut().unwrap().outcome = Outcome::Fail;
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Denied(vec!["agent".into()])
    );
}

#[test]
fn agent_does_not_waive_ordinary_requirements_or_hard_failures() {
    let now = Utc::now();
    let mut policy = policy();
    policy.required.push("heuristics".into());
    let findings = vec![
        evidence("inventory", Outcome::Pass, now),
        evidence("heuristics", Outcome::Inconclusive, now),
        evidence("agent", Outcome::Pass, now),
    ];
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["heuristics".into()])
    );
    for hard in ["integrity", "archive_safety", "required_signature"] {
        let mut findings = findings.clone();
        findings.push(evidence(hard, Outcome::Fail, now));
        assert_eq!(
            evaluate(&policy, &findings, now),
            Decision::Denied(vec![hard.into()])
        );
    }
}

#[test]
fn a_current_agent_verdict_cannot_approve_a_new_generation_of_findings() {
    let now = Utc::now();
    let policy = policy();
    let inventory = evidence("inventory", Outcome::Pass, now);
    let original = evidence("heuristics", Outcome::Inconclusive, now);
    let mut agent = evidence("agent", Outcome::Pass, now);
    bind_inputs(&mut agent, &[inventory.clone(), original.clone()]);
    let mut findings = vec![inventory, original.clone(), agent];
    assert_eq!(evaluate(&policy, &findings, now), Decision::Approved);
    let mut newer = original;
    newer.created_at += Duration::seconds(1);
    newer.details = json!({"new_finding":"requires a fresh investigation"});
    findings.push(newer);
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["agent".into()])
    );
    let ordinary: Vec<_> = findings
        .iter()
        .filter(|e| e.check != "agent")
        .cloned()
        .collect();
    bind_inputs(&mut findings[2], &ordinary);
    assert_eq!(evaluate(&policy, &findings, now), Decision::Approved);
}

#[test]
fn expired_future_or_skipped_newer_agent_evidence_does_not_revive_an_old_pass() {
    let now = Utc::now();
    let mut policy = Policy {
        trust_agent: true,
        ..Policy::default()
    };
    policy.required.push("agent".into());
    let inventory = evidence("inventory", Outcome::Pass, now);
    let old = evidence("agent", Outcome::Pass, now);
    for (outcome, expired, future) in [
        (Outcome::Pass, true, false),
        (Outcome::Fail, true, false),
        (Outcome::Pass, false, true),
        (Outcome::Skipped, false, false),
    ] {
        let mut newest = old.clone();
        newest.created_at = if future {
            now + Duration::seconds(1)
        } else {
            now - Duration::seconds(1)
        };
        newest.outcome = outcome;
        if expired {
            newest.expires_at = now;
        }
        assert_eq!(
            evaluate(&policy, &[inventory.clone(), old.clone(), newest], now),
            Decision::Pending(vec!["agent".into()])
        );
    }
}

#[test]
fn conditional_input_binding_is_required_validated_and_matches_every_latest_tie() {
    let now = Utc::now();
    let policy = policy();
    let ordinary = vec![
        evidence("inventory", Outcome::Pass, now),
        evidence("heuristics", Outcome::Inconclusive, now),
    ];
    let agent = evidence("agent", Outcome::Pass, now);
    let mut findings = ordinary.clone();
    findings.push(agent.clone());
    assert_eq!(
        policy.evaluate("artifact", "configuration", &findings, now),
        Decision::Pending(vec!["agent".into()])
    );
    let mut bound = agent;
    bind_inputs(&mut bound, &ordinary);
    assert!(policy.agent_inputs_match(&bound, "artifact", "configuration", &ordinary, now));
    let valid = bound.details["packweir_inputs"].clone();
    let mut invalid = vec![
        json!(null),
        json!({"version":2,"findings":valid["findings"]}),
        json!({"version":1,"findings":{}}),
        json!({"version":1,"findings":{"heuristics":"malformed"}}),
    ];
    let mut missing = valid.clone();
    missing["findings"]
        .as_object_mut()
        .unwrap()
        .remove("heuristics");
    invalid.push(missing);
    let mut self_reference = valid.clone();
    self_reference["findings"]["agent"] = json!("a".repeat(64));
    invalid.push(self_reference);
    let mut extra = valid.clone();
    extra["unexpected"] = json!(true);
    invalid.push(extra);
    let mut oversized = valid.clone();
    for index in 0..1025 {
        oversized["findings"][format!("check{index}")] = json!("a".repeat(64));
    }
    invalid.push(oversized);
    for value in invalid {
        let mut invalid = bound.clone();
        invalid.details["packweir_inputs"] = value;
        assert!(
            !policy.agent_inputs_match(&invalid, "artifact", "configuration", &ordinary, now),
            "unexpectedly accepted {}",
            invalid.details["packweir_inputs"]
        );
    }
    let mut conflicting = ordinary[1].clone();
    conflicting.details = json!({"different":"same timestamp"});
    let mut tied = ordinary;
    tied.push(conflicting);
    assert!(!policy.agent_inputs_match(&bound, "artifact", "configuration", &tied, now));
}

#[test]
fn supplied_legacy_bindings_are_checked_and_optional_skipped_inputs_are_still_known_data() {
    let now = Utc::now();
    let mut policy = Policy {
        trust_agent: true,
        ..Policy::default()
    };
    policy.required.push("agent".into());
    let ordinary = vec![
        evidence("inventory", Outcome::Pass, now),
        evidence("optional", Outcome::Skipped, now),
    ];
    let mut agent = evidence("agent", Outcome::Pass, now);
    bind_inputs(&mut agent, &ordinary);
    let mut findings = ordinary;
    findings.push(agent);
    assert_eq!(evaluate(&policy, &findings, now), Decision::Approved);
    findings[1].details = json!({"changed":true});
    assert_eq!(
        evaluate(&policy, &findings, now),
        Decision::Pending(vec!["agent".into()])
    );
}

#[test]
fn explanations_never_report_pass_for_fresh_and_expired_latest_agent_or_trigger_ties() {
    let now = Utc::now();
    let delivery = scope(&config());
    for check in ["agent", "heuristics"] {
        let policy = if check == "agent" {
            Policy {
                trust_agent: true,
                required: vec!["inventory".into(), "agent".into()],
                ..Policy::default()
            }
        } else {
            policy()
        };
        let fresh = evidence(check, Outcome::Pass, now);
        let mut expired = fresh.clone();
        expired.expires_at = now;
        for tied in [vec![fresh.clone(), expired.clone()], vec![expired, fresh]] {
            let mut findings = vec![evidence("inventory", Outcome::Pass, now)];
            findings.extend(tied);
            let explanation = explain::scope(
                "artifact",
                delivery.clone(),
                "configuration".into(),
                EffectivePolicy {
                    policy: policy.clone(),
                    layers: vec!["global:test".into()],
                    identity_required: false,
                },
                &findings,
                now,
            );
            assert!(matches!(&explanation.decision, Decision::Pending(_)));
            let explained = explanation
                .checks
                .iter()
                .find(|entry| entry.check == check)
                .unwrap();
            assert_ne!(
                explained.status, "pass",
                "{check} cannot pass from the order of mixed-validity evidence"
            );
        }
    }
}

fn requirements(rule: AgentEscalation) -> PolicyRequirements {
    PolicyRequirements {
        revision: "additions-v1".into(),
        required: vec!["ordinary".into()],
        deny_on_failure: vec!["explicit_denial".into()],
        agent_escalation: Some(rule),
    }
}

#[test]
fn policy_layers_union_conditions_and_outcomes_in_a_stable_order() {
    let first = requirements(rule("heuristics", &[Outcome::Inconclusive]));
    let second = requirements(rule("heuristics", &[Outcome::Error, Outcome::Inconclusive]));
    let third = requirements(rule("source_posture", &[Outcome::Unsupported]));
    let mut left = Policy::default();
    for addition in [&first, &second, &third] {
        left.extend(addition);
    }
    let mut right = Policy::default();
    for addition in [&third, &second, &first] {
        right.extend(addition);
    }
    assert_eq!(left.fingerprint(), right.fingerprint());
    assert_eq!(
        left.escalation_check_names(),
        vec!["heuristics", "source_posture"]
    );
    let conditions = &left.agent_escalation.as_ref().unwrap().when_any;
    assert_eq!(
        conditions[0].outcomes,
        vec![Outcome::Error, Outcome::Inconclusive]
    );
    assert!(left.required.contains(&"inventory".into()));
    assert!(left.required.contains(&"ordinary".into()));
    assert!(left.deny_on_failure.contains(&"explicit_denial".into()));
}

fn config() -> Config {
    let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    config.policy.trust_agent = true;
    let adapter: CommandScanner = serde_json::from_value(
        json!({"program":std::env::current_exe().unwrap(), "version":"fixture-v1"}),
    )
    .unwrap();
    for check in ["agent", "heuristics", "source_posture"] {
        config.scanners.insert(check.into(), adapter.clone());
    }
    config
}

fn scope(config: &Config) -> DeliveryScope {
    let origin = "https://registry.npmjs.org/@acme/widget/-/widget-1.0.0.tgz";
    DeliveryScope {
        repository: "npm".into(),
        origin: origin.into(),
        filename: "widget-1.0.0.tgz".into(),
        package: identity::observe(&config.repositories["npm"], &origin.parse().unwrap(), ""),
    }
}

#[test]
fn repository_and_package_conditions_are_additive_and_bound_to_delivery_configuration() {
    let mut config = config();
    let delivery = scope(&config);
    let original = config.delivery_fingerprint(&delivery).unwrap();
    config.policy.agent_escalation = Some(rule("inventory", &[Outcome::Inconclusive]));
    config.repositories.get_mut("npm").unwrap().policy =
        Some(requirements(rule("heuristics", &[Outcome::Inconclusive])));
    config.policy_scopes.push(PolicyScope {
        name: "acme".into(),
        repository: "npm".into(),
        namespace: Some("@acme".into()),
        package: None,
        policy: requirements(rule("source_posture", &[Outcome::Unsupported])),
    });
    config.validate().unwrap();
    let effective = config.effective_policy(&delivery).unwrap();
    assert_eq!(
        effective.policy.escalation_check_names(),
        vec!["heuristics", "inventory", "source_posture"]
    );
    assert!(effective.policy.required.contains(&"inventory".into()));
    assert!(
        effective
            .policy
            .required
            .contains(&"package_identity".into())
    );
    assert_ne!(config.delivery_fingerprint(&delivery).unwrap(), original);
    let serialized = toml::to_string(&config).unwrap();
    let decoded: Config = toml::from_str(&serialized).unwrap();
    decoded.validate().unwrap();
    assert_eq!(config.fingerprint(), decoded.fingerprint());
    let previous = config.delivery_fingerprint(&delivery).unwrap();
    config.policy_scopes[0]
        .policy
        .agent_escalation
        .as_mut()
        .unwrap()
        .when_any[0]
        .outcomes
        .push(Outcome::Error);
    assert_ne!(config.delivery_fingerprint(&delivery).unwrap(), previous);
}

#[test]
fn validation_rejects_invalid_conditions_and_requires_agent_authorization_in_every_layer() {
    let mut invalid = vec![
        AgentEscalation { when_any: vec![] },
        rule("agent", &[Outcome::Inconclusive]),
        rule("missing", &[Outcome::Inconclusive]),
        rule("integrity", &[Outcome::Fail]),
        rule("heuristics", &[]),
        rule("heuristics", &[Outcome::Skipped]),
        rule("heuristics", &[Outcome::Error, Outcome::Error]),
    ];
    let mut duplicate = rule("heuristics", &[Outcome::Error]);
    duplicate.when_any.push(duplicate.when_any[0].clone());
    invalid.push(duplicate);
    invalid.push(AgentEscalation {
        when_any: vec![
            OutcomeCondition {
                check: "heuristics".into(),
                outcomes: vec![Outcome::Error],
            };
            65
        ],
    });
    invalid.push(rule("heuristics", &[Outcome::Error; 6]));
    for rule in invalid {
        let mut config = config();
        config.policy.agent_escalation = Some(rule);
        assert!(config.validate().is_err());
    }
    for builtin in ["inventory", "archive_safety", "package_identity"] {
        let mut config = config();
        config.policy.agent_escalation = Some(rule(builtin, &[Outcome::Fail]));
        config.validate().unwrap();
    }
    for layer in 0..3 {
        let mut config = config();
        let condition = rule("heuristics", &[Outcome::Inconclusive]);
        match layer {
            0 => config.policy.agent_escalation = Some(condition),
            1 => config.repositories.get_mut("npm").unwrap().policy = Some(requirements(condition)),
            _ => config.policy_scopes.push(PolicyScope {
                name: "acme".into(),
                repository: "npm".into(),
                namespace: Some("@acme".into()),
                package: None,
                policy: requirements(condition),
            }),
        }
        config.validate().unwrap();
        let mut untrusted = config.clone();
        untrusted.policy.trust_agent = false;
        assert!(untrusted.validate().is_err());
        config.scanners.remove("agent");
        assert!(config.validate().is_err());
    }
}

#[test]
fn omitted_escalation_keeps_legacy_policy_defaults_and_serialization() {
    let policy: Policy = serde_json::from_value(json!({"revision":"legacy"})).unwrap();
    assert!(policy.agent_escalation.is_none());
    assert_eq!(policy.required, vec!["inventory"]);
    assert!(!policy.trust_agent);
    assert!(
        serde_json::to_value(&policy)
            .unwrap()
            .get("agent_escalation")
            .is_none()
    );
    assert_eq!(
        state(&policy, &[], Utc::now()),
        EscalationState::NotTriggered
    );
    let additions: PolicyRequirements =
        serde_json::from_value(json!({"revision":"legacy"})).unwrap();
    assert!(additions.agent_escalation.is_none());
    assert!(additions.required.is_empty());
    assert!(
        serde_json::to_value(&additions)
            .unwrap()
            .get("agent_escalation")
            .is_none()
    );
}
