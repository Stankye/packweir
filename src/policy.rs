use crate::model::{Decision, Evidence, Outcome, agent_binding, evidence_fingerprint, sha256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeCondition {
    pub check: String,
    pub outcomes: Vec<Outcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEscalation {
    pub when_any: Vec<OutcomeCondition>,
}

impl AgentEscalation {
    fn merge(&mut self, additions: &Self) {
        let mut conditions = BTreeMap::<String, Vec<Outcome>>::new();
        for condition in self.when_any.iter().chain(&additions.when_any) {
            let outcomes = conditions.entry(condition.check.clone()).or_default();
            outcomes.extend(&condition.outcomes);
        }
        self.when_any = conditions
            .into_iter()
            .map(|(check, mut outcomes)| {
                // Sort stable wire names to make additive policy order deterministic.
                outcomes.sort_by_key(|outcome| {
                    serde_json::to_string(outcome).expect("serializable outcome")
                });
                outcomes.dedup();
                OutcomeCondition { check, outcomes }
            })
            .collect();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EscalationState {
    Triggered { checks: Vec<String> },
    NotTriggered,
    Unresolved { checks: Vec<String> },
}

/// Return every applicable record at the latest timestamp, preserving conflicting
/// results so callers cannot approve according to their input ordering.
pub fn latest_applicable<'a>(
    subject: &str,
    check: &str,
    configuration: &str,
    evidence: &'a [Evidence],
    now: DateTime<Utc>,
) -> Vec<&'a Evidence> {
    let applicable = evidence
        .iter()
        .filter(|e| e.applicable(subject, check, configuration, now));
    let Some(latest) = applicable.clone().map(|e| e.created_at).max() else {
        return vec![];
    };
    applicable.filter(|e| e.created_at == latest).collect()
}

/// Preserve the newest observed generation, including records that are no longer valid.
pub fn latest_observed<'a>(
    subject: &str,
    check: &str,
    configuration: &str,
    evidence: &'a [Evidence],
) -> Vec<&'a Evidence> {
    let matching = evidence
        .iter()
        .filter(|e| e.subject == subject && e.check == check && e.configuration == configuration);
    let Some(latest) = matching.clone().map(|e| e.created_at).max() else {
        return vec![];
    };
    matching.filter(|e| e.created_at == latest).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequirements {
    pub revision: String,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub deny_on_failure: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_escalation: Option<AgentEscalation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScope {
    pub name: String,
    pub repository: String,
    pub namespace: Option<String>,
    pub package: Option<String>,
    pub policy: PolicyRequirements,
}

impl PolicyScope {
    pub fn matches(&self, identity: &crate::identity::PackageIdentity) -> bool {
        self.package.as_ref().is_none_or(|p| {
            if identity.ecosystem == crate::model::Ecosystem::Cargo {
                p.replace('_', "-") == identity.name.replace('_', "-")
            } else {
                p == &identity.name
            }
        }) && self.namespace.as_ref().is_none_or(|expected| {
            identity.namespace.as_ref().is_some_and(|actual| {
                actual == expected
                    || (identity.ecosystem == crate::model::Ecosystem::Maven
                        && actual
                            .strip_prefix(expected)
                            .is_some_and(|s| s.starts_with('.')))
            })
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub policy: Policy,
    pub layers: Vec<String>,
    pub identity_required: bool,
}

impl Policy {
    pub fn extend(&mut self, additions: &PolicyRequirements) {
        self.required.extend(additions.required.iter().cloned());
        self.deny_on_failure
            .extend(additions.deny_on_failure.iter().cloned());
        self.required.sort();
        self.required.dedup();
        self.deny_on_failure.sort();
        self.deny_on_failure.dedup();
        if let Some(additions) = &additions.agent_escalation {
            self.agent_escalation
                .get_or_insert_with(|| AgentEscalation { when_any: vec![] })
                .merge(additions);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub revision: String,
    #[serde(default = "default_required")]
    pub required: Vec<String>,
    #[serde(default)]
    pub deny_on_failure: Vec<String>,
    #[serde(default)]
    pub trust_agent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_escalation: Option<AgentEscalation>,
}
fn default_required() -> Vec<String> {
    vec!["inventory".into()]
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            revision: "initial".into(),
            required: default_required(),
            deny_on_failure: vec![],
            trust_agent: false,
            agent_escalation: None,
        }
    }
}
impl Policy {
    pub fn agent_always_required(&self) -> bool {
        self.required.iter().any(|check| check == "agent")
    }

    pub fn escalation_check_names(&self) -> Vec<String> {
        let mut checks: Vec<_> = self
            .agent_escalation
            .iter()
            .flat_map(|rule| {
                rule.when_any
                    .iter()
                    .map(|condition| condition.check.clone())
            })
            .collect();
        checks.sort();
        checks.dedup();
        checks
    }

    /// Agent conclusions must describe the current generation of their ordinary inputs.
    /// Only legacy policies without conditional escalation may omit this engine-owned map.
    pub fn agent_inputs_match(
        &self,
        agent: &Evidence,
        subject: &str,
        configuration: &str,
        evidence: &[Evidence],
        now: DateTime<Utc>,
    ) -> bool {
        if agent.check != "agent"
            || agent.subject != subject
            || agent.configuration != configuration
        {
            return false;
        }
        let Some(inputs) = agent.details.get("packweir_inputs") else {
            return self.agent_escalation.is_none();
        };
        let Some(schema) = inputs.as_object() else {
            return false;
        };
        let Some(findings) = inputs
            .get("findings")
            .and_then(serde_json::Value::as_object)
        else {
            return false;
        };
        if schema.len() != 2
            || inputs.get("version").and_then(serde_json::Value::as_u64) != Some(1)
            || findings.len() > 1024
            || self
                .escalation_check_names()
                .iter()
                .any(|check| !findings.contains_key(check))
        {
            return false;
        }
        findings.iter().all(|(check, expected)| {
            let Some(expected) = expected.as_str() else {
                return false;
            };
            if check == "agent"
                || check.is_empty()
                || check.len() > 128
                || !check
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || expected.len() != 64
                || !expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return false;
            }
            let latest = latest_observed(subject, check, configuration, evidence);
            !latest.is_empty()
                && latest.iter().all(|input| {
                    input.applicable(subject, check, configuration, now)
                        && evidence_fingerprint(input) == expected
                })
        })
    }

    /// Derive escalation from upstream evidence, never from the agent's verdict or skip.
    /// Every condition needs a current input, even if another condition already matched.
    pub fn escalation_state(
        &self,
        subject: &str,
        configuration: &str,
        evidence: &[Evidence],
        now: DateTime<Utc>,
    ) -> EscalationState {
        let Some(rule) = &self.agent_escalation else {
            return EscalationState::NotTriggered;
        };
        let mut triggered = vec![];
        let mut unresolved = vec![];
        for condition in &rule.when_any {
            let inputs = latest_observed(subject, &condition.check, configuration, evidence);
            match inputs.first() {
                Some(e)
                    if inputs.iter().all(|input| {
                        input.applicable(subject, &condition.check, configuration, now)
                            && input.outcome != Outcome::Skipped
                            && input.outcome == e.outcome
                    }) =>
                {
                    if condition.outcomes.contains(&e.outcome) {
                        triggered.push(condition.check.clone());
                    }
                }
                _ => unresolved.push(condition.check.clone()),
            }
        }
        triggered.sort();
        triggered.dedup();
        unresolved.sort();
        unresolved.dedup();
        if !unresolved.is_empty() {
            EscalationState::Unresolved { checks: unresolved }
        } else if triggered.is_empty() {
            EscalationState::NotTriggered
        } else {
            EscalationState::Triggered { checks: triggered }
        }
    }

    pub fn fingerprint(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("serializable policy"))
    }
    pub fn evaluate(
        &self,
        subject: &str,
        configuration: &str,
        evidence: &[Evidence],
        now: DateTime<Utc>,
    ) -> Decision {
        let mut denied = vec![];
        let mut pending = vec![];
        let mut required = self.required.clone();
        match self.escalation_state(subject, configuration, evidence, now) {
            EscalationState::Triggered { .. } => required.push("agent".into()),
            EscalationState::Unresolved { checks } => pending.extend(
                checks
                    .into_iter()
                    .map(|check| format!("agent_escalation:{check}")),
            ),
            EscalationState::NotTriggered => {}
        }
        for check in required.iter().chain(self.deny_on_failure.iter()) {
            let is_required = required.contains(check);
            let latest = if check == "agent" {
                latest_observed(subject, check, configuration, evidence)
            } else {
                latest_applicable(subject, check, configuration, evidence, now)
            };
            if latest.iter().any(|e| {
                e.applicable(subject, check, configuration, now) && e.outcome == Outcome::Fail
            }) {
                denied.push(check.clone());
            } else if !latest.is_empty()
                && latest.iter().all(|e| {
                    e.applicable(subject, check, configuration, now) && e.outcome == Outcome::Pass
                })
            {
                if check == "agent"
                    && (!self.trust_agent
                        || latest.iter().any(|e| {
                            !agent_binding(&e.details)
                                || !self.agent_inputs_match(
                                    e,
                                    subject,
                                    configuration,
                                    evidence,
                                    now,
                                )
                        }))
                {
                    pending.push(check.clone());
                }
            } else if is_required {
                pending.push(check.clone());
            }
        }
        // Hard failures cannot be waived by an agent or by omitting a required check.
        for e in evidence.iter().filter(|e| {
            e.subject == subject
                && e.configuration == configuration
                && e.created_at <= now
                && e.expires_at > now
        }) {
            if ["integrity", "archive_safety", "required_signature"].contains(&e.check.as_str())
                && e.outcome == Outcome::Fail
            {
                denied.push(e.check.clone());
            }
        }
        denied.sort();
        denied.dedup();
        pending.sort();
        pending.dedup();
        if !denied.is_empty() {
            Decision::Denied(denied)
        } else if !pending.is_empty() {
            Decision::Pending(pending)
        } else {
            Decision::Approved
        }
    }
}
