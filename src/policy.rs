use crate::model::{Decision, Evidence, Outcome, agent_binding, sha256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequirements {
    pub revision: String,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub deny_on_failure: Vec<String>,
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
        }
    }
}
impl Policy {
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
        for check in self.required.iter().chain(self.deny_on_failure.iter()) {
            let required = self.required.contains(check);
            let latest = evidence
                .iter()
                .filter(|e| e.applicable(subject, check, configuration, now))
                .max_by_key(|e| e.created_at);
            match latest {
                Some(e) if e.outcome == Outcome::Fail => denied.push(check.clone()),
                Some(e) if e.outcome == Outcome::Pass => {
                    if check == "agent" && (!self.trust_agent || !agent_binding(&e.details)) {
                        pending.push(check.clone());
                    }
                }
                _ if required => pending.push(check.clone()),
                _ => {}
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
