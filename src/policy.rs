use crate::model::{Decision, Evidence, Outcome, agent_binding, sha256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
