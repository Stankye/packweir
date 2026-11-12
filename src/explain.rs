use crate::{
    identity::DeliveryScope,
    model::{Decision, Evidence, Outcome, agent_binding},
    policy::EffectivePolicy,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckExplanation {
    pub check: String,
    pub required: bool,
    pub deny_on_failure: bool,
    pub status: String,
    pub reason: String,
    pub next_action: String,
    pub age_seconds: Option<i64>,
    pub evidence: Option<Evidence>,
    pub provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScopeExplanation {
    pub scope: DeliveryScope,
    pub configuration: String,
    pub policy: EffectivePolicy,
    pub decision: Decision,
    pub checks: Vec<CheckExplanation>,
    pub job: Option<crate::store::JobStatus>,
    #[serde(default)]
    pub agent_escalation: Option<crate::policy::EscalationState>,
}

pub fn scope(
    digest: &str,
    scope: DeliveryScope,
    configuration: String,
    policy: EffectivePolicy,
    evidence: &[Evidence],
    now: DateTime<Utc>,
) -> ScopeExplanation {
    let decision = policy
        .policy
        .evaluate(digest, &configuration, evidence, now);
    let agent_escalation = policy.policy.agent_escalation.as_ref().map(|_| {
        policy
            .policy
            .escalation_state(digest, &configuration, evidence, now)
    });
    let conditional_agent_required = matches!(
        agent_escalation,
        Some(crate::policy::EscalationState::Triggered { .. })
    );
    let escalation_inputs = policy.policy.escalation_check_names();
    let names: BTreeSet<_> = policy
        .policy
        .required
        .iter()
        .chain(&policy.policy.deny_on_failure)
        .cloned()
        .chain(evidence.iter().map(|e| e.check.clone()))
        .chain(escalation_inputs.iter().cloned())
        .chain(agent_escalation.as_ref().map(|_| "agent".to_owned()))
        .collect();
    let checks = names.into_iter().map(|check| {
        let matching: Vec<_> = evidence.iter().filter(|e|e.subject==digest && e.configuration==configuration && e.check==check).collect();
        let hard = ["integrity","archive_safety","required_signature"].contains(&check.as_str());
        let latest = if check == "agent" || escalation_inputs.contains(&check) {
            crate::policy::latest_observed(digest, &check, &configuration, evidence)
        } else {
            crate::policy::latest_applicable(digest, &check, &configuration, evidence, now)
        };
        let hard_failure = hard.then(||matching.iter().copied().filter(|e|e.applicable(digest,&check,&configuration,now)&&e.outcome==Outcome::Fail).max_by_key(|e|e.created_at)).flatten();
        let latest_failure = latest.iter().copied().find(|e|e.outcome==Outcome::Fail&&e.applicable(digest,&check,&configuration,now));
        let conflicting = latest.first().is_some_and(|first|latest.iter().any(|e|e.outcome!=first.outcome));
        let invalid_latest = latest.iter().any(|e|!e.applicable(digest,&check,&configuration,now));
        let chosen = hard_failure.or(latest_failure).or_else(||latest.first().copied())
            .or_else(||matching.into_iter().max_by_key(|e|e.created_at));
        let (status,reason,action) = match chosen {
            None => ("missing","No evidence exists in the current delivery and document context.","Request this artifact or run prefetch to queue analysis; configure the check if unavailable."),
            Some(e) if e.created_at>now => ("not_yet_valid","Evidence is dated in the future.","Check clock synchronization and rescan."),
            Some(e) if e.expires_at<=now => ("expired","Evidence has expired.","Refresh advisory/trust inputs if applicable and request a rescan."),
            Some(_) if (conflicting||invalid_latest) && hard_failure.is_none() && latest_failure.is_none() => ("inconclusive","Latest evidence records have conflicting outcomes or validity at the same timestamp.","Inspect the conflicting reports and request fresh analysis; record order cannot establish approval."),
            Some(e) if check=="agent" && e.outcome==Outcome::Pass && (!policy.policy.trust_agent || latest.iter().any(|e| !agent_binding(&e.details) || !policy.policy.agent_inputs_match(e,digest,&configuration,evidence,now))) =>
                ("inconclusive","Agent trust, attributable bindings, or current finding dependencies are missing or stale.","Refresh upstream findings and investigate their exact bundle with an authorized adapter."),
            Some(e) => match e.outcome {
                Outcome::Pass => ("pass","Applicable evidence passed.","None until the policy, inputs, or evidence validity changes."),
                Outcome::Fail => ("fail","Applicable evidence reported a failure.","Inspect the finding and remediate or select an acceptable release; hard failures cannot be overridden."),
                Outcome::Error => ("error","The scanner failed or timed out.","Check worker diagnostics, executable/resource pins, and scanner availability; then rescan."),
                Outcome::Unsupported => ("unsupported","The check does not support this input.","Configure a qualified check that covers this artifact."),
                Outcome::Skipped => ("skipped","This check did not execute; this is not a passing verdict.","Inspect the recorded skip reason and escalation inputs; a required check still needs applicable passing evidence."),
                Outcome::Inconclusive if check=="package_identity" => ("inconclusive","Identity is unavailable, ambiguous, or missing the required discovery binding.","Fetch native registry metadata (npm packument or PyPI project index), then prefetch/rescan; unsupported or conflicting claims remain pending."),
                Outcome::Inconclusive => ("inconclusive","Available evidence does not establish the required result.","Inspect coverage and supply missing mappings, documents, or verification material; then rescan."),
            }
        };
        CheckExplanation {required:policy.policy.required.contains(&check)||(check=="agent"&&conditional_agent_required),deny_on_failure:policy.policy.deny_on_failure.contains(&check),
            check,status:status.into(),reason:reason.into(),next_action:action.into(),age_seconds:chosen.map(|e|(now-e.created_at).num_seconds()),evidence:chosen.cloned(),provider:"unknown".into()}
    }).collect();
    ScopeExplanation {
        scope,
        configuration,
        policy,
        decision,
        checks,
        job: None,
        agent_escalation,
    }
}

pub fn aggregate(decisions: impl Iterator<Item = Decision>) -> Decision {
    let mut denied = BTreeSet::new();
    let mut pending = BTreeSet::new();
    let mut count = 0;
    for decision in decisions {
        count += 1;
        match decision {
            Decision::Denied(reasons) => denied.extend(reasons),
            Decision::Pending(reasons) => pending.extend(reasons),
            Decision::Approved => {}
        }
    }
    if !denied.is_empty() {
        Decision::Denied(denied.into_iter().collect())
    } else if !pending.is_empty() {
        Decision::Pending(pending.into_iter().collect())
    } else if count == 0 {
        Decision::Pending(vec!["artifact_not_registered".into()])
    } else {
        Decision::Approved
    }
}

pub fn render(digest: &str, scopes: &[ScopeExplanation]) -> String {
    let mut text = format!("Artifact SHA-256: {digest}\n");
    for entry in scopes {
        let package = entry
            .scope
            .package
            .as_ref()
            .map(|p| p.purl.as_str())
            .unwrap_or("unidentified package");
        text.push_str(&format!("\nRepository: {}\nPackage: {package}\nOrigin: {}\nDecision: {:?}\nPolicy: {}\nConfiguration: {}\n",
            entry.scope.repository,entry.scope.origin,entry.decision,entry.policy.layers.join(" -> "),entry.configuration));
        if let Some(job) = &entry.job {
            text.push_str(&format!("Job: {}; attempts: {}\n", job.state, job.attempts));
        }
        if let Some(escalation) = &entry.agent_escalation {
            match escalation {
                crate::policy::EscalationState::Triggered { checks } => text.push_str(&format!(
                    "Agent escalation: required by {}\n",
                    checks.join(", ")
                )),
                crate::policy::EscalationState::NotTriggered => {
                    text.push_str("Agent escalation: conditions did not trigger investigation\n")
                }
                crate::policy::EscalationState::Unresolved { checks } => text.push_str(&format!(
                    "Agent escalation: waiting for current evidence from {}\n",
                    checks.join(", ")
                )),
            }
        }
        for check in &entry.checks {
            let role = if check.required {
                "required"
            } else if check.deny_on_failure
                || ["integrity", "archive_safety", "required_signature"]
                    .contains(&check.check.as_str())
            {
                "blocks on failure"
            } else {
                "informational"
            };
            text.push_str(&format!(
                "  {}: {} ({role})\n    {}\n    Next: {}\n",
                check.check, check.status, check.reason, check.next_action
            ));
            if let Some(e) = &check.evidence {
                text.push_str(&format!(
                    "    Tool: {}; age: {}s; expires: {}\n",
                    e.tool_version,
                    check.age_seconds.unwrap_or(0),
                    e.expires_at
                ));
            }
        }
    }
    // Scanner and registry strings are untrusted terminal data.
    text.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
