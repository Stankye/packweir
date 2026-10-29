use super::{Execution, matching_indices};
use crate::{
    config::{PinnedResource, SourceBinding},
    model::Outcome,
    scanner::ScannerOutput,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) async fn run(
    execution: &mut Execution<'_>,
    bundle: &Value,
    policy: &str,
    configuration: &str,
    required: &[String],
    sources: &[SourceBinding],
    plugins: &BTreeMap<String, PinnedResource>,
) -> Result<ScannerOutput> {
    let mut result = execution.result(
        Outcome::Inconclusive,
        "source_posture",
        "every artifact alias needs an operator-supplied source mapping",
    );
    let Some(indices) = matching_indices(
        bundle,
        sources
            .iter()
            .map(|s| (s.repository.as_str(), s.origin.as_str())),
    ) else {
        return Ok(result);
    };
    for plugin in plugins.values() {
        crate::process::verify_executable(&plugin.path, &plugin.sha256).await?;
    }
    let mut reports = vec![];
    let mut outcome = Outcome::Pass;
    for index in indices {
        let expected = &sources[index];
        let output = execution
            .execute(
                vec![
                    "check".into(),
                    "--target=repo".into(),
                    "--format=debug".into(),
                    "--color=never".into(),
                    "--verbosity=quiet".into(),
                    format!("--policy={}", execution.resource(policy).display()).into(),
                    format!("--exec={}", execution.resource(configuration).display()).into(),
                    format!(
                        "--cache={}",
                        execution.directory.join("hipcheck-cache").display()
                    )
                    .into(),
                    format!("--ref={}", expected.source_revision).into(),
                    expected.source_uri.clone().into(),
                ],
                &execution.environment(),
            )
            .await?;
        if !matches!(output.status.code(), Some(0 | 1)) {
            result.outcome = Outcome::Error;
            result.details["reason"] = json!("Hipcheck execution failed");
            return Ok(result);
        }
        let report: Value = serde_json::from_slice(&output.stdout)?;
        let parts: Vec<_> = expected
            .source_uri
            .trim_start_matches("https://github.com/")
            .split('/')
            .collect();
        if report["repo_head"].as_str() != Some(expected.source_revision.as_str())
            || report["repo_owner"].as_str() != Some(parts[0])
            || report["repo_name"].as_str() != Some(parts[1])
        {
            result.details["reason"] =
                json!("Hipcheck report source identity/revision differs from the expected source");
            result.details["report"] = report;
            return Ok(result);
        }
        let mut seen = BTreeSet::new();
        let mut passing = BTreeSet::new();
        let mut failing = BTreeSet::new();
        let mut errors = false;
        for (key, passed) in [
            ("passing", Some(true)),
            ("failing", Some(false)),
            ("errored", None),
        ] {
            let analyses = report
                .get(key)
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("Hipcheck analysis list missing"))?;
            for analysis in analyses {
                let name = analysis
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("Hipcheck analysis name missing"))?;
                ensure!(seen.insert(name), "duplicate Hipcheck analysis");
                match passed {
                    Some(value) => {
                        ensure!(
                            analysis["passed"].as_bool() == Some(value),
                            "Hipcheck analysis state disagrees with its report list"
                        );
                        if value {
                            passing.insert(name);
                        } else {
                            failing.insert(name);
                        }
                    }
                    None => errors = true,
                }
            }
        }
        let recommendation = report["recommendation"]["kind"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Hipcheck recommendation missing"))?;
        ensure!(
            ["Pass", "Investigate"].contains(&recommendation),
            "unknown Hipcheck recommendation"
        );
        let current = if required.iter().any(|r| failing.contains(r.as_str())) {
            Outcome::Fail
        } else if errors
            || required.iter().any(|r| !passing.contains(r.as_str()))
            || recommendation == "Investigate"
            || !output.status.success()
        {
            Outcome::Inconclusive
        } else {
            Outcome::Pass
        };
        if current == Outcome::Fail {
            outcome = Outcome::Fail;
        } else if current != Outcome::Pass && outcome != Outcome::Fail {
            outcome = Outcome::Inconclusive;
        }
        reports.push(json!({"identity":{"repository":expected.repository,"origin":expected.origin},
            "source_uri":expected.source_uri,"source_revision":expected.source_revision,"report":report}));
    }
    result.outcome = outcome;
    result.details = json!({"verification_scope":"source_posture", "evidence_digest":execution.evidence_digest,
        "program_digest":execution.scanner.program_sha256, "policy_digest":execution.scanner.resources[policy].sha256,
        "execution_digest":execution.scanner.resources[configuration].sha256,"required_analyses":required,"reports":reports,
        "plugins":plugins,"resources":execution.scanner.resources,
        "reason":match outcome { Outcome::Pass=>"all explicitly required analyses passed for every mapped source", Outcome::Fail=>"a required source analysis failed", _=>"source investigation or missing/errored analyses require escalation" }});
    Ok(result)
}
