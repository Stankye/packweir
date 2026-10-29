use super::{Execution, document_digest, matching_indices, source_matches};
use crate::{
    config::SourceBinding,
    model::{Outcome, sha256},
    scanner::{ReadOnlyInputs, ScannerOutput},
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(super) async fn run(
    execution: &mut Execution<'_>,
    bundle: &Value,
    builder_id: &str,
    sources: &[SourceBinding],
) -> Result<ScannerOutput> {
    let mut result = execution.result(
        Outcome::Inconclusive,
        "source_bound_provenance",
        "no verified provenance matched every expected source revision",
    );
    let Some(indices) = matching_indices(
        bundle,
        sources
            .iter()
            .map(|s| (s.repository.as_str(), s.origin.as_str())),
    ) else {
        return Ok(result);
    };
    let documents: Vec<_> = bundle
        .get("documents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|d| d["kind"] == "attestation")
        .collect();
    if documents.is_empty() || documents.len() > 8 {
        return Ok(result);
    }
    let mut inputs = ReadOnlyInputs::default();
    let mut verified = vec![];
    for index in indices {
        let expected = &sources[index];
        let mut matched = None;
        for (candidate, document) in documents.iter().enumerate() {
            let digest = document_digest(document)?;
            let path = execution
                .directory
                .join(format!("provenance-{candidate}.intoto.jsonl"));
            // A candidate can be reused for multiple aliases; create its snapshot once.
            if !path.exists() {
                let content = &document["document"];
                let bytes = if let Some(raw) = content.get("raw_base64") {
                    anyhow::ensure!(
                        content.as_object().is_some_and(|v| v.len() == 1),
                        "raw attestation wrapper must contain only raw_base64"
                    );
                    STANDARD.decode(
                        raw.as_str()
                            .ok_or_else(|| anyhow::anyhow!("invalid raw attestation"))?,
                    )?
                } else {
                    serde_json::to_vec(content)?
                };
                anyhow::ensure!(bytes.len() <= 8 * 1024 * 1024, "attestation exceeds limit");
                inputs.write(&path, &bytes)?;
            }
            let output = execution
                .execute(
                    vec![
                        "verify-artifact".into(),
                        format!("--provenance-path={}", path.display()).into(),
                        format!(
                            "--source-uri={}",
                            expected.source_uri.trim_start_matches("https://")
                        )
                        .into(),
                        format!("--builder-id={builder_id}").into(),
                        "--print-provenance".into(),
                        execution.directory.join("artifact").into_os_string(),
                    ],
                    &execution.environment(),
                )
                .await?;
            if !output.status.success() {
                continue;
            }
            let statement: Value = serde_json::from_slice(&output.stdout)?;
            if matches_expectation(&statement, &execution.job.subject, builder_id, expected) {
                matched = Some(
                    json!({"identity":{"repository":expected.repository,"origin":expected.origin},
                    "source_uri":expected.source_uri,"source_revision":expected.source_revision,
                    "attestation_digest":digest,"statement_digest":sha256(&serde_json::to_vec(&statement)?),"statement":statement}),
                );
                result.references.push(format!("sha256:{digest}"));
                break;
            }
        }
        let Some(statement) = matched else {
            return Ok(result);
        };
        verified.push(statement);
    }
    result.outcome = Outcome::Pass;
    result.details = json!({"verification_scope":"source_bound_provenance", "verified_subject":execution.job.subject,
        "trusted_identity":true,"signature_verified":true,"policy_matched":true,"builder_id":builder_id,
        "verified":verified,"program_digest":execution.scanner.program_sha256,"evidence_digest":execution.evidence_digest});
    Ok(result)
}

fn matches_expectation(
    statement: &Value,
    subject: &str,
    builder_id: &str,
    expected: &SourceBinding,
) -> bool {
    if ![
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1",
    ]
    .contains(&statement["_type"].as_str().unwrap_or(""))
        || !statement["subject"].as_array().is_some_and(|s| {
            s.iter()
                .any(|s| s["digest"]["sha256"].as_str() == Some(subject))
        })
    {
        return false;
    }
    let predicate = &statement["predicate"];
    match statement["predicateType"].as_str() {
        Some("https://slsa.dev/provenance/v0.2") => {
            let source = &predicate["invocation"]["configSource"];
            predicate["builder"]["id"].as_str() == Some(builder_id)
                && source["uri"]
                    .as_str()
                    .is_some_and(|u| source_matches(u, &expected.source_uri))
                && source["digest"]["sha1"].as_str() == Some(expected.source_revision.as_str())
        }
        Some("https://slsa.dev/provenance/v1") => {
            let sources: Vec<_> = predicate["buildDefinition"]["resolvedDependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| {
                    s["uri"]
                        .as_str()
                        .is_some_and(|u| source_matches(u, &expected.source_uri))
                })
                .collect();
            predicate["runDetails"]["builder"]["id"].as_str() == Some(builder_id)
                && sources.len() == 1
                && (sources[0]["digest"]["gitCommit"]
                    .as_str()
                    .or_else(|| sources[0]["digest"]["sha1"].as_str()))
                    == Some(expected.source_revision.as_str())
        }
        _ => false,
    }
}
