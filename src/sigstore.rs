//! Sigstore bundle verification delegated to a pinned Cosign executable.
use crate::{
    config::{CommandScanner, ScannerDriver},
    model::{Outcome, sha256},
    scanner::{ReadOnlyInputs, ScannerOutput},
    store::Job,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) async fn verify(
    scanner: &CommandScanner,
    job: &Job,
    bundle: &Value,
    directory: &Path,
    evidence_digest: &str,
) -> Result<ScannerOutput> {
    let ScannerDriver::Sigstore {
        certificate_identity,
        certificate_oidc_issuer,
        trusted_root,
    } = &scanner.driver
    else {
        anyhow::bail!("Sigstore driver required");
    };
    let candidates: Vec<_> = bundle
        .get("documents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|d| d["kind"] == "sigstore_bundle")
        .collect();
    let mut result = ScannerOutput {
        outcome: Outcome::Inconclusive,
        details: json!({"reason":"no acceptable Sigstore blob signature verified", "evidence_digest":evidence_digest,
            "verification_scope":"sigstore_blob_signature", "candidate_count":candidates.len()}),
        references: vec![],
        valid_until: None,
    };
    if candidates.len() > 8 {
        result.details["reason"] = json!("Sigstore bundle candidate limit exceeded");
        return Ok(result);
    }
    let deadline = Instant::now() + Duration::from_secs(scanner.timeout_seconds);
    let mut inputs = ReadOnlyInputs::default();
    let mut attempted = vec![];
    for (index, document) in candidates.iter().enumerate() {
        let Some(signature) = document.get("document") else {
            continue;
        };
        // Deliberately support blob signatures only, never interpret a DSSE statement as provenance.
        if !matches!(
            signature["mediaType"].as_str(),
            Some(
                "application/vnd.dev.sigstore.bundle.v0.3+json"
                    | "application/vnd.dev.sigstore.bundle+json;version=0.3"
            )
        ) || !signature["messageSignature"].is_object()
            || signature.get("dsseEnvelope").is_some()
            || signature["messageSignature"]["messageDigest"]["algorithm"] != "SHA2_256"
        {
            continue;
        }
        let digest = signature["messageSignature"]["messageDigest"]["digest"]
            .as_str()
            .and_then(|d| STANDARD.decode(d).ok())
            .map(hex::encode);
        if digest.as_deref() != Some(job.subject.as_str()) {
            continue;
        }
        let material = &signature["verificationMaterial"];
        if !material["certificate"]["rawBytes"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
            || !material["tlogEntries"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|e| e["inclusionProof"].is_object()))
        {
            continue;
        }
        let bytes = serde_json::to_vec(signature)?;
        let digest = sha256(&bytes);
        if let Some(claimed) = document.get("blob_digest") {
            ensure!(
                claimed.as_str() == Some(digest.as_str()),
                "Sigstore document digest mismatch"
            );
        }
        let path = directory.join(format!("sigstore-{index}.json"));
        inputs.write(&path, &bytes)?;
        let args: Vec<OsString> = vec![
            "verify-blob".into(),
            format!("--bundle={}", path.display()).into(),
            format!(
                "--trusted-root={}",
                directory.join(format!("resource-{trusted_root}")).display()
            )
            .into(),
            format!("--certificate-identity={certificate_identity}").into(),
            format!("--certificate-oidc-issuer={certificate_oidc_issuer}").into(),
            directory.join("artifact").into_os_string(),
        ];
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("Sigstore verification timed out"))?;
        let output = crate::process::execute(
            &scanner.program,
            &args,
            &scanner.environment,
            directory,
            &[],
            remaining,
        )
        .await?;
        attempted.push(digest.clone());
        if output.status.success() {
            return Ok(ScannerOutput {
                outcome: Outcome::Pass,
                details: json!({"verified_subject":job.subject, "trusted_identity":true, "signature_verified":true,
                    "policy_matched":true, "transparency_verified":true, "verification_scope":"sigstore_blob_signature",
                    "certificate_identity":certificate_identity, "certificate_oidc_issuer":certificate_oidc_issuer,
                    "bundle_digest":digest, "trusted_root_digest":scanner.resources[trusted_root].sha256,
                    "program_digest":scanner.program_sha256, "evidence_digest":evidence_digest}),
                references: vec![format!("sha256:{digest}")],
                valid_until: None,
            });
        }
    }
    // Nonzero verifier exits can mean invalid signatures OR an operational problem. Neither approves delivery.
    result.details["attempted_bundles"] = json!(attempted);
    Ok(result)
}
