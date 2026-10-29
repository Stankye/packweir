pub use crate::process::read_bounded;
use crate::{
    config::{CommandScanner, Config},
    inventory,
    model::{Evidence, Outcome, agent_binding},
    storage::BlobStore,
    store::{Job, Store},
};
use anyhow::{Result, ensure};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerOutput {
    pub outcome: Outcome,
    pub details: serde_json::Value,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
}

#[derive(Default)]
pub(crate) struct ReadOnlyInputs {
    #[cfg(windows)]
    permissions: Vec<(std::path::PathBuf, std::fs::Permissions)>,
}
impl ReadOnlyInputs {
    pub(crate) fn write(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        std::fs::write(path, bytes)?;
        let mut permissions = std::fs::metadata(path)?.permissions();
        #[cfg(windows)]
        self.permissions.push((path.into(), permissions.clone()));
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)?;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ReadOnlyInputs {
    fn drop(&mut self) {
        for (path, permissions) in &self.permissions {
            let _ = std::fs::set_permissions(path, permissions.clone());
        }
    }
}

/// Run one configured adapter without a database. The caller supplies an attributable evidence bundle.
pub async fn run(
    scanner: &CommandScanner,
    job: &Job,
    bytes: &[u8],
    bundle: &serde_json::Value,
) -> Result<ScannerOutput> {
    scanner.validate()?;
    ensure!(
        crate::model::sha256(bytes) == job.subject,
        "scanner subject does not match artifact bytes"
    );
    if let Some(expected) = &scanner.program_sha256 {
        crate::process::verify_executable(&scanner.program, expected).await?;
    }
    let directory = tempfile::tempdir()?;
    let mut inputs = ReadOnlyInputs::default();
    let path = directory.path().join("artifact");
    inputs.write(&path, bytes)?;
    let mut resources = BTreeMap::new();
    let mut total = 0;
    for (name, resource) in &scanner.resources {
        let file = tokio::fs::File::open(&resource.path).await?;
        ensure!(
            file.metadata().await?.is_file(),
            "scanner resource must be a file"
        );
        let content = read_bounded(file, 8 * 1024 * 1024).await?;
        total += content.len();
        ensure!(
            total <= 32 * 1024 * 1024,
            "scanner resources exceed combined limit"
        );
        ensure!(
            crate::model::sha256(&content) == resource.sha256,
            "scanner resource digest mismatch"
        );
        let resource_path = directory.path().join(format!("resource-{name}"));
        inputs.write(&resource_path, &content)?;
        resources.insert(
            name,
            serde_json::json!({"path":resource_path,"sha256":resource.sha256}),
        );
    }
    let serialized_bundle = serde_json::to_vec(bundle)?;
    ensure!(
        serialized_bundle.len() <= 8 * 1024 * 1024,
        "evidence bundle exceeds limit"
    );
    let bundle_digest = crate::model::sha256(&serialized_bundle);
    let bundle_path = directory.path().join("evidence.json");
    inputs.write(&bundle_path, &serialized_bundle)?;
    if matches!(
        scanner.driver,
        crate::config::ScannerDriver::Sigstore { .. }
    ) {
        return crate::sigstore::verify(scanner, job, bundle, directory.path(), &bundle_digest)
            .await;
    }
    if !matches!(scanner.driver, crate::config::ScannerDriver::Command) {
        return crate::drivers::run(scanner, job, bundle, directory.path(), &bundle_digest).await;
    }
    let mut input = serde_json::json!({"protocol_version":1,"subject":job.subject,
        "configuration":job.configuration,"filename":job.filename,"artifact_path":path,
        "evidence_path":bundle_path,"evidence_digest":bundle_digest,"context_revision":job.context_revision});
    if !resources.is_empty() {
        input["resources"] = serde_json::to_value(resources)?;
    }
    let output = crate::process::execute(
        &scanner.program,
        &scanner.args.iter().map(Into::into).collect::<Vec<_>>(),
        &scanner.environment,
        directory.path(),
        &serde_json::to_vec(&input)?,
        std::time::Duration::from_secs(scanner.timeout_seconds),
    )
    .await?;
    ensure!(output.status.success(), "scanner returned failure");
    let output: ScannerOutput = serde_json::from_slice(&output.stdout)?;
    if let Some(declared) = output
        .details
        .get("evidence_digest")
        .and_then(|v| v.as_str())
    {
        ensure!(
            declared == bundle_digest,
            "scanner used a different evidence bundle"
        );
    }
    Ok(output)
}

fn evidence(
    config: &Config,
    job: &Job,
    check: &str,
    version: &str,
    outcome: Outcome,
    details: serde_json::Value,
) -> Evidence {
    let now = Utc::now();
    Evidence {
        subject: job.subject.clone(),
        check: check.into(),
        tool_version: version.into(),
        configuration: job.configuration.clone(),
        outcome,
        created_at: now,
        expires_at: now + Duration::seconds(config.evidence_ttl_seconds),
        details,
        references: vec![],
    }
}

pub async fn analyze(config: &Config, store: &Store, blobs: &BlobStore, job: &Job) -> Result<()> {
    let bytes = blobs.read(&job.subject).await?;
    let name = job.filename.clone();
    let inspected = tokio::task::spawn_blocking(move || {
        inventory::inspect(&name, &bytes, inventory::Limits::default())
    })
    .await?;
    let mut findings = vec![];
    match inspected {
        Ok(inventory) => {
            for (kind, document) in [
                ("inventory", serde_json::to_value(&inventory)?),
                ("cyclonedx", inventory::cyclonedx(&inventory)),
                ("spdx", inventory::spdx(&inventory)),
            ] {
                let digest = blobs.put(serde_json::to_vec(&document)?).await?;
                store
                    .document(&job.subject, kind, "artifact_observed", &digest)
                    .await?;
            }
            findings.push(evidence(
                config,
                job,
                "inventory",
                env!("CARGO_PKG_VERSION"),
                Outcome::Pass,
                serde_json::json!({"files":inventory.files.len(),"coverage":inventory.coverage}),
            ));
            findings.push(evidence(
                config,
                job,
                "archive_safety",
                env!("CARGO_PKG_VERSION"),
                Outcome::Pass,
                serde_json::json!({"bounded":true}),
            ));
        }
        Err(_) => {
            findings.push(evidence(
                config,
                job,
                "inventory",
                env!("CARGO_PKG_VERSION"),
                Outcome::Fail,
                serde_json::json!({"reason":"inventory incomplete or archive rejected"}),
            ));
            findings.push(evidence(
                config,
                job,
                "archive_safety",
                env!("CARGO_PKG_VERSION"),
                Outcome::Fail,
                serde_json::json!({"reason":"archive rejected"}),
            ));
        }
    }
    // Do not invoke deeper tools on an archive rejected by the bounded inspector.
    if !findings.iter().any(|e| e.outcome == Outcome::Fail) {
        let bytes = blobs.read(&job.subject).await?;
        let mut documents = Vec::new();
        for mut document in store.documents(&job.subject).await? {
            let digest = document["blob_digest"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("document digest missing"))?;
            let content: serde_json::Value = serde_json::from_slice(&blobs.read(digest).await?)?;
            document["document"] = content;
            documents.push(document);
        }
        let bundle = serde_json::json!({"identities":store.identities(&job.subject).await?,"documents":documents});
        for (name, scanner) in &config.scanners {
            let mut e = match run(scanner, job, &bytes, &bundle).await {
                Ok(output) => {
                    let outcome = if name == "agent" && !agent_binding(&output.details) {
                        Outcome::Inconclusive
                    } else {
                        output.outcome
                    };
                    let mut e =
                        evidence(config, job, name, &scanner.version, outcome, output.details);
                    if let Some(valid_until) = output.valid_until {
                        e.expires_at = e.expires_at.min(valid_until);
                        if valid_until <= Utc::now() {
                            e.outcome = Outcome::Inconclusive;
                        }
                    }
                    e.references = output.references;
                    e
                }
                Err(_) => evidence(
                    config,
                    job,
                    name,
                    &scanner.version,
                    Outcome::Error,
                    serde_json::json!({"reason":"scanner failed or timed out"}),
                ),
            };
            // Provenance adapters must explicitly provide the artifact subject and trust checks.
            if ["provenance", "required_signature"].contains(&name.as_str())
                && e.outcome == Outcome::Pass
            {
                let bound = e.details.get("verified_subject").and_then(|v| v.as_str())
                    == Some(job.subject.as_str());
                let trusted =
                    e.details.get("trusted_identity").and_then(|v| v.as_bool()) == Some(true);
                let verified = e
                    .details
                    .get("signature_verified")
                    .and_then(|v| v.as_bool())
                    == Some(true);
                let expected =
                    e.details.get("policy_matched").and_then(|v| v.as_bool()) == Some(true);
                if !(bound && trusted && verified && expected) {
                    e.outcome = Outcome::Inconclusive;
                }
            }
            findings.push(e);
        }
    }
    store.complete(job, &findings).await?;
    store
        .audit(
            "analysis_completed",
            &job.subject,
            serde_json::json!({"job":job.id,"checks":findings.len()}),
        )
        .await?;
    Ok(())
}

pub async fn worker(config: Arc<Config>, store: Store, blobs: BlobStore, once: bool) -> Result<()> {
    let fingerprint = config.fingerprint();
    let seconds = config
        .scanners
        .values()
        .map(|s| s.timeout_seconds)
        .fold(0u64, u64::saturating_add)
        .saturating_add(300)
        .min(i32::MAX as u64) as i32;
    loop {
        match store.lease(&fingerprint, seconds).await? {
            Some(job) => {
                if analyze(&config, &store, &blobs, &job).await.is_err() {
                    tracing::warn!(job=%job.id,"analysis failed; job scheduled for bounded retry");
                    store.fail(&job).await?;
                }
            }
            None if once => break,
            None => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
        if once {
            break;
        }
    }
    Ok(())
}
