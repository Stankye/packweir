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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

async fn scan_evidence(
    config: &Config,
    job: &Job,
    name: &str,
    scanner: &CommandScanner,
    bytes: &[u8],
    bundle: &serde_json::Value,
) -> Evidence {
    let mut result = match run(scanner, job, bytes, bundle).await {
        Ok(output) => {
            let outcome = if name == "agent" && !agent_binding(&output.details) {
                Outcome::Inconclusive
            } else {
                output.outcome
            };
            let mut result = evidence(config, job, name, &scanner.version, outcome, output.details);
            if let Some(valid_until) = output.valid_until {
                result.expires_at = result.expires_at.min(valid_until);
                if valid_until <= Utc::now() {
                    result.outcome = Outcome::Inconclusive;
                }
            }
            result.references = output.references;
            result
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
    if ["provenance", "required_signature"].contains(&name) && result.outcome == Outcome::Pass {
        let details = &result.details;
        let bound =
            details.get("verified_subject").and_then(|v| v.as_str()) == Some(job.subject.as_str());
        let trusted = details.get("trusted_identity").and_then(|v| v.as_bool()) == Some(true);
        let verified = details.get("signature_verified").and_then(|v| v.as_bool()) == Some(true);
        let matched = details.get("policy_matched").and_then(|v| v.as_bool()) == Some(true);
        if !(bound && trusted && verified && matched) {
            result.outcome = Outcome::Inconclusive;
        }
    }
    result
}

fn skipped_agent(
    config: &Config,
    job: &Job,
    reason: &str,
    state: &crate::policy::EscalationState,
) -> Evidence {
    evidence(
        config,
        job,
        "agent",
        env!("CARGO_PKG_VERSION"),
        Outcome::Skipped,
        serde_json::json!({"engine_generated":true,"reason":reason,"escalation":state}),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisCheckpoint {
    version: u32,
    subject: String,
    configuration: String,
    context_revision: i64,
    findings: Vec<Evidence>,
    bundle: serde_json::Value,
}

fn checkpoint_current(checkpoint: &AnalysisCheckpoint, job: &Job) -> Result<bool> {
    ensure!(
        checkpoint.version == 1
            && checkpoint.subject == job.subject
            && checkpoint.configuration == job.configuration
            && checkpoint.context_revision == job.context_revision,
        "ordinary analysis checkpoint binding mismatch"
    );
    ensure!(
        checkpoint.findings.len() <= 64 && checkpoint.bundle.is_object(),
        "invalid ordinary analysis checkpoint"
    );
    let checks: std::collections::BTreeSet<_> = checkpoint
        .findings
        .iter()
        .map(|finding| finding.check.as_str())
        .collect();
    ensure!(
        checks.len() == checkpoint.findings.len()
            && ["inventory", "archive_safety"].iter().all(|name| checkpoint
                .findings
                .iter()
                .any(|finding| finding.check == *name && finding.outcome == Outcome::Pass)),
        "ordinary checkpoint is incomplete or lacks bounded inspection"
    );
    let now = Utc::now();
    Ok(checkpoint.findings.iter().all(|finding| {
        finding.subject == job.subject
            && finding.configuration == job.configuration
            && finding.created_at <= now
            && finding.expires_at > now
    }))
}

pub async fn analyze(config: &Config, store: &Store, blobs: &BlobStore, job: &Job) -> Result<()> {
    let mut derived_outputs = Vec::new();
    let scope = store.job_scope(job.id).await?;
    if let Some(scope) = &scope {
        ensure!(
            config.delivery_fingerprint(scope)? == job.configuration,
            "job delivery configuration changed"
        );
        let artifact = store
            .artifact(&scope.repository, &scope.origin)
            .await?
            .ok_or_else(|| anyhow::anyhow!("artifact identity no longer registered"))?;
        ensure!(
            artifact.digest == job.subject && artifact.scope() == *scope,
            "job artifact identity changed"
        );
    } else {
        ensure!(
            job.configuration == config.fingerprint(),
            "legacy job configuration changed"
        );
    }
    let policy = match &scope {
        Some(scope) => config.effective_policy(scope)?.policy,
        None => config.policy.clone(),
    };
    let checkpoint = if config.remote_scanners.is_empty() {
        None
    } else {
        let saved = crate::remote_analysis::checkpoint(store, job).await?;
        let saved: Option<AnalysisCheckpoint> = saved.map(serde_json::from_value).transpose()?;
        saved
    };
    let resumed = checkpoint
        .as_ref()
        .map(|saved| checkpoint_current(saved, job))
        .transpose()?
        .unwrap_or(false);
    let (mut findings, mut saved_bundle) = match checkpoint {
        Some(saved) => (
            if resumed { saved.findings } else { Vec::new() },
            Some(saved.bundle),
        ),
        None => (Vec::new(), None),
    };
    if !resumed {
        let bytes = blobs.read(&job.subject).await?;
        let name = job.filename.clone();
        let inspected = tokio::task::spawn_blocking(move || {
            inventory::inspect(&name, &bytes, inventory::Limits::default())
        })
        .await?;
        if let Some(scope) = &scope {
            findings.push(evidence(
                config,
                job,
                "package_identity",
                env!("CARGO_PKG_VERSION"),
                if config.identity_sufficient(scope)? {
                    Outcome::Pass
                } else {
                    Outcome::Inconclusive
                },
                serde_json::json!({"package":scope.package,"trusted_source_established":false}),
            ));
        }
        match inspected {
            Ok(inventory) => {
                // Keep the original immutable bundle through same-context retries
                // and finding refreshes. SBOM UUID/time fields are not stable IDs.
                if saved_bundle.is_none() {
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
    }
    // Do not invoke deeper tools on an archive rejected by the bounded inspector.
    if !findings.iter().any(|e| {
        e.outcome == Outcome::Fail && ["inventory", "archive_safety"].contains(&e.check.as_str())
    }) {
        let bytes: Arc<[u8]> = blobs.read(&job.subject).await?.into();
        let bundle = if let Some(bundle) = saved_bundle.take() {
            bundle
        } else {
            let mut documents = Vec::new();
            let mut document_bytes = 0usize;
            for mut document in store.documents(&job.subject).await? {
                let digest = document["blob_digest"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("document digest missing"))?;
                let raw = blobs.read_bounded(digest, 8 * 1024 * 1024).await?;
                document_bytes = document_bytes
                    .checked_add(raw.len())
                    .ok_or_else(|| anyhow::anyhow!("scanner document size overflow"))?;
                ensure!(
                    document_bytes <= 8 * 1024 * 1024,
                    "scanner documents exceed bundle limit"
                );
                let content: serde_json::Value = serde_json::from_slice(&raw)?;
                document["document"] = content;
                documents.push(document);
            }
            let identities = if let Some(scope) = &scope {
                vec![serde_json::to_value(scope)?]
            } else {
                store.identities(&job.subject).await?
            };
            serde_json::json!({"identities":identities,"documents":documents})
        };
        if !resumed {
            for (name, scanner) in config
                .scanners
                .iter()
                .filter(|(name, _)| name.as_str() != "agent")
            {
                findings.push(scan_evidence(config, job, name, scanner, &bytes, &bundle).await);
            }
            if !config.remote_scanners.is_empty() {
                let checkpoint = AnalysisCheckpoint {
                    version: 1,
                    subject: job.subject.clone(),
                    configuration: job.configuration.clone(),
                    context_revision: job.context_revision,
                    findings: findings.clone(),
                    bundle: bundle.clone(),
                };
                crate::remote_analysis::save_checkpoint(
                    store,
                    job,
                    &serde_json::to_value(checkpoint)?,
                )
                .await?;
            }
        }
        let mut next_poll: Option<chrono::DateTime<Utc>> = None;
        let bundle_digest = crate::model::sha256(&serde_json::to_vec(&bundle)?);
        for (name, remote) in &config.remote_scanners {
            match Box::pin(crate::assemblyline_http::advance(
                store,
                job,
                name,
                remote.assemblyline(),
                &bytes,
                &bundle,
                &bundle_digest,
            ))
            .await?
            {
                crate::assemblyline_http::Step::Pending(next) => {
                    next_poll = Some(next_poll.map_or(next, |current| current.min(next)));
                }
                crate::assemblyline_http::Step::Finished(output) => {
                    if remote.assemblyline().binary_analysis.is_some() {
                        derived_outputs.extend(crate::binary_remote::drafts(name, &output)?);
                    }
                    let mut result = evidence(
                        config,
                        job,
                        name,
                        &remote.assemblyline().profile_revision,
                        output.outcome,
                        output.details,
                    );
                    if let Some(until) = output.valid_until {
                        result.expires_at = result.expires_at.min(until);
                        if until <= Utc::now() {
                            result.outcome = Outcome::Inconclusive;
                        }
                    }
                    result.references = output.references;
                    findings.push(result);
                }
            }
        }
        if let Some(next) = next_poll {
            crate::remote_analysis::defer(store, job, next).await?;
            return Ok(());
        }
        if let Some(agent) = config.scanners.get("agent") {
            let state =
                policy.escalation_state(&job.subject, &job.configuration, &findings, Utc::now());
            // Once conditional scheduling is configured, scopes without a rule must
            // not silently disclose their packages to the agent through legacy behavior.
            let conditional = config.policy.agent_escalation.is_some()
                || config.repositories.values().any(|repository| {
                    repository
                        .policy
                        .as_ref()
                        .is_some_and(|policy| policy.agent_escalation.is_some())
                })
                || config
                    .policy_scopes
                    .iter()
                    .any(|scope| scope.policy.agent_escalation.is_some());
            let invoke = policy.agent_always_required()
                || !conditional
                || matches!(state, crate::policy::EscalationState::Triggered { .. });
            if invoke {
                let mut agent_bundle = bundle;
                agent_bundle["subject"] = serde_json::json!(job.subject);
                agent_bundle["configuration"] = serde_json::json!(job.configuration);
                agent_bundle["context_revision"] = serde_json::json!(job.context_revision);
                agent_bundle["findings"] = serde_json::to_value(&findings)?;
                agent_bundle["escalation"] = serde_json::to_value(&state)?;
                let mut result =
                    scan_evidence(config, job, "agent", agent, &bytes, &agent_bundle).await;
                // An investigation cannot outlive any finding supplied as an input.
                if let Some(expiry) = findings.iter().map(|finding| finding.expires_at).min() {
                    result.expires_at = result.expires_at.min(expiry);
                    if result.expires_at <= Utc::now() && result.outcome == Outcome::Pass {
                        result.outcome = Outcome::Inconclusive;
                    }
                }
                // These dependency bindings belong to the engine, never to an adapter's
                // self-report. Policy rejects reuse after any supplied finding changes.
                let dependencies: BTreeMap<_, _> = findings
                    .iter()
                    .map(|finding| {
                        (
                            finding.check.clone(),
                            crate::model::evidence_fingerprint(finding),
                        )
                    })
                    .collect();
                if !result.details.is_object() {
                    result.details = serde_json::json!({"adapter_details":result.details});
                }
                result.details["packweir_inputs"] =
                    serde_json::json!({"version":1,"findings":dependencies});
                findings.push(result);
            } else {
                let reason = if policy.agent_escalation.is_none() {
                    "scope_not_selected"
                } else if matches!(state, crate::policy::EscalationState::Unresolved { .. }) {
                    "condition_unresolved"
                } else {
                    "condition_not_triggered"
                };
                findings.push(skipped_agent(config, job, reason, &state));
            }
        }
    } else if config.scanners.contains_key("agent") {
        let state =
            policy.escalation_state(&job.subject, &job.configuration, &findings, Utc::now());
        findings.push(skipped_agent(config, job, "unsafe_archive", &state));
    }
    if derived_outputs.is_empty() {
        store.complete(job, &findings).await?;
    } else {
        store
            .complete_with_outputs(job, &findings, &derived_outputs, blobs)
            .await?;
    }
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
        .saturating_add(
            config
                .remote_scanners
                .values()
                .map(|s| s.assemblyline().request_timeout_seconds.saturating_mul(4))
                .sum::<u64>(),
        )
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

#[cfg(test)]
mod future_budget_tests {
    use super::*;

    fn future_bytes<F: std::future::Future>(_: impl FnOnce() -> F) -> usize {
        std::mem::size_of::<F>()
    }

    #[tokio::test]
    async fn scanner_futures_stay_within_stack_budget() {
        let config = Config::load(Path::new("packweir.toml")).unwrap();
        let scanner: CommandScanner = serde_json::from_value(serde_json::json!({
            "program":std::env::current_exe().unwrap(),"version":"future-layout-probe"
        }))
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(&crate::config::StorageConfig::Fs {
            root: directory.path().to_string_lossy().into_owned(),
        })
        .unwrap();
        let store = Store {
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://unused@127.0.0.1:1/unused")
                .unwrap(),
        };
        let job = Job {
            id: uuid::Uuid::new_v4(),
            subject: crate::model::sha256(b"probe"),
            configuration: config.fingerprint(),
            filename: "probe.txt".into(),
            lease: uuid::Uuid::new_v4(),
            context_revision: 0,
        };
        let bundle = serde_json::json!({});
        let sizes = [
            (
                "executable verifier",
                future_bytes(|| crate::process::verify_executable("unused", "unused")),
            ),
            (
                "signature verifier",
                future_bytes(|| {
                    crate::sigstore::verify(&scanner, &job, &bundle, directory.path(), "probe")
                }),
            ),
            (
                "driver dispatch",
                future_bytes(|| {
                    crate::drivers::run(&scanner, &job, &bundle, directory.path(), "probe")
                }),
            ),
            (
                "scanner run",
                future_bytes(|| run(&scanner, &job, b"probe", &bundle)),
            ),
            (
                "scan evidence",
                future_bytes(|| scan_evidence(&config, &job, "probe", &scanner, b"probe", &bundle)),
            ),
            (
                "analyze",
                future_bytes(|| analyze(&config, &store, &blobs, &job)),
            ),
            (
                "worker",
                future_bytes(|| worker(Arc::new(config), store, blobs, true)),
            ),
        ];
        for (name, bytes) in sizes {
            assert!(
                bytes <= 16 * 1024,
                "{name} future is {bytes} bytes; large scanner state must use heap storage"
            );
        }
    }
}
