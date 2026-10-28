use crate::{
    config::{CommandScanner, Config},
    inventory,
    model::{Evidence, Outcome, agent_binding},
    storage::BlobStore,
    store::{Job, Store},
};
use anyhow::{Result, ensure};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::{io::Write, process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScannerOutput {
    outcome: Outcome,
    details: serde_json::Value,
    #[serde(default)]
    references: Vec<String>,
}

#[cfg(windows)]
struct RestorePermissions {
    path: std::path::PathBuf,
    permissions: std::fs::Permissions,
}
#[cfg(windows)]
impl Drop for RestorePermissions {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.path, self.permissions.clone());
    }
}

pub async fn read_bounded(reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    reader.take(limit + 1).read_to_end(&mut bytes).await?;
    ensure!(bytes.len() as u64 <= limit, "scanner output limit exceeded");
    Ok(bytes)
}

async fn command(
    scanner: &CommandScanner,
    job: &Job,
    bytes: &[u8],
    bundle: &serde_json::Value,
) -> Result<ScannerOutput> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("artifact");
    let mut file = std::fs::File::create(&path)?;
    file.write_all(bytes)?;
    drop(file);
    let mut permissions = std::fs::metadata(&path)?.permissions();
    // Windows cannot remove a read-only input; restore its original permissions on every exit path.
    #[cfg(windows)]
    let _restore_permissions = RestorePermissions {
        path: path.clone(),
        permissions: permissions.clone(),
    };
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions)?;
    let bundle = serde_json::to_vec(bundle)?;
    ensure!(
        bundle.len() <= 8 * 1024 * 1024,
        "evidence bundle exceeds limit"
    );
    let bundle_digest = crate::model::sha256(&bundle);
    let bundle_path = directory.path().join("evidence.json");
    std::fs::write(&bundle_path, &bundle)?;
    let mut cmd = Command::new(&scanner.program);
    cmd.args(&scanner.args)
        .current_dir(directory.path())
        .env_clear()
        .envs(&scanner.environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Windows needs these to load executables; scanner configuration controls every other variable.
    #[cfg(windows)]
    for name in ["SYSTEMROOT", "WINDIR"] {
        if let Ok(value) = std::env::var(name) {
            cmd.env(name, value);
        }
    }
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let input = serde_json::to_vec(
        &serde_json::json!({"protocol_version":1,"subject":job.subject,
        "configuration":job.configuration,"filename":job.filename,"artifact_path":path,
        "evidence_path":bundle_path,"evidence_digest":bundle_digest,"context_revision":job.context_revision}),
    )?;
    let execution = async {
        let write = async {
            stdin.write_all(&input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        let (_, output, _) = tokio::try_join!(
            write,
            read_bounded(stdout, 1024 * 1024),
            read_bounded(stderr, 64 * 1024)
        )?;
        let status = child.wait().await?;
        ensure!(status.success(), "scanner returned failure");
        let output: ScannerOutput = serde_json::from_slice(&output)?;
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
        Ok::<_, anyhow::Error>(output)
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(scanner.timeout_seconds),
        execution,
    )
    .await;
    // kill_on_drop protects cancellation; explicitly reap on timeout/error.
    match result {
        Ok(Ok(output)) => Ok(output),
        other => {
            let _ = child.kill().await;
            match other {
                Ok(Err(error)) => Err(error),
                Err(_) => anyhow::bail!("scanner timed out"),
                _ => unreachable!(),
            }
        }
    }
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
            let mut e = match command(scanner, job, &bytes, &bundle).await {
                Ok(output) => {
                    let outcome = if name == "agent" && !agent_binding(&output.details) {
                        Outcome::Inconclusive
                    } else {
                        output.outcome
                    };
                    let mut e =
                        evidence(config, job, name, &scanner.version, outcome, output.details);
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
