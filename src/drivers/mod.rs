mod hipcheck;
mod osv;
mod slsa;

use crate::{
    config::{CommandScanner, ScannerDriver},
    model::{Outcome, sha256},
    process,
    scanner::ScannerOutput,
    store::Job,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::Path,
    time::{Duration, Instant},
};

struct Execution<'a> {
    scanner: &'a CommandScanner,
    job: &'a Job,
    directory: &'a Path,
    evidence_digest: &'a str,
    deadline: Instant,
    output_bytes: usize,
}

impl Execution<'_> {
    async fn execute(
        &mut self,
        args: Vec<OsString>,
        environment: &BTreeMap<String, String>,
    ) -> Result<process::Output> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow::anyhow!("driver execution budget exhausted"))?;
        let output = process::execute(
            &self.scanner.program,
            &args,
            environment,
            self.directory,
            &[],
            remaining,
        )
        .await?;
        tracing::debug!(program=%self.scanner.program, status=?output.status, stderr=%String::from_utf8_lossy(&output.stderr), "native scanner diagnostics");
        self.output_bytes += output.stdout.len();
        ensure!(
            self.output_bytes <= 1024 * 1024,
            "driver combined output limit exceeded"
        );
        Ok(output)
    }

    fn result(&self, outcome: Outcome, scope: &str, reason: &str) -> ScannerOutput {
        ScannerOutput {
            outcome,
            details: json!({"verification_scope":scope,"reason":reason,
            "evidence_digest":self.evidence_digest,"program_digest":self.scanner.program_sha256}),
            references: vec![],
            valid_until: None,
        }
    }

    fn resource(&self, name: &str) -> std::path::PathBuf {
        self.directory.join(format!("resource-{name}"))
    }

    fn environment(&self) -> BTreeMap<String, String> {
        let mut environment = self.scanner.environment.clone();
        for name in [
            "HOME",
            "USERPROFILE",
            "LOCALAPPDATA",
            "XDG_CACHE_HOME",
            "TMPDIR",
            "TMP",
            "TEMP",
        ] {
            environment.insert(name.into(), self.directory.to_string_lossy().into_owned());
        }
        #[cfg(windows)]
        environment
            .entry("PATHEXT".into())
            .or_insert_with(|| ".COM;.EXE".into());
        environment
    }
}

pub(crate) async fn run(
    scanner: &CommandScanner,
    job: &Job,
    bundle: &Value,
    directory: &Path,
    evidence_digest: &str,
) -> Result<ScannerOutput> {
    let mut execution = Execution {
        scanner,
        job,
        directory,
        evidence_digest,
        deadline: Instant::now() + Duration::from_secs(scanner.timeout_seconds),
        output_bytes: 0,
    };
    match &scanner.driver {
        ScannerDriver::Slsa {
            builder_id,
            sources,
        } => slsa::run(&mut execution, bundle, builder_id, sources).await,
        ScannerDriver::Osv {
            packages,
            databases,
        } => osv::run(&mut execution, bundle, packages, databases).await,
        ScannerDriver::Hipcheck {
            policy,
            execution: configuration,
            required_analyses,
            sources,
            plugins,
        } => {
            hipcheck::run(
                &mut execution,
                bundle,
                policy,
                configuration,
                required_analyses,
                sources,
                plugins,
            )
            .await
        }
        _ => anyhow::bail!("unsupported built-in driver"),
    }
}

// Every registered alias must be mapped by operator configuration. An empty/partial map cannot approve.
fn matching_indices<'a>(
    bundle: &Value,
    bindings: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<Vec<usize>> {
    let identities = bundle.get("identities")?.as_array()?;
    if identities.is_empty() || identities.len() > 32 {
        return None;
    }
    let lookup: BTreeMap<_, _> = bindings
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect();
    let mut selected = BTreeSet::new();
    for identity in identities {
        let key = (
            identity.get("repository")?.as_str()?,
            identity.get("origin")?.as_str()?,
        );
        selected.insert(*lookup.get(&key)?);
    }
    Some(selected.into_iter().collect())
}

fn document_digest(document: &Value) -> Result<String> {
    let digest = sha256(&serde_json::to_vec(
        document
            .get("document")
            .ok_or_else(|| anyhow::anyhow!("missing document content"))?,
    )?);
    if let Some(claimed) = document.get("blob_digest") {
        ensure!(
            claimed.as_str() == Some(digest.as_str()),
            "input document digest mismatch"
        );
    }
    Ok(digest)
}

fn source_matches(uri: &str, expected: &str) -> bool {
    uri.strip_prefix("git+").unwrap_or(uri).split('@').next() == Some(expected)
}
