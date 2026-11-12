use super::{
    Execution,
    licenses::{self, FileInput},
};
use crate::{
    config::{OSSGADGET_VERSION, OssgadgetMode},
    inventory,
    model::{Outcome, sha256},
    scanner::{ReadOnlyInputs, ScannerOutput, read_bounded},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

const ENTRYPOINT: &str = "packweir-ossgadget-helper.dll";
const ENGINE: &str =
    "Microsoft.ApplicationInspector 1.9.55 (from Microsoft.CST.OSSGadget.CLI 0.2.49)";
const PACKAGE: &str = "0f139a32ecf35538d44cf0be7781be6194a395bc331d4084240f77f1c5b8aded";
const SOURCE: &str = "4063457b40211c25b41d56465d41783f2d42c5c1";
const MIB: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    protocol_version: u32,
    entrypoint: String,
    #[serde(deserialize_with = "unique_files")]
    files: BTreeMap<String, String>,
}

fn unique_files<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Files;
    impl<'de> serde::de::Visitor<'de> for Files {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("unique deployment file pins")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut files = BTreeMap::new();
            while let Some((name, digest)) = map.next_entry::<String, String>()? {
                if files.len() >= 512 || files.insert(name, digest).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive deployment files",
                    ));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Files)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    protocol_version: u32,
    helper_version: String,
    engine: String,
    package_sha256: String,
    source_revision: String,
    mode: OssgadgetMode,
    status: String,
    complete: bool,
    archive_crawling: bool,
    rules_sha256: Option<String>,
    engine_result_code: Option<i32>,
    engine_result_name: Option<String>,
    files: Vec<FileReport>,
    findings: Vec<Finding>,
    totals: Totals,
    diagnostics: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileReport {
    path: String,
    sha256: String,
    size: u64,
    status: String,
    upstream_status: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    path: String,
    rule_id: String,
    description: Option<String>,
    tags: Vec<String>,
    severity: String,
    confidence: String,
    severity_value: i32,
    confidence_value: i32,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
    language: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Totals {
    requested: usize,
    analyzed: usize,
    skipped: usize,
    errored: usize,
    matches: usize,
}

fn no_link(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        !metadata.file_type().is_symlink() && metadata.file_attributes() & 0x400 == 0
    }
    #[cfg(not(windows))]
    {
        !metadata.file_type().is_symlink()
    }
}

fn safe_deployment_path(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && name.split('/').all(|part| {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && ![
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9",
                ]
                .contains(&stem.as_str())
        })
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn deployment(
    root: &Path,
    target: &Path,
    manifest: Manifest,
    deadline: Instant,
) -> Result<ReadOnlyInputs> {
    ensure!(
        manifest.protocol_version == 1 && manifest.entrypoint == ENTRYPOINT,
        "unsupported OSSGadget deployment manifest"
    );
    ensure!(
        !manifest.files.is_empty() && manifest.files.len() <= 512,
        "invalid OSSGadget deployment count"
    );
    for required in [
        ENTRYPOINT,
        "packweir-ossgadget-helper.runtimeconfig.json",
        "packweir-ossgadget-helper.deps.json",
    ] {
        ensure!(
            manifest.files.contains_key(required),
            "OSSGadget deployment is missing helper loader inputs"
        );
    }
    for ancestor in root.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && no_link(&metadata),
            "OSSGadget deployment root contains a link or reparse point"
        );
    }
    std::fs::create_dir(target)?;
    let mut inputs = ReadOnlyInputs::default();
    let mut names = BTreeSet::new();
    let mut total = 0;
    for (name, expected) in manifest.files {
        ensure!(
            Instant::now() < deadline,
            "OSSGadget staging budget exhausted"
        );
        ensure!(
            safe_deployment_path(&name)
                && digest(&expected)
                && names.insert(name.to_ascii_lowercase()),
            "unsafe, aliased, or unpinned OSSGadget deployment path"
        );
        let mut source = root.to_path_buf();
        let parts: Vec<_> = name.split('/').collect();
        for (index, part) in parts.iter().enumerate() {
            source.push(part);
            let metadata = std::fs::symlink_metadata(&source)?;
            ensure!(
                no_link(&metadata)
                    && (if index + 1 == parts.len() {
                        metadata.is_file() && metadata.len() <= 8 * MIB
                    } else {
                        metadata.is_dir()
                    }),
                "OSSGadget deployment file is linked, special, or oversized"
            );
        }
        let mut bytes = vec![];
        std::fs::File::open(&source)?
            .take(8 * MIB + 1)
            .read_to_end(&mut bytes)?;
        total += bytes.len() as u64;
        ensure!(
            bytes.len() as u64 <= 8 * MIB && total <= 64 * MIB && sha256(&bytes) == expected,
            "OSSGadget deployment digest or size mismatch"
        );
        let path = target.join(name);
        std::fs::create_dir_all(path.parent().expect("deployment parent"))?;
        inputs.write(&path, &bytes)?;
    }
    Ok(inputs)
}

async fn verify_input(root: &Path, relative: &str, expected: &str, size: u64) -> Result<()> {
    let path = root.join(relative);
    for ancestor in path.ancestors().take_while(|path| path.starts_with(root)) {
        ensure!(
            no_link(&tokio::fs::symlink_metadata(ancestor).await?),
            "OSSGadget input replaced by a link"
        );
    }
    let metadata = tokio::fs::symlink_metadata(&path).await?;
    ensure!(
        metadata.is_file() && metadata.len() == size,
        "OSSGadget input replaced during scan"
    );
    let bytes = read_bounded(tokio::fs::File::open(path).await?, size).await?;
    ensure!(
        sha256(&bytes) == expected,
        "OSSGadget input changed during scan"
    );
    Ok(())
}

fn assess(
    report: &Report,
    expected: &[FileInput],
    mode: OssgadgetMode,
    rules: Option<&str>,
    denied: &[String],
) -> Result<Outcome> {
    ensure!(
        report.protocol_version == 1
            && report.helper_version == "1"
            && report.engine == ENGINE
            && report.package_sha256 == PACKAGE
            && report.source_revision == SOURCE
            && report.mode == mode
            && !report.archive_crawling
            && report.rules_sha256.as_deref() == rules,
        "OSSGadget report identity, options, or rules mismatch"
    );
    ensure!(
        ["complete", "partial"].contains(&report.status.as_str())
            && report.complete == (report.status == "complete"),
        "OSSGadget report completion state mismatch"
    );
    ensure!(
        report.files.len() == expected.len()
            && report.findings.len() <= 2000
            && report.diagnostics.len() <= 64
            && report.diagnostics.iter().all(|d| d.len() <= 1024),
        "OSSGadget report limit or coverage mismatch"
    );
    let lookup: BTreeMap<_, _> = expected
        .iter()
        .map(|file| (file.relative.as_str(), file))
        .collect();
    let mut seen = BTreeSet::new();
    let mut analyzed = 0;
    let mut skipped = 0;
    let mut errored = 0;
    let mut covered = BTreeSet::new();
    for file in &report.files {
        let expected = lookup
            .get(file.path.as_str())
            .ok_or_else(|| anyhow::anyhow!("unexpected OSSGadget report file"))?;
        ensure!(
            seen.insert(file.path.as_str())
                && file.sha256 == expected.sha256
                && file.size == expected.size,
            "OSSGadget duplicate file, digest, or size mismatch"
        );
        match file.status.as_str() {
            "analyzed" | "affected" => {
                ensure!(
                    file.upstream_status.as_deref()
                        == Some(if file.status == "analyzed" {
                            "Analyzed"
                        } else {
                            "Affected"
                        }),
                    "OSSGadget upstream file completion mismatch"
                );
                analyzed += 1;
                covered.insert(file.path.as_str());
            }
            "skipped" => skipped += 1,
            "error" => errored += 1,
            "not_analyzed" => {}
            _ => anyhow::bail!("unknown OSSGadget file status"),
        }
        ensure!(
            file.reason
                .as_ref()
                .is_none_or(|reason| reason.len() <= 2048),
            "OSSGadget file reason exceeds limit"
        );
    }
    ensure!(
        report.totals.requested == expected.len()
            && report.totals.analyzed == analyzed
            && report.totals.skipped == skipped
            && report.totals.errored == errored
            && report.totals.matches == report.findings.len(),
        "OSSGadget report totals mismatch"
    );
    for finding in &report.findings {
        ensure!(
            covered.contains(finding.path.as_str())
                && !finding.rule_id.is_empty()
                && finding.rule_id.len() <= 256
                && finding.description.as_ref().is_none_or(|d| d.len() <= 2048)
                && finding.tags.len() <= 64
                && finding.tags.iter().all(|tag| tag.len() <= 256)
                && finding
                    .language
                    .as_ref()
                    .is_none_or(|language| language.len() <= 256),
            "OSSGadget finding is unbound or exceeds limits"
        );
        let severity = [
            ("Unspecified", 0),
            ("Critical", 1),
            ("Important", 2),
            ("Moderate", 4),
            ("BestPractice", 8),
            ("ManualReview", 16),
        ];
        let confidence = [("Unspecified", 0), ("Low", 1), ("Medium", 2), ("High", 4)];
        ensure!(
            severity.contains(&(finding.severity.as_str(), finding.severity_value))
                && confidence.contains(&(finding.confidence.as_str(), finding.confidence_value)),
            "OSSGadget finding enum mismatch"
        );
    }
    if report.complete {
        ensure!(
            analyzed == expected.len()
                && report.diagnostics.is_empty()
                && matches!(
                    (
                        report.engine_result_code,
                        report.engine_result_name.as_deref()
                    ),
                    (Some(0), Some("Success")) | (Some(1), Some("NoMatches"))
                ),
            "OSSGadget complete report lacks engine or file completion"
        );
    }
    ensure!(
        report.engine_result_name.as_deref() != Some("NoMatches") || report.findings.is_empty(),
        "OSSGadget NoMatches report contains findings"
    );
    Ok(
        if report
            .findings
            .iter()
            .any(|finding| denied.contains(&finding.rule_id))
        {
            Outcome::Fail
        } else if !report.complete || !report.findings.is_empty() {
            Outcome::Inconclusive
        } else {
            Outcome::Pass
        },
    )
}

pub(super) async fn run(
    execution: &mut Execution<'_>,
    root: &str,
    manifest: &str,
    mode: OssgadgetMode,
    custom_rules: Option<&str>,
    denied: &[String],
) -> Result<ScannerOutput> {
    ensure!(
        execution.scanner.version == OSSGADGET_VERSION,
        "unqualified OSSGadget version"
    );
    let mut result = execution.result(
        Outcome::Inconclusive,
        "observed_artifact_rules",
        "OSSGadget rule coverage is incomplete",
    );
    let bytes = read_bounded(
        tokio::fs::File::open(execution.directory.join("artifact")).await?,
        128 * MIB,
    )
    .await?;
    ensure!(
        sha256(&bytes) == execution.job.subject,
        "OSSGadget artifact subject changed"
    );
    let name = execution.job.filename.clone();
    let input_root = execution.directory.join("ossgadget-input");
    let prepare_root = input_root.clone();
    let prepared = tokio::task::spawn_blocking(move || -> Result<_> {
        let inventory = inventory::inspect(
            &name,
            &bytes,
            inventory::Limits {
                expanded_bytes: 32 * MIB,
                files: 1024,
                depth: 3,
            },
        )?;
        let containers: BTreeSet<_> = inventory
            .files
            .iter()
            .flat_map(|file| {
                file.path
                    .match_indices("!/")
                    .map(|(index, _)| file.path[..index].to_owned())
            })
            .collect();
        let leaves: Vec<_> = inventory
            .files
            .iter()
            .filter(|file| !containers.contains(&file.path))
            .collect();
        if leaves.is_empty()
            || leaves.len() > 256
            || leaves.iter().any(|file| file.size > 4 * MIB)
            || leaves.iter().map(|file| file.size).sum::<u64>() > 32 * MIB
        {
            return Ok(None);
        }
        let binary: BTreeSet<_> = leaves
            .iter()
            .filter(|file| file.kind != "text")
            .map(|file| file.path.as_str())
            .collect();
        let (files, inputs) = licenses::materialize(&name, &bytes, &prepare_root)?;
        let mut unsupported = vec![];
        for file in &files {
            let bytes = std::fs::read(prepare_root.join(&file.relative))?;
            if binary.contains(file.logical.as_str())
                || std::str::from_utf8(&bytes).is_err()
                || bytes.contains(&0)
                || bytes
                    .iter()
                    .filter(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
                    .count() as f64
                    > bytes.len() as f64 * 0.3
            {
                unsupported.push(file.logical.clone());
            }
        }
        Ok(Some((files, inputs, unsupported)))
    })
    .await??;
    let Some((expected, _leaf_inputs, unsupported)) = prepared else {
        result.details["reason"] =
            json!("artifact leaf inputs exceed qualified OSSGadget coverage limits");
        return Ok(result);
    };
    let manifest_bytes = read_bounded(
        tokio::fs::File::open(execution.resource(manifest)).await?,
        MIB,
    )
    .await?;
    let parsed: Manifest = serde_json::from_slice(&manifest_bytes)?;
    let deployment_root = execution.directory.join("ossgadget-deployment");
    let stage = deployment_root.clone();
    let source = PathBuf::from(root);
    let deadline = execution.deadline;
    let _deployment_inputs =
        tokio::task::spawn_blocking(move || deployment(&source, &stage, parsed, deadline))
            .await??;
    let mut inputs = ReadOnlyInputs::default();
    let mut request = json!({"protocol_version":1,"mode":mode,"root":input_root,"files":expected.iter().map(|file| json!({"path":file.relative,"sha256":file.sha256})).collect::<Vec<_>>()});
    let rules = if let Some(resource) = custom_rules {
        let bytes = read_bounded(
            tokio::fs::File::open(execution.resource(resource)).await?,
            MIB,
        )
        .await?;
        let path = input_root.join(".packweir-custom-rules.json");
        inputs.write(&path, &bytes)?;
        let digest = sha256(&bytes);
        request["rules_path"] = json!(path);
        request["rules_sha256"] = json!(digest);
        Some((digest, bytes.len() as u64))
    } else {
        None
    };
    let request = serde_json::to_vec(&request)?;
    ensure!(
        request.len() <= 256 * 1024,
        "OSSGadget request exceeds limit"
    );
    let mut environment = execution.environment();
    for (key, value) in [
        ("DOTNET_MULTILEVEL_LOOKUP", "0"),
        ("DOTNET_NOLOGO", "1"),
        ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
    ] {
        environment.insert(key.into(), value.into());
    }
    environment.insert(
        "DOTNET_CLI_HOME".into(),
        execution.directory.to_string_lossy().into_owned(),
    );
    let output = execution
        .execute_with_input(
            vec![
                "exec".into(),
                "--runtimeconfig".into(),
                deployment_root
                    .join("packweir-ossgadget-helper.runtimeconfig.json")
                    .into_os_string(),
                "--depsfile".into(),
                deployment_root
                    .join("packweir-ossgadget-helper.deps.json")
                    .into_os_string(),
                deployment_root.join(ENTRYPOINT).into_os_string(),
            ],
            &environment,
            &request,
        )
        .await?;
    if !output.status.success() {
        result.outcome = Outcome::Error;
        result.details["reason"] = json!("OSSGadget helper execution failed");
        result.details["report_sha256"] = json!(sha256(&output.stdout));
        if let Ok(report) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            result.details["report"] = report;
        }
        return Ok(result);
    }
    let report: Report = serde_json::from_slice(&output.stdout)?;
    for file in &expected {
        verify_input(&input_root, &file.relative, &file.sha256, file.size).await?;
    }
    if let Some((digest, size)) = &rules {
        verify_input(&input_root, ".packweir-custom-rules.json", digest, *size).await?;
    }
    ensure!(
        Instant::now() < execution.deadline,
        "OSSGadget execution budget exhausted"
    );
    result.outcome = assess(
        &report,
        &expected,
        mode,
        rules.as_ref().map(|(digest, _)| digest.as_str()),
        denied,
    )?;
    if result.outcome == Outcome::Pass && !unsupported.is_empty() {
        result.outcome = Outcome::Inconclusive;
    }
    result.details["reason"] = json!(match result.outcome {
        Outcome::Pass => "complete qualified rule scan found no matches",
        Outcome::Fail => "an observed rule matches explicit operator denial policy",
        _ => "rule findings or incomplete coverage require investigation",
    });
    result.details["report"] = serde_json::to_value(&report)?;
    result.details["report_sha256"] = json!(sha256(&output.stdout));
    result.details["deployment_manifest_sha256"] = json!(sha256(&manifest_bytes));
    result.details["deny_rules"] = json!(denied);
    result.details["files"] = json!(expected.iter().map(|file| json!({"path":file.logical,"scan_path":file.relative,"sha256":file.sha256,"size":file.size})).collect::<Vec<_>>());
    result.details["unsupported_leaf_paths"] = json!(unsupported);
    result.details["coverage"] = json!(
        "bounded explicit artifact leaves; selected characteristic, backdoor, or custom rules only; binary and unsupported files remain partial; no absence-of-malware assertion"
    );
    Ok(result)
}
