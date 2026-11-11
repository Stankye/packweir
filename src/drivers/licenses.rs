use super::Execution;
use crate::{
    inventory,
    licenses::{LicenseDecision, LicensePolicy, SCANCODE_VERSION},
    model::{Outcome, sha256},
    scanner::{ReadOnlyInputs, ScannerOutput, read_bounded},
};
use anyhow::{Result, ensure};
use flate2::read::MultiGzDecoder;
use serde_json::{Value, json};
use sha1::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
    path::Path,
};

const REPORT_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
struct FileInput {
    logical: String,
    relative: String,
    sha256: String,
    sha1: String,
    size: u64,
}

pub(super) async fn run(
    execution: &mut Execution<'_>,
    policy: &LicensePolicy,
) -> Result<ScannerOutput> {
    policy.validate()?;
    ensure!(
        execution.scanner.version == SCANCODE_VERSION,
        "ScanCode version needs separate qualification"
    );
    let artifact = tokio::fs::File::open(execution.directory.join("artifact")).await?;
    let bytes = read_bounded(artifact, 128 * 1024 * 1024).await?;
    ensure!(
        sha256(&bytes) == execution.job.subject,
        "license input subject changed"
    );
    let directory = execution.directory.join("license-input");
    let name = execution.job.filename.clone();
    let prepare_directory = directory.clone();
    let (expected, _inputs) =
        tokio::task::spawn_blocking(move || materialize(&name, &bytes, &prepare_directory))
            .await??;
    let mut result = execution.result(
        Outcome::Inconclusive,
        "observed_file_licenses",
        "license observations require complete file coverage",
    );
    if expected.is_empty() {
        result.details["reason"] = json!("artifact has no inspectable leaf files");
        return Ok(result);
    }
    let report_path = execution.directory.join("scancode-report.json");
    let environment = execution.environment();
    let output = execution
        .execute(
            vec![
                "--license".into(),
                "--copyright".into(),
                "--package".into(),
                "--info".into(),
                "--strip-root".into(),
                "--quiet".into(),
                "--processes".into(),
                "1".into(),
                "--json".into(),
                report_path.as_os_str().into(),
                directory.as_os_str().into(),
            ],
            &environment,
        )
        .await?;
    if !output.status.success() {
        result.outcome = Outcome::Error;
        result.details["reason"] = json!("ScanCode execution failed or reported scan errors");
        return Ok(result);
    }
    let metadata = tokio::fs::symlink_metadata(&report_path).await?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "ScanCode report is not a regular file"
    );
    let report_bytes =
        read_bounded(tokio::fs::File::open(&report_path).await?, REPORT_LIMIT).await?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    // A trusted scanner still must not substitute input files while reporting the original hashes.
    for expected in &expected {
        let path = directory.join(&expected.relative);
        let metadata = tokio::fs::symlink_metadata(&path).await?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == expected.size,
            "license input replaced during scan"
        );
        let bytes = read_bounded(tokio::fs::File::open(path).await?, expected.size).await?;
        ensure!(
            sha256(&bytes) == expected.sha256,
            "license input changed during scan"
        );
    }
    let assessed = assess_report(&report, &expected, policy, &directory)?;
    result.outcome = assessed.0;
    result.details["reason"] = json!(assessed.1);
    result.details["files"] = assessed.2;
    result.details["report"] = report;
    result.details["report_sha256"] = json!(sha256(&report_bytes));
    result.details["policy"] = serde_json::to_value(policy)?;
    result.details["spdx_license_list"] = json!(spdx::identifiers::VERSION);
    result.details["coverage"] = json!(
        "bounded archive leaf contents; independent file observations, no inherited license scope, complete dependency graph, or legal obligation determination"
    );
    Ok(result)
}

fn assess_report(
    report: &Value,
    expected: &[FileInput],
    policy: &LicensePolicy,
    input: &Path,
) -> Result<(Outcome, &'static str, Value)> {
    let headers = report
        .get("headers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("ScanCode headers missing"))?;
    ensure!(headers.len() == 1, "ambiguous ScanCode headers");
    let header = &headers[0];
    ensure!(
        header["tool_name"] == "scancode-toolkit" && header["tool_version"] == SCANCODE_VERSION,
        "ScanCode report tool/version mismatch"
    );
    empty_array(header, "errors")?;
    for option in [
        "--license",
        "--copyright",
        "--package",
        "--info",
        "--strip-root",
    ] {
        ensure!(
            header["options"][option] == true,
            "ScanCode coverage option missing"
        );
    }
    ensure!(
        header["options"]["input"] == json!([input]),
        "ScanCode report input mismatch"
    );
    ensure!(
        header["end_timestamp"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "ScanCode report is incomplete"
    );
    ensure!(
        header["extra_data"]["files_count"].as_u64() == Some(expected.len() as u64),
        "ScanCode file count mismatch"
    );
    let files = report
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("ScanCode files missing"))?;
    ensure!(files.len() <= 30_001, "ScanCode resource limit exceeded");
    let lookup: BTreeMap<_, _> = expected.iter().map(|f| (f.relative.as_str(), f)).collect();
    let mut seen = BTreeSet::new();
    let mut findings = Vec::new();
    let mut denied = false;
    let mut inconclusive = false;
    for file in files {
        empty_array(file, "scan_errors")?;
        let path = file
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("ScanCode path missing"))?;
        if file["type"] == "directory" {
            continue;
        }
        ensure!(file["type"] == "file", "unsupported ScanCode resource type");
        let expected = lookup
            .get(path)
            .ok_or_else(|| anyhow::anyhow!("unexpected ScanCode file path"))?;
        ensure!(seen.insert(path), "duplicate ScanCode file result");
        ensure!(
            file["size"].as_u64() == Some(expected.size)
                && file["sha1"].as_str() == Some(&expected.sha1),
            "ScanCode file digest/size mismatch"
        );
        let detections = file
            .get("license_detections")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("ScanCode license detection coverage missing"))?;
        ensure!(
            detections.len() <= 256,
            "ScanCode license detection count exceeded"
        );
        let clues = file
            .get("license_clues")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("ScanCode license clue coverage missing"))?;
        ensure!(
            file.get("copyrights").and_then(Value::as_array).is_some(),
            "ScanCode copyright coverage missing"
        );
        let detected = optional_expression(file, "detected_license_expression_spdx")?;
        let packages = file
            .get("package_data")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("ScanCode package coverage missing"))?;
        ensure!(packages.len() <= 256, "ScanCode package count exceeded");
        let mut declarations = BTreeSet::new();
        for package in packages {
            if let Some(expression) =
                optional_expression(package, "declared_license_expression_spdx")?
            {
                declarations.insert(expression.to_owned());
            }
        }
        let assessment = detected
            .map(|expression| policy.assess(expression))
            .transpose()?;
        let declared_assessments = declarations
            .iter()
            .map(|expression| policy.assess(expression))
            .collect::<Result<Vec<_>>>()?;
        let mut conflicting = false;
        if let Some(detected) = &assessment {
            for declaration in &declared_assessments {
                conflicting |=
                    !crate::licenses::equivalent(&declaration.expression, &detected.expression)?;
            }
        } else if let Some(first) = declared_assessments.first() {
            for declaration in &declared_assessments[1..] {
                conflicting |=
                    !crate::licenses::equivalent(&declaration.expression, &first.expression)?;
            }
        }
        let detected_terms = detections
            .iter()
            .map(|d| {
                optional_expression(d, "license_expression_spdx")?
                    .ok_or_else(|| anyhow::anyhow!("ScanCode detection SPDX expression missing"))
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(aggregate) = detected {
            conflicting |= !crate::licenses::conjunction_equivalent(aggregate, &detected_terms)?;
        } else {
            conflicting |= !detected_terms.is_empty();
        }
        let unknown = assessment.is_none()
            || assessment
                .as_ref()
                .is_some_and(|a| a.decision == LicenseDecision::Unknown);
        if conflicting {
            inconclusive = true;
        }
        if !clues.is_empty() {
            inconclusive = true;
        }
        if let Some(assessment) = &assessment {
            match assessment.decision {
                LicenseDecision::Allowed => {}
                LicenseDecision::Denied => denied = true,
                LicenseDecision::Unknown => inconclusive = true,
            }
        } else if !policy.allow_unknown {
            inconclusive = true;
        }
        // Explicitly denied declarations remain actionable even when file-level detection differs.
        if declared_assessments
            .iter()
            .any(|a| a.decision == LicenseDecision::Denied)
        {
            denied = true;
        }
        findings.push(json!({"path":expected.logical,"scan_path":path,"sha256":expected.sha256,"size":expected.size,
            "detected":assessment,"declared":declared_assessments,"unknown":unknown,"unknown_allowed":assessment.is_none() && policy.allow_unknown,
            "conflicting":conflicting,"copyrights":file["copyrights"],"license_detections":file["license_detections"],"license_clues":clues}));
    }
    ensure!(
        seen.len() == expected.len(),
        "ScanCode omitted artifact files"
    );
    let (outcome, reason) = if denied {
        (
            Outcome::Fail,
            "license observations do not satisfy the explicit policy",
        )
    } else if inconclusive {
        (
            Outcome::Inconclusive,
            "license evidence is unknown or conflicting and requires review",
        )
    } else {
        (
            Outcome::Pass,
            "all scanned leaf files satisfy the configured license policy, including explicitly allowed uncertainty",
        )
    };
    Ok((outcome, reason, json!(findings)))
}

fn empty_array(value: &Value, key: &str) -> Result<()> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("ScanCode error status missing"))?;
    ensure!(values.is_empty(), "ScanCode reported scan errors");
    Ok(())
}

fn optional_expression<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>> {
    let value = value
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("ScanCode license coverage field missing"))?;
    if value.is_null() {
        return Ok(None);
    }
    let expression = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid ScanCode license expression"))?;
    if expression.trim().is_empty() {
        return Ok(None);
    }
    ensure!(
        expression.len() <= 4096,
        "license expression limit exceeded"
    );
    Ok(Some(expression))
}

fn materialize(
    name: &str,
    bytes: &[u8],
    directory: &Path,
) -> Result<(Vec<FileInput>, ReadOnlyInputs)> {
    let inspected = inventory::inspect(name, bytes, inventory::Limits::default())?;
    let mut leaves = BTreeMap::new();
    let mut used = 0;
    collect(name, bytes, 0, &mut used, &mut leaves)?;
    let containers: BTreeSet<_> = inspected
        .files
        .iter()
        .flat_map(|f| {
            f.path
                .match_indices("!/")
                .map(|(index, _)| f.path[..index].to_owned())
        })
        .collect();
    let expected: BTreeMap<_, _> = inspected
        .files
        .iter()
        .filter(|f| !containers.contains(&f.path))
        .map(|f| (f.path.as_str(), f.sha256.as_str()))
        .collect();
    ensure!(
        leaves.len() == expected.len(),
        "license extraction coverage disagrees with inventory"
    );
    std::fs::create_dir(directory)?;
    let mut inputs = ReadOnlyInputs::default();
    let mut files = Vec::new();
    for (index, (logical, bytes)) in leaves.into_iter().enumerate() {
        let digest = sha256(&bytes);
        ensure!(
            expected.get(logical.as_str()).copied() == Some(digest.as_str()),
            "license extraction content differs from inventory"
        );
        let filename = logical
            .rsplit('/')
            .next()
            .unwrap_or("content")
            .rsplit("!/")
            .next()
            .unwrap_or("content");
        let relative = format!("f{index:05}/{filename}");
        let path = directory.join(&relative);
        std::fs::create_dir(path.parent().expect("leaf parent"))?;
        inputs.write(&path, &bytes)?;
        files.push(FileInput {
            logical,
            relative,
            sha256: digest,
            sha1: hex::encode(sha1::Sha1::digest(&bytes)),
            size: bytes.len() as u64,
        });
    }
    Ok((files, inputs))
}

fn bounded(reader: impl Read, used: &mut u64) -> Result<Vec<u8>> {
    let remaining = inventory::Limits::default()
        .expanded_bytes
        .saturating_sub(*used);
    let mut bytes = Vec::new();
    reader.take(remaining + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= remaining,
        "license expansion limit exceeded"
    );
    *used += bytes.len() as u64;
    Ok(bytes)
}

fn collect(
    path: &str,
    bytes: &[u8],
    depth: usize,
    used: &mut u64,
    leaves: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let zip = bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06");
    let gzip = bytes.starts_with(&[0x1f, 0x8b]);
    let tar = path.ends_with(".tar") || (bytes.len() > 262 && &bytes[257..262] == b"ustar");
    if !(zip || gzip || tar) {
        ensure!(
            leaves.len() < inventory::Limits::default().files,
            "license file limit exceeded"
        );
        ensure!(
            leaves.insert(path.into(), bytes.to_vec()).is_none(),
            "duplicate license file"
        );
        return Ok(());
    }
    ensure!(
        depth < inventory::Limits::default().depth,
        "license nesting limit exceeded"
    );
    if zip {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        archive.validate_header_consistency()?;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name()?.into_owned();
            ensure!(
                inventory::safe_path(&name)
                    && entry.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
                "unsafe ZIP leaf"
            );
            if entry.is_dir() {
                continue;
            }
            let content = bounded(&mut entry, used)?;
            collect(
                &format!("{path}!/{name}"),
                &content,
                depth + 1,
                used,
                leaves,
            )?;
        }
    } else if gzip {
        let content = bounded(MultiGzDecoder::new(bytes), used)?;
        let nested = if path.ends_with(".tgz") || path.ends_with(".crate") {
            format!("{path}!/payload.tar")
        } else {
            format!(
                "{path}!/{}",
                path.rsplit('/')
                    .next()
                    .unwrap_or("payload")
                    .trim_end_matches(".gz")
            )
        };
        collect(&nested, &content, depth + 1, used, leaves)?;
    } else {
        let mut archive = tar::Archive::new(Cursor::new(bytes));
        archive.set_ignore_zeros(true);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = entry.path()?.to_string_lossy().into_owned();
            ensure!(inventory::safe_path(&name), "unsafe TAR leaf");
            if entry.header().entry_type().is_dir() {
                continue;
            }
            ensure!(
                entry.header().entry_type().is_file(),
                "TAR links and special files rejected"
            );
            let content = bounded(&mut entry, used)?;
            collect(
                &format!("{path}!/{name}"),
                &content,
                depth + 1,
                used,
                leaves,
            )?;
        }
    }
    Ok(())
}
