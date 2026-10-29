use super::{Execution, matching_indices};
use crate::{
    config::{OsvDatabase, PackageBinding},
    model::Outcome,
    scanner::{ReadOnlyInputs, ScannerOutput, read_bounded},
};
use anyhow::{Result, ensure};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

pub(super) async fn run(
    execution: &mut Execution<'_>,
    bundle: &Value,
    packages: &[PackageBinding],
    databases: &BTreeMap<String, OsvDatabase>,
) -> Result<ScannerOutput> {
    let mut result = execution.result(
        Outcome::Inconclusive,
        "mapped_package_vulnerabilities",
        "every artifact alias needs an operator-supplied package mapping",
    );
    let Some(indices) = matching_indices(
        bundle,
        packages
            .iter()
            .map(|p| (p.repository.as_str(), p.origin.as_str())),
    ) else {
        return Ok(result);
    };
    let expected: BTreeSet<_> = indices
        .iter()
        .map(|i| {
            let p = &packages[*i];
            (p.ecosystem.clone(), p.name.clone(), p.version.clone())
        })
        .collect();
    let ecosystems: BTreeSet<_> = expected.iter().map(|p| p.0.as_str()).collect();
    let mut inputs = ReadOnlyInputs::default();
    let mut revisions = BTreeMap::new();
    let mut total = 0;
    for ecosystem in ecosystems {
        let database = &databases[ecosystem];
        let now = Utc::now();
        if database.published_at > now || database.expires_at <= now {
            result.details["reason"] = json!("OSV database snapshot is not currently valid");
            return Ok(result);
        }
        let file = tokio::fs::File::open(&database.path).await?;
        ensure!(
            file.metadata().await?.is_file(),
            "OSV database must be a file"
        );
        let bytes = read_bounded(file, 256 * 1024 * 1024).await?;
        total += bytes.len();
        ensure!(
            total <= 512 * 1024 * 1024,
            "combined OSV database limit exceeded"
        );
        ensure!(
            crate::model::sha256(&bytes) == database.sha256,
            "OSV database digest mismatch"
        );
        validate_archive(&bytes)?;
        let path = execution
            .directory
            .join("database/osv-scalibr")
            .join(ecosystem)
            .join("all.zip");
        std::fs::create_dir_all(path.parent().expect("database parent"))?;
        inputs.write(&path, &bytes)?;
        result.valid_until = Some(
            result
                .valid_until
                .map_or(database.expires_at, |old| old.min(database.expires_at)),
        );
        revisions.insert(ecosystem, json!({"sha256":database.sha256,"revision":database.revision,"published_at":database.published_at,"expires_at":database.expires_at}));
    }
    let package_list: Vec<_> = expected.iter().map(|(ecosystem,name,version)| {
        Ok(json!({"type":"library","name":name,"version":version,"purl":package_url(ecosystem,name,version)?}))
    }).collect::<Result<_>>()?;
    let input = execution.directory.join("mapped.cdx.json");
    inputs.write(
        &input,
        &serde_json::to_vec(&json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":package_list}))?,
    )?;
    let config = execution.directory.join("osv-scanner.toml");
    inputs.write(&config, b"")?;
    let mut environment = execution.environment();
    environment.insert(
        "OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY".into(),
        execution
            .directory
            .join("database")
            .to_string_lossy()
            .into_owned(),
    );
    let output = execution
        .execute(
            vec![
                "scan".into(),
                "source".into(),
                "--offline".into(),
                "--format=json".into(),
                "--all-packages".into(),
                "--all-vulns".into(),
                "--no-resolve".into(),
                "--no-call-analysis=go".into(),
                "--no-call-analysis=rust".into(),
                format!("--config={}", config.display()).into(),
                format!("--lockfile=:{}", input.display()).into(),
            ],
            &environment,
        )
        .await?;
    let code = output.status.code();
    result.details["databases"] = json!(revisions);
    if code == Some(128) {
        result.outcome = Outcome::Unsupported;
        result.details["reason"] = json!("OSV found no supported packages");
        return Ok(result);
    }
    if !matches!(code, Some(0 | 1)) {
        result.outcome = Outcome::Error;
        result.details["reason"] = json!("OSV execution failed");
        return Ok(result);
    }
    let report: Value = serde_json::from_slice(&output.stdout)?;
    let groups = report
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("OSV results array missing"))?;
    let mut observed = BTreeSet::new();
    let mut findings = BTreeSet::new();
    for group in groups {
        let packages = group
            .get("packages")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("OSV package results missing"))?;
        for package in packages {
            let string = |key| {
                package["package"][key]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("OSV package identity missing"))
            };
            observed.insert((string("ecosystem")?, string("name")?, string("version")?));
            if let Some(vulnerabilities) = package.get("vulnerabilities") {
                for vulnerability in vulnerabilities
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("invalid OSV vulnerabilities"))?
                {
                    let id = vulnerability["id"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("OSV finding identifier missing"))?;
                    findings.insert(id.to_owned());
                }
            }
        }
    }
    let generic_findings = report
        .get("experimental_generic_findings")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid generic findings"))
        })
        .transpose()?
        .is_some_and(|v| !v.is_empty());
    result.details["report"] = report.clone();
    result.details["packages"] = json!(expected);
    result.details["coverage"] = json!(
        "mapped package versions only; transitive and embedded components are not established"
    );
    result.details["advisories"] = json!(findings);
    if observed != expected || observed.is_empty() {
        result.details["reason"] =
            json!("OSV output did not cover the exact requested package identities");
    } else if code == Some(1) && (!findings.is_empty() || generic_findings) {
        result.outcome = Outcome::Fail;
        result.details["reason"] = json!("OSV reported known vulnerabilities or findings");
    } else if code == Some(0) && findings.is_empty() && !generic_findings {
        result.outcome = Outcome::Pass;
        result.details["reason"] =
            json!("no known vulnerabilities in the mapped versions and pinned database snapshots");
    } else {
        result.details["reason"] = json!("OSV exit status and report disagree");
    }
    Ok(result)
}

fn validate_archive(bytes: &[u8]) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        !archive.is_empty() && archive.len() <= 200_000,
        "OSV database entry limit exceeded or empty database"
    );
    archive.validate_header_consistency()?;
    let mut size = 0u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        size = size
            .checked_add(entry.size())
            .ok_or_else(|| anyhow::anyhow!("OSV database size overflow"))?;
        ensure!(
            entry.enclosed_name().is_some()
                && crate::bounds::safe_path(entry.name()?.trim_end_matches('/'))
                && entry.size() <= 16 * 1024 * 1024
                && size <= 1024 * 1024 * 1024,
            "OSV database contains unsafe paths or exceeds expansion limits"
        );
    }
    Ok(())
}

fn package_url(ecosystem: &str, name: &str, version: &str) -> Result<String> {
    let encode =
        |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let (kind, path) = match ecosystem {
        "npm" => (
            "npm",
            name.split('/').map(encode).collect::<Vec<_>>().join("/"),
        ),
        "PyPI" => ("pypi", encode(name)),
        "crates.io" => ("cargo", encode(name)),
        "NuGet" => ("nuget", encode(name)),
        "Maven" => {
            let (group, artifact) = name
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Maven mapping requires group:artifact"))?;
            ("maven", format!("{}/{}", encode(group), encode(artifact)))
        }
        _ => anyhow::bail!("unsupported package ecosystem"),
    };
    Ok(format!("pkg:{kind}/{path}@{}", encode(version)))
}
