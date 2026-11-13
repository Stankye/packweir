//! Bind provider-neutral binary observations to authenticated service results and
//! independently inspected original/embedded input bytes.
use crate::{
    analysis_outputs::OutputDraft,
    binary_analysis::{self, BinaryAnalysisPolicy},
    inventory,
    model::{Outcome, sha256},
    scanner::ScannerOutput,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

pub const SECTION_TITLE: &str = "Packweir binary analysis manifest v1";

fn time(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("binary service timestamp missing"))?
        .parse()
        .map_err(Into::into)
}

pub async fn reconcile(
    policy: &BinaryAnalysisPolicy,
    filename: &str,
    bytes: Arc<[u8]>,
    output: &mut ScannerOutput,
    max_age_seconds: i64,
) -> Result<()> {
    reconcile_with_empty_policy(policy, filename, bytes, output, max_age_seconds, false).await
}

pub async fn reconcile_with_empty_policy(
    policy: &BinaryAnalysisPolicy,
    filename: &str,
    bytes: Arc<[u8]>,
    output: &mut ScannerOutput,
    max_age_seconds: i64,
    allow_empty_files: bool,
) -> Result<()> {
    policy.validate()?;
    let expected_subject = sha256(&bytes);
    ensure!(
        output.details["subject"] == expected_subject,
        "binary analysis original subject differs"
    );
    let filename = filename.to_owned();
    let kinds = policy.candidate_kinds.clone();
    let (inventory, mut inputs) = tokio::task::spawn_blocking(move || {
        inventory::inspect_analysis_inputs(&filename, &bytes, inventory::Limits::default(), &kinds)
    })
    .await??;
    let mut paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut observed = BTreeMap::new();
    for file in &inventory.files {
        observed.insert(file.sha256.clone(), (file.size, file.kind.clone()));
        if inputs.contains_key(&file.sha256) {
            let names = paths.entry(file.sha256.clone()).or_default();
            ensure!(names.len() < 256, "too many binary input aliases");
            names.push(file.path.clone());
        }
    }
    let initial_inputs = inputs.len();
    let raw = output.details["raw_report"].clone();
    let results = raw["results"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("binary result map missing"))?;
    let mut reports = BTreeMap::new();
    for (key, result) in results
        .iter()
        .filter(|(_, r)| r["response"]["service_name"] == policy.service)
    {
        let sections = result["result"]["sections"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("binary service sections missing"))?;
        let bodies: Vec<_> = sections
            .iter()
            .filter(|s| s["title_text"] == SECTION_TITLE)
            .collect();
        if bodies.is_empty() {
            continue;
        }
        ensure!(bodies.len() == 1, "ambiguous binary manifest section");
        let body = bodies[0]["body"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("binary manifest body missing"))?;
        let manifest = binary_analysis::parse_manifest(body)?;
        let input = result["sha256"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("binary result input missing"))?;
        ensure!(
            manifest["input"]["sha256"] == input,
            "binary manifest/result input differs"
        );
        ensure!(
            reports
                .insert(input.to_owned(), (key, result, manifest))
                .is_none(),
            "duplicate binary service manifests"
        );
    }
    let mut queue: VecDeque<String> = inputs.keys().cloned().collect();
    let mut processed = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut manifests = Vec::new();
    let mut reasons = BTreeSet::new();
    let mut total_verified_bytes: u64 = inputs.values().map(|b| b.len() as u64).sum();
    let remote_files: BTreeSet<String> = output.details["files"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("normalized remote file graph missing"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("invalid normalized file digest"))
        })
        .collect::<Result<_>>()?;
    let mut decoded_inventories: BTreeMap<String, crate::model::Inventory> = BTreeMap::new();
    let mut decoded_nodes = BTreeSet::new();
    let mut decoded_missing = BTreeSet::new();
    let mut decoded_empty = BTreeSet::new();
    let mut native_depth: BTreeMap<String, usize> =
        inputs.keys().map(|sha| (sha.clone(), 0)).collect();
    loop {
        let next = queue.pop_front().or_else(|| reports.keys().next().cloned());
        let Some(input_sha) = next else { break };
        if !processed.insert(input_sha.clone()) {
            continue;
        }
        ensure!(
            processed.len() <= 256,
            "binary analysis input graph exceeds limit"
        );
        let Some((key, result, manifest)) = reports.remove(&input_sha) else {
            missing.insert(input_sha);
            continue;
        };
        // Server classification may have marked Ghidra not_applicable. Local
        // native bytes still require a uniquely attributed, pinned execution.
        // Never let that classification waive identity or freshness checks.
        let coverage = output.details["coverage"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("normalized binary service coverage missing"))?;
        let pairs: Vec<_> = coverage
            .iter()
            .filter(|v| v["sha256"] == input_sha && v["service"] == policy.service)
            .collect();
        ensure!(
            pairs.len() == 1,
            "ambiguous normalized binary service coverage"
        );
        let records = pairs[0]["results"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("normalized binary execution record missing"))?;
        ensure!(
            records.len() == 1 && records[0]["result_key"] == *key,
            "binary execution record differs from the selected raw result"
        );
        let record = &records[0];
        ensure!(
            record["pin_matched"] == true
                && record["fresh"] == true
                && record["empty_cached"] == false,
            "binary execution is stale, empty-cached, or unpinned"
        );
        let valid_until = time(record, "valid_until")?;
        ensure!(valid_until > Utc::now(), "binary execution has expired");
        output.valid_until = Some(
            output
                .valid_until
                .map_or(valid_until, |old| old.min(valid_until)),
        );
        let service_complete = record["partial"] == false && record["drop_file"] == false;
        if !service_complete {
            reasons.insert(format!(
                "binary service execution on {input_sha} is partial or dropped"
            ));
        }
        let local = inputs.get(&input_sha);
        let size = observed
            .get(&input_sha)
            .map(|(size, _)| *size)
            .or_else(|| local.map(|b| b.len() as u64))
            .or_else(|| raw["file_infos"][&input_sha]["size"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("binary input size missing"))?;
        let kind = observed
            .get(&input_sha)
            .map(|(_, kind)| kind.as_str())
            .or_else(|| local.map(|b| inventory::kind(b)))
            .or_else(|| manifest["input"]["kind"].as_str())
            .ok_or_else(|| anyhow::anyhow!("binary input kind missing"))?;
        let validated = binary_analysis::validate_manifest(
            policy,
            &input_sha,
            size,
            kind,
            local.map(Vec::as_slice),
            &manifest,
            Utc::now(),
        )?;
        let milestone = &result["response"]["milestones"];
        let analysis = &manifest["analysis"];
        let started = time(analysis, "started_at")?;
        let completed = time(analysis, "completed_at")?;
        ensure!(
            time(milestone, "service_started")? <= started
                && completed <= time(milestone, "service_completed")?,
            "binary report execution falls outside its service execution"
        );
        let expiry = completed
            .checked_add_signed(Duration::seconds(max_age_seconds))
            .ok_or_else(|| anyhow::anyhow!("binary report expiry overflow"))?;
        output.valid_until = Some(output.valid_until.map_or(expiry, |old| old.min(expiry)));
        if expiry <= Utc::now() {
            reasons.insert(format!("binary analysis on {input_sha} is stale"));
        }
        if !validated.complete {
            reasons.insert(format!("binary analysis on {input_sha} is incomplete"));
        }
        let input_paths = paths
            .get(&input_sha)
            .cloned()
            .unwrap_or_else(|| vec![format!("remote-derived/{input_sha}")]);
        let mut details = validated.details;
        details["service_validation"] = json!({"result_key":key,"execution":record,
            "complete":service_complete,"applicability_basis":"independent_native_input_or_report"});
        details["logical_paths"] = json!(input_paths);
        let source_verified = validated.input_bytes_verified;
        for derived in validated
            .outputs
            .iter()
            .filter(|o| o.kind == "decoded_bytes")
        {
            // The typed manifest proves the derivation. The service's actual
            // SDK result must also attribute the same bytes as its child.
            let extracted = result["response"]["extracted"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("binary extracted references missing"))?;
            ensure!(
                extracted.iter().any(|e| e["sha256"] == derived.sha256),
                "decoded output has no attributed extracted-child edge"
            );
            if !source_verified {
                continue;
            }
            let depth = native_depth.get(&input_sha).copied().unwrap_or(0) + 1;
            ensure!(depth <= 64, "derived binary transformation depth exceeded");
            if !decoded_inventories.contains_key(&derived.sha256) {
                let remaining = (64_u64 * 1024 * 1024)
                    .checked_sub(total_verified_bytes)
                    .ok_or_else(|| anyhow::anyhow!("derived inspection byte budget exceeded"))?;
                ensure!(
                    derived.size <= remaining,
                    "derived inspection byte budget exceeded"
                );
                let content = derived.bytes.clone();
                let kinds = policy.candidate_kinds.clone();
                let limits = inventory::Limits {
                    expanded_bytes: remaining - derived.size,
                    files: 256,
                    depth: 3,
                };
                let (decoded, native) = tokio::task::spawn_blocking(move || {
                    inventory::inspect_analysis_inputs("decoded", &content, limits, &kinds)
                })
                .await??;
                let work = decoded.files.iter().try_fold(0u64, |total, file| {
                    total
                        .checked_add(file.size)
                        .ok_or_else(|| anyhow::anyhow!("derived inspection byte count overflow"))
                })?;
                total_verified_bytes = total_verified_bytes
                    .checked_add(work)
                    .ok_or_else(|| anyhow::anyhow!("derived inspection byte count overflow"))?;
                ensure!(
                    total_verified_bytes <= 64 * 1024 * 1024,
                    "derived inspection byte budget exceeded"
                );
                for file in &decoded.files {
                    decoded_nodes.insert(file.sha256.clone());
                    ensure!(
                        decoded_nodes.len() <= 256,
                        "derived inspection file count exceeded"
                    );
                    if let Some((size, kind)) =
                        observed.insert(file.sha256.clone(), (file.size, file.kind.clone()))
                    {
                        ensure!(
                            size == file.size && kind == file.kind,
                            "verified input inventories disagree"
                        );
                    }
                    if !remote_files.contains(&file.sha256) {
                        if allow_empty_files && file.size == 0 && file.sha256 == sha256(b"") {
                            decoded_empty.insert(file.sha256.clone());
                        } else {
                            decoded_missing.insert(file.sha256.clone());
                        }
                    }
                }
                for (sha, content) in native {
                    if !inputs.contains_key(&sha) {
                        ensure!(inputs.len() < 256, "derived native input count exceeded");
                        native_depth.insert(sha.clone(), depth);
                        inputs.insert(sha.clone(), content);
                        queue.push_back(sha);
                    }
                }
                decoded_inventories.insert(derived.sha256.clone(), decoded);
            }
            for file in &decoded_inventories[&derived.sha256].files {
                if !inputs.contains_key(&file.sha256) {
                    continue;
                }
                let aliases = paths.entry(file.sha256.clone()).or_default();
                let suffix = file
                    .path
                    .strip_prefix("decoded")
                    .ok_or_else(|| anyhow::anyhow!("decoded inventory path differs"))?;
                let path = format!("derived/{input_sha}/{}{suffix}", derived.sha256);
                if !aliases.contains(&path) {
                    ensure!(aliases.len() < 256, "too many derived binary input aliases");
                    aliases.push(path);
                }
            }
        }
        manifests.push(details);
    }
    if !missing.is_empty() {
        reasons.insert(
            "binary service omitted locally observed or verified derived native inputs".into(),
        );
    }
    if !decoded_missing.is_empty() {
        reasons.insert(
            "remote graph omitted files observed in independently verified decoded content".into(),
        );
    }
    // A child may sort before a parent whose later derivation supplies another
    // path to the same bytes. Seal aliases after the complete graph is visited.
    for entry in &mut manifests {
        if let Some(input) = entry["input_sha256"].as_str()
            && let Some(aliases) = paths.get(input)
        {
            let aliases: BTreeSet<_> = aliases.iter().collect();
            entry["logical_paths"] = json!(aliases);
        }
    }
    let complete = reasons.is_empty();
    output.details["binary_analysis"] = json!({"purpose":"binary_observations","approval_scope":"declared analysis coverage only",
        "service":policy.service,"identity_sha256":policy.identity_sha256,"local_native_inputs":initial_inputs,
        "processed_inputs":processed.len(),"missing_inputs":missing,"coverage_complete":complete,"reasons":reasons,
        "decoded_inventory":{"files":decoded_nodes,"missing_files":decoded_missing,"known_empty_content":decoded_empty,
            "basis":"independently_verified_decoded_bytes","inspection_bytes":total_verified_bytes},
        "manifests":manifests});
    if !complete {
        output.outcome = Outcome::Inconclusive;
        output.details["coverage_complete"] = json!(false);
        let coverage_reasons = output.details["coverage_reasons"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("remote coverage reasons missing"))?;
        let reason = json!("binary analysis observations or derivation coverage are incomplete");
        if !coverage_reasons.contains(&reason) {
            coverage_reasons.push(reason);
        }
    }
    ensure!(
        serde_json::to_vec(&output.details)?.len() <= 4 * 1024 * 1024,
        "binary analysis evidence exceeds limit"
    );
    Ok(())
}

pub fn drafts(check_name: &str, output: &ScannerOutput) -> Result<Vec<OutputDraft>> {
    let Some(manifests) = output.details["binary_analysis"]["manifests"].as_array() else {
        return Ok(vec![]);
    };
    let mut outputs = Vec::new();
    for entry in manifests {
        let paths: Vec<String> = serde_json::from_value(entry["logical_paths"].clone())?;
        outputs.extend(OutputDraft::from_manifest(
            check_name,
            &entry["manifest"],
            &paths,
        )?);
        ensure!(outputs.len() <= 256, "derived output count exceeds limit");
    }
    Ok(outputs)
}
