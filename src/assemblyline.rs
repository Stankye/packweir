//! Bounded, fail-closed normalization of Assemblyline v4 submission evidence.
//!
//! The platform score is an observation. Approval requires every explicitly pinned
//! service to have completed on the original file and every extracted descendant.
use crate::{
    model::{Outcome, sha256},
    scanner::ScannerOutput,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const MAX_REPORT_BYTES: usize = 1024 * 1024;
pub const MAX_FILES: usize = 256;
pub const MAX_RESULTS: usize = 1024;
const MAX_SECTIONS: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblylinePolicy {
    pub required_services: BTreeMap<String, AssemblylineServicePin>,
    #[serde(default)]
    pub deny_rules: Vec<AssemblylineDenyRule>,
    #[serde(default = "default_result_age")]
    pub max_result_age_seconds: i64,
}

fn default_result_age() -> i64 {
    86400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblylineServicePin {
    pub version: String,
    /// `None` pins the upstream null tool version; it is not a wildcard.
    pub tool_version: Option<String>,
    /// Exact upstream result-key `c` component, without the `c` prefix.
    pub configuration_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblylineDenyRule {
    pub service: String,
    pub heuristic_id: String,
    #[serde(default)]
    pub signature: Option<String>,
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl AssemblylinePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.required_services.is_empty() && self.required_services.len() <= 32,
            "Assemblyline requires 1..=32 explicitly pinned services"
        );
        ensure!(
            (1..=2_592_000).contains(&self.max_result_age_seconds),
            "Assemblyline result age must be between 1 second and 30 days"
        );
        for (name, pin) in &self.required_services {
            ensure!(
                bounded_text(name, 128) && !name.contains(['/', '\\']),
                "invalid Assemblyline service name"
            );
            ensure!(
                bounded_text(&pin.version, 128),
                "invalid Assemblyline service version"
            );
            ensure!(
                pin.tool_version
                    .as_deref()
                    .is_none_or(|v| bounded_text(v, 256)),
                "invalid Assemblyline tool version"
            );
            ensure!(
                !pin.configuration_key.is_empty()
                    && pin.configuration_key.len() <= 32
                    && pin
                        .configuration_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric()),
                "Assemblyline requires an exact result configuration key"
            );
        }
        ensure!(
            self.deny_rules.len() <= 256,
            "too many Assemblyline deny rules"
        );
        let mut rules = BTreeSet::new();
        for rule in &self.deny_rules {
            ensure!(
                self.required_services.contains_key(&rule.service),
                "Assemblyline deny rule service must be explicitly pinned"
            );
            ensure!(
                bounded_text(&rule.heuristic_id, 256)
                    && rule
                        .signature
                        .as_deref()
                        .is_none_or(|v| bounded_text(v, 256)),
                "invalid Assemblyline deny rule"
            );
            ensure!(
                rules.insert((&rule.service, &rule.heuristic_id, &rule.signature)),
                "duplicate Assemblyline deny rule"
            );
        }
        Ok(())
    }
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Assemblyline {field} object missing"))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Assemblyline {field} array missing"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Assemblyline {field} string missing"))
}

fn timestamp(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(text(value, field)?)?.with_timezone(&Utc))
}

fn incomplete(reasons: &mut BTreeSet<String>, reason: impl Into<String>) {
    reasons.insert(reason.into());
}

/// Normalize the actual v4 `submission/full` body plus the separate `submission/tree`
/// envelope. Both inputs must be the authenticated instance's `api_response` values.
/// No child bytes are fetched, transformed, or executed here.
pub fn normalize_at(
    subject: &str,
    submission_id: &str,
    report: &Value,
    tree: &Value,
    policy: &AssemblylinePolicy,
    now: DateTime<Utc>,
) -> Result<ScannerOutput> {
    policy.validate()?;
    ensure!(
        digest(subject),
        "invalid Assemblyline original artifact digest"
    );
    ensure!(
        bounded_text(submission_id, 128),
        "invalid Assemblyline submission identifier"
    );
    let raw = serde_json::to_vec(report)?;
    let raw_tree = serde_json::to_vec(tree)?;
    ensure!(
        raw.len()
            .checked_add(raw_tree.len())
            .is_some_and(|n| n <= MAX_REPORT_BYTES),
        "Assemblyline combined report limit exceeded"
    );
    ensure!(
        text(report, "sid")? == submission_id,
        "Assemblyline submission identifier mismatch"
    );
    let originals = array(report, "files")?;
    ensure!(
        originals.len() == 1 && text(&originals[0], "sha256")? == subject,
        "Assemblyline original artifact digest mismatch"
    );
    let results = object(report, "results")?;
    let errors = object(report, "errors")?;
    let file_infos = object(report, "file_infos")?;
    let report_tree = object(report, "file_tree")?;
    let tree_nodes = object(tree, "tree")?;
    ensure!(
        results.len() <= MAX_RESULTS
            && errors.len() <= MAX_RESULTS
            && file_infos.len() <= MAX_FILES,
        "Assemblyline report record limit exceeded"
    );
    ensure!(
        report_tree == tree_nodes,
        "Assemblyline full report and file tree disagree"
    );
    let mut reasons = BTreeSet::new();
    if text(report, "state")? != "completed" {
        incomplete(&mut reasons, "submission did not complete");
    }
    let params = report
        .get("params")
        .ok_or_else(|| anyhow::anyhow!("Assemblyline submission params missing"))?;
    if params.get("ignore_cache").and_then(Value::as_bool) != Some(false) {
        incomplete(
            &mut reasons,
            "submission did not preserve deterministic result configuration keys",
        );
    }
    let selection = params
        .get("services")
        .ok_or_else(|| anyhow::anyhow!("Assemblyline service selection missing"))?;
    let selected = array(selection, "selected")?;
    let excluded = array(selection, "excluded")?;
    for service in policy.required_services.keys() {
        if !selected.iter().any(|v| v.as_str() == Some(service))
            || excluded.iter().any(|v| v.as_str() == Some(service))
        {
            incomplete(
                &mut reasons,
                format!("required service {service} was not explicitly selected or was excluded"),
            );
        }
    }
    for field in [
        "missing_result_keys",
        "missing_error_keys",
        "missing_file_keys",
    ] {
        if !array(report, field)?.is_empty() {
            incomplete(&mut reasons, format!("{field} is nonempty"));
        }
    }
    for field in ["partial", "filtered"] {
        let flag = tree
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("Assemblyline tree {field} flag missing"))?;
        if flag {
            incomplete(&mut reasons, format!("file tree is {field}"));
        }
    }
    if !errors.is_empty() || report.get("error_count").and_then(Value::as_u64) != Some(0) {
        incomplete(
            &mut reasons,
            "submission contains service errors or warnings",
        );
    }

    // Flatten iteratively: untrusted trees cannot consume the Rust call stack.
    ensure!(
        tree_nodes.len() == 1 && tree_nodes.contains_key(subject),
        "Assemblyline file tree original artifact mismatch"
    );
    let mut queue: VecDeque<_> = tree_nodes
        .iter()
        .map(|(sha, node)| (None::<String>, sha, node, 0usize))
        .collect();
    let mut files = BTreeSet::new();
    let mut tree_edges = BTreeSet::new();
    let mut tree_records = 0usize;
    while let Some((parent, sha, node, depth)) = queue.pop_front() {
        tree_records += 1;
        ensure!(
            tree_records <= MAX_RESULTS && depth <= 64,
            "Assemblyline file tree limit exceeded"
        );
        ensure!(
            digest(sha) && text(node, "sha256")? == sha,
            "Assemblyline file tree digest mismatch"
        );
        if node.get("truncated").and_then(Value::as_bool) != Some(false) {
            incomplete(
                &mut reasons,
                "file tree contains truncated or unmarked nodes",
            );
        }
        if let Some(parent) = parent {
            tree_edges.insert((parent, sha.clone()));
        }
        files.insert(sha.clone());
        ensure!(
            files.len() <= MAX_FILES,
            "Assemblyline file tree file limit exceeded"
        );
        if !file_infos.contains_key(sha) {
            incomplete(&mut reasons, format!("file metadata missing for {sha}"));
        } else if file_infos[sha]
            .get("sha256")
            .and_then(Value::as_str)
            .is_some_and(|claimed| claimed != sha)
        {
            anyhow::bail!("Assemblyline file metadata digest mismatch");
        }
        for (child, child_node) in object(node, "children")? {
            queue.push_back((Some(sha.clone()), child, child_node, depth + 1));
        }
    }
    for sha in file_infos.keys() {
        ensure!(
            files.contains(sha),
            "Assemblyline file metadata is unrelated to original artifact"
        );
    }

    let mut observed = BTreeMap::<(String, String), Vec<Value>>::new();
    let mut extracted_edges = BTreeSet::new();
    let mut extracted = Vec::new();
    let mut supplementary = Vec::new();
    let mut service_errors = Vec::new();
    let mut error_keys = BTreeMap::<(String, String), Vec<String>>::new();
    let mut findings = Vec::new();
    let mut matched_denials = Vec::new();
    let mut section_count = 0usize;
    let mut valid_until: Option<DateTime<Utc>> = None;
    for (key, error) in errors {
        let sha = text(error, "sha256")?;
        ensure!(
            digest(sha) && files.contains(sha),
            "Assemblyline service error is unrelated to original artifact"
        );
        let response = error
            .get("response")
            .ok_or_else(|| anyhow::anyhow!("Assemblyline error response missing"))?;
        let service = text(response, "service_name")?;
        let status = text(response, "status")?;
        ensure!(
            ["FAIL_RECOVERABLE", "FAIL_NONRECOVERABLE"].contains(&status),
            "unknown Assemblyline service error status"
        );
        let version = text(response, "service_version")?;
        let expected_prefix = format!(
            "{}.{}.v{}.c",
            sha,
            service.replace('.', "_"),
            version.replace('.', "_")
        );
        ensure!(
            key.strip_prefix(&expected_prefix).is_some_and(|suffix| {
                suffix.split_once(".e").is_some_and(|(config, code)| {
                    !config.is_empty()
                        && config.bytes().all(|b| b.is_ascii_alphanumeric())
                        && !code.is_empty()
                        && code.bytes().all(|b| b.is_ascii_digit())
                })
            }),
            "Assemblyline service error key binding mismatch"
        );
        service_errors.push(json!({"sha256":sha,"service":service,"service_version":version,
            "service_tool_version":response.get("service_tool_version"),"error_key":key,
            "type":text(error,"type")?,"severity":text(error,"severity")?,"status":status,"message":text(response,"message")?}));
        error_keys
            .entry((sha.to_owned(), service.to_owned()))
            .or_default()
            .push(key.clone());
    }
    for (key, result) in results {
        let sha = text(result, "sha256")?;
        ensure!(
            digest(sha) && files.contains(sha),
            "Assemblyline result is unrelated to original artifact"
        );
        let response = result
            .get("response")
            .ok_or_else(|| anyhow::anyhow!("Assemblyline response missing"))?;
        let service = text(response, "service_name")?;
        let version = text(response, "service_version")?;
        ensure!(
            bounded_text(service, 128) && bounded_text(version, 128),
            "invalid Assemblyline result service identity"
        );
        let mut key_parts = key.split('.');
        let key_sha = key_parts.next();
        let key_service = key_parts.next();
        let key_version = key_parts.next();
        let key_config = key_parts.next().and_then(|v| v.strip_prefix('c'));
        let suffix = key_parts.next();
        ensure!(
            key_parts.next().is_none()
                && key_sha == Some(sha)
                && key_service == Some(service.replace('.', "_").as_str())
                && key_config
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
                && (suffix.is_none() || suffix == Some("e")),
            "invalid Assemblyline result key binding"
        );
        let empty = suffix == Some("e");
        // Empty cached results are synthesized by the UI with a fresh `created`
        // timestamp and no tool revision. They cannot establish pinned freshness.
        if !empty {
            ensure!(
                key_version == Some(format!("v{}", version.replace('.', "_")).as_str()),
                "Assemblyline result key version mismatch"
            );
        }
        let created = timestamp(result, "created")?;
        let expiry = created
            .checked_add_signed(Duration::seconds(policy.max_result_age_seconds))
            .ok_or_else(|| anyhow::anyhow!("Assemblyline result expiry overflow"))?;
        let mut fresh = created <= now && expiry > now;
        let milestones = response
            .get("milestones")
            .ok_or_else(|| anyhow::anyhow!("Assemblyline service milestones missing"))?;
        let started = timestamp(milestones, "service_started")?;
        let completed = timestamp(milestones, "service_completed")?;
        fresh &= started <= completed && completed <= now;
        let mut effective_expiry = expiry;
        if !result.get("expiry_ts").is_none_or(Value::is_null) {
            let upstream_expiry = timestamp(result, "expiry_ts")?;
            fresh &= upstream_expiry > now;
            effective_expiry = effective_expiry.min(upstream_expiry);
        }
        let partial = result
            .get("partial")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("Assemblyline result partial flag missing"))?;
        let drop_file = result
            .get("drop_file")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("Assemblyline result drop_file flag missing"))?;
        if partial || drop_file || empty || !fresh {
            incomplete(
                &mut reasons,
                format!("service {service} on {sha} is partial, filtered, empty-cached, or stale"),
            );
        }
        let mut pin_matched = false;
        if let Some(pin) = policy.required_services.get(service) {
            let tool = response.get("service_tool_version");
            let tool_matches = match &pin.tool_version {
                Some(expected) => tool.and_then(Value::as_str) == Some(expected.as_str()),
                None => tool.is_some_and(Value::is_null),
            };
            pin_matched = version == pin.version
                && key_config == Some(pin.configuration_key.as_str())
                && tool_matches;
            if !pin_matched {
                incomplete(
                    &mut reasons,
                    format!("service {service} version, tool, or configuration differs from pin"),
                );
            }
        }
        valid_until =
            Some(valid_until.map_or(effective_expiry, |previous| previous.min(effective_expiry)));
        let mut result_extracted = BTreeSet::new();
        for child in array(response, "extracted")? {
            let child_sha = text(child, "sha256")?;
            ensure!(
                digest(child_sha) && files.contains(child_sha),
                "Assemblyline extracted file digest is absent from tree"
            );
            ensure!(
                result_extracted.insert(child_sha),
                "duplicate Assemblyline extracted child in result"
            );
            extracted_edges.insert((sha.to_owned(), child_sha.to_owned()));
            extracted.push(json!({"parent_sha256":sha,"child_sha256":child_sha,"service":service,"result_key":key,"file":child}));
        }
        for child in array(response, "supplementary")? {
            ensure!(
                digest(text(child, "sha256")?),
                "invalid Assemblyline supplementary file digest"
            );
            supplementary
                .push(json!({"parent_sha256":sha,"service":service,"result_key":key,"file":child}));
        }
        let body = result
            .get("result")
            .ok_or_else(|| anyhow::anyhow!("Assemblyline result body missing"))?;
        let score = body
            .get("score")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("Assemblyline result score missing"))?;
        let sections = array(body, "sections")?;
        section_count += sections.len();
        ensure!(
            section_count <= MAX_SECTIONS,
            "Assemblyline result section limit exceeded"
        );
        if score != 0
            && !sections
                .iter()
                .any(|section| section.get("heuristic").is_some_and(|v| !v.is_null()))
        {
            incomplete(
                &mut reasons,
                format!("service {service} has an unexplained score"),
            );
        }
        for (index, section) in sections.iter().enumerate() {
            let Some(heuristic) = section.get("heuristic").filter(|v| !v.is_null()) else {
                continue;
            };
            let heuristic_id = text(heuristic, "heur_id")?;
            let signatures = array(heuristic, "signature")?;
            let finding = json!({"sha256":sha,"service":service,"service_version":version,
                "service_tool_version":response.get("service_tool_version"),"configuration_key":key_config,
                "result_key":key,"section":index,"heuristic":heuristic,"title":section.get("title_text")});
            let mut matching_rules = Vec::new();
            for (rule_index, rule) in policy.deny_rules.iter().enumerate() {
                if rule.service == service
                    && rule.heuristic_id == heuristic_id
                    && rule.signature.as_ref().is_none_or(|signature| {
                        signatures.iter().any(|s| {
                            s.get("name").and_then(Value::as_str) == Some(signature.as_str())
                        })
                    })
                    && pin_matched
                    && fresh
                    && !partial
                    && !drop_file
                    && !empty
                {
                    matching_rules.push(rule_index);
                }
            }
            if !matching_rules.is_empty() {
                matched_denials.push(
                    json!({"rule_indices":matching_rules,"finding_index":findings.len(),
                    "result_key":key,"sha256":sha,"service":service,"heuristic_id":heuristic_id}),
                );
            }
            findings.push(finding);
        }
        observed.entry((sha.to_owned(), service.to_owned())).or_default().push(json!({
            "result_key":key,"service_version":version,"service_tool_version":response.get("service_tool_version"),
            "configuration_key":key_config,"pin_matched":pin_matched,"fresh":fresh,"partial":partial,
            "drop_file":drop_file,"empty_cached":empty,"created":created,"valid_until":effective_expiry,"score":score}));
    }
    ensure!(
        tree_edges == extracted_edges,
        "Assemblyline extracted relationships and file tree disagree"
    );
    let platform_score = report
        .get("max_score")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("Assemblyline platform score missing"))?;
    if platform_score != 0 && findings.is_empty() {
        incomplete(
            &mut reasons,
            "platform score has no attributable heuristic finding",
        );
    }
    let mut coverage = Vec::new();
    for sha in &files {
        for service in policy.required_services.keys() {
            let records = observed.get(&(sha.clone(), service.clone()));
            let service_error_keys = error_keys.get(&(sha.clone(), service.clone()));
            let status = if service_error_keys.is_some() {
                "service_error"
            } else {
                match records {
                    None => {
                        incomplete(
                            &mut reasons,
                            format!("required service {service} missing or skipped on {sha}"),
                        );
                        "missing_or_skipped"
                    }
                    Some(records) if records.len() != 1 => {
                        incomplete(
                            &mut reasons,
                            format!("required service {service} has duplicate results on {sha}"),
                        );
                        "ambiguous"
                    }
                    Some(records) => {
                        let record = &records[0];
                        if record["pin_matched"] == true
                            && record["fresh"] == true
                            && record["partial"] == false
                            && record["drop_file"] == false
                            && record["empty_cached"] == false
                        {
                            "complete"
                        } else {
                            "incomplete"
                        }
                    }
                }
            };
            coverage
                .push(json!({"sha256":sha,"service":service,"status":status,"results":records,"error_keys":service_error_keys}));
        }
    }
    // Coverage/identity uncertainty takes precedence over any heuristic mapping.
    let outcome = if !reasons.is_empty() {
        Outcome::Inconclusive
    } else if !matched_denials.is_empty() {
        Outcome::Fail
    } else if !findings.is_empty() {
        Outcome::Inconclusive
    } else {
        Outcome::Pass
    };
    let reason = match outcome {
        Outcome::Pass => {
            "all pinned required services completed on the original artifact and extracted descendants without heuristic findings"
        }
        Outcome::Fail => {
            "an explicitly configured deny rule matched an attributable service finding"
        }
        _ if !reasons.is_empty() => {
            "incomplete, stale, or unpinned analysis requires investigation"
        }
        _ => "heuristic observations require investigation unless explicitly mapped to a deny rule",
    };
    let output = ScannerOutput {
        outcome,
        details: json!({"verification_scope":"assemblyline_services","subject":subject,"submission_id":submission_id,
            "reason":reason,"coverage_complete":reasons.is_empty(),"coverage_reasons":reasons,
            "required_services":policy.required_services,"policy":policy,"policy_digest":sha256(&serde_json::to_vec(policy)?),
            "max_result_age_seconds":policy.max_result_age_seconds,"platform_score":platform_score,"files":files,"coverage":coverage,
            "findings":findings,"matched_deny_rules":matched_denials,"service_errors":service_errors,"extracted":extracted,"supplementary":supplementary,
            "raw_report_sha256":sha256(&raw),"raw_tree_sha256":sha256(&raw_tree),"raw_report":report,"raw_tree":tree}),
        references: Vec::new(),
        valid_until,
    };
    ensure!(
        serde_json::to_vec(&output)?.len() <= 4 * MAX_REPORT_BYTES,
        "Assemblyline normalized evidence limit exceeded"
    );
    Ok(output)
}
