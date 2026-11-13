//! Controlled reconciliation fixtures; actual Ghidra qualification is separate.
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use packweir::{
    assemblyline::{AssemblylinePolicy, AssemblylineServicePin, normalize_at},
    binary_analysis::{BinaryAnalysisPolicy, default_candidate_kinds, producer_identity_sha256},
    binary_remote::{self, SECTION_TITLE},
    model::{Outcome, sha256},
    scanner::ScannerOutput,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    sync::Arc,
};

const SERVICE: &str = "ControlledBinaryFixture";
const CHECK: &str = "controlled_binary_observation";

fn producer() -> Value {
    let mut value = json!({"engine":"ControlledFixture","engine_version":"1",
        "engine_archive_sha256":sha256(b"fixture-engine"),"jdk_version":"fixture-only",
        "jdk_archive_sha256":sha256(b"fixture-jdk"),"decompiler_sha256":sha256(b"fixture-decompiler"),
        "scripts_sha256":sha256(b"fixture-scripts"),"profile_sha256":sha256(b"fixture-profile"),
        "driver_sha256":sha256(b"fixture-driver")});
    value["identity_sha256"] = json!(producer_identity_sha256(&value).unwrap());
    value
}
fn policy() -> BinaryAnalysisPolicy {
    BinaryAnalysisPolicy {
        service: SERVICE.into(),
        identity_sha256: producer()["identity_sha256"].as_str().unwrap().into(),
        required_capabilities: vec!["decompile".into(), "pcode".into(), "decode_xor".into()],
        informational_warnings: vec![],
        candidate_kinds: default_candidate_kinds(),
    }
}
fn native() -> Vec<u8> {
    b"\x7fELFcontrolled fixture, never executed".to_vec()
}
fn manifest(bytes: &[u8], decoded: Option<(&[u8], usize)>) -> Value {
    let sha = sha256(bytes);
    let now = Utc::now();
    let text = |kind: &str, media: &str, operation: &str, data: &[u8]| {
        json!({"kind":kind,"media_type":media,"sha256":sha256(data),
        "size":data.len(),"data_base64":STANDARD.encode(data),"derivation":{"operation":operation,"version":"1",
        "input_sha256":sha,"parameters":{"function_entry":"controlled-entry"},"source_spans":[{"offset":0,"length":bytes.len(),"sha256":sha}]}})
    };
    let mut outputs = vec![
        text(
            "decompiled_c",
            "text/x-c",
            "ghidra.decompile",
            b"/* controlled fixture */ void observed(void) {}\n",
        ),
        text(
            "pcode",
            "text/plain",
            "ghidra.pcode",
            b"controlled fixture INT_XOR\n",
        ),
    ];
    if let Some((decoded, offset)) = decoded {
        outputs.push(json!({"kind":"decoded_bytes","media_type":"application/octet-stream","sha256":sha256(decoded),
            "size":decoded.len(),"data_base64":STANDARD.encode(decoded),"derivation":{"operation":"xor.decode","version":"1",
            "input_sha256":sha,"parameters":{"key_hex":"5a"},"source_spans":[{"offset":offset,"length":decoded.len(),
                "sha256":sha256(&bytes[offset..offset+decoded.len()])}]}}));
    }
    json!({"schema_version":"packweir.binary-analysis.v1","input":{"sha256":sha,"size":bytes.len(),"kind":packweir::inventory::kind(bytes)},
        "producer":producer(),"analysis":{"started_at":(now-Duration::seconds(12)).to_rfc3339(),
            "completed_at":(now-Duration::seconds(10)).to_rfc3339(),"status":"complete","timed_out":false,"errors":[],"warnings":[],
            "language_id":"fixture:LE:64:default","compiler_spec_id":"fixture","requested_capabilities":["decompile","pcode","decode_xor"],
            "capabilities":{"decompile":"complete","pcode":"complete","decode_xor":"complete"},
            "functions_total":1,"functions_decompiled":1,"functions_failed":0,"export_truncated":false,"log_sha256":sha256(b"fixture-log")},
        "observations":[{"kind":"note","name":"scope","value":"Controlled reconciliation fixture, no actual tool execution"}],"outputs":outputs})
}
fn output(bytes: &[u8]) -> ScannerOutput {
    ScannerOutput {
        outcome: Outcome::Pass,
        details: json!({"subject":sha256(bytes),"coverage_complete":true,"coverage_reasons":[],
            "coverage":[],"files":[sha256(bytes)],"raw_report":{"results":{},"file_infos":{}}}),
        references: vec![],
        valid_until: Some(Utc::now() + Duration::hours(1)),
    }
}
fn add_report(output: &mut ScannerOutput, manifest: Value, extracted: &[String]) -> String {
    let sha = manifest["input"]["sha256"].as_str().unwrap().to_owned();
    let key = format!("{sha}.{SERVICE}.vfixture.cfixture");
    output.details["raw_report"]["file_infos"][&sha] =
        json!({"sha256":sha,"size":manifest["input"]["size"],"type":"text/plain"});
    let started = manifest["analysis"]["started_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap()
        - Duration::seconds(1);
    let completed = manifest["analysis"]["completed_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap()
        + Duration::seconds(1);
    output.details["raw_report"]["results"][&key] = json!({"sha256":sha,"response":{"service_name":SERVICE,
        "service_tool_version":"controlled fixture only","milestones":{"service_started":started.to_rfc3339(),"service_completed":completed.to_rfc3339()},
        "extracted":extracted.iter().map(|sha|json!({"sha256":sha,"parent_relation":"EXTRACTED"})).collect::<Vec<_>>()},
        "result":{"sections":[{"title_text":SECTION_TITLE,"body":serde_json::to_string(&manifest).unwrap()}]}});
    output.details["coverage"].as_array_mut().unwrap().push(json!({"sha256":sha,"service":SERVICE,
        "applicable":false,"status":"not_applicable","results":[{"result_key":key,"pin_matched":true,
            "fresh":true,"partial":false,"drop_file":false,"empty_cached":false,
            "valid_until":(Utc::now()+Duration::hours(2)).to_rfc3339()}]}));
    for digest in std::iter::once(&sha).chain(extracted) {
        let files = output.details["files"].as_array_mut().unwrap();
        if !files.iter().any(|file| file == digest) {
            files.push(json!(digest));
        }
    }
    key
}
async fn reconcile(filename: &str, bytes: &[u8], output: &mut ScannerOutput) -> anyhow::Result<()> {
    binary_remote::reconcile(&policy(), filename, Arc::from(bytes), output, 3600).await
}
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[tokio::test]
async fn locally_observed_native_inputs_require_reports_despite_remote_text_classification() {
    let bytes = native();
    let mut result = output(&bytes);
    result.details["raw_report"]["file_infos"][sha256(&bytes)] =
        json!({"sha256":sha256(&bytes),"size":bytes.len(),"type":"text/plain"});
    reconcile("misclassified.txt", &bytes, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    assert_eq!(result.details["binary_analysis"]["local_native_inputs"], 1);
    assert_eq!(
        result.details["binary_analysis"]["missing_inputs"],
        json!([sha256(&bytes)])
    );
    assert_eq!(result.details["coverage_complete"], false);
    assert!(binary_remote::drafts(CHECK, &result).unwrap().is_empty());

    let bundle = archive(&[("a.so", &bytes), ("README", b"plain text")]);
    let mut result = output(&bundle);
    reconcile("wheel.whl", &bundle, &mut result).await.unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    assert_eq!(
        result.details["binary_analysis"]["missing_inputs"],
        json!([sha256(&bytes)])
    );
}

#[tokio::test]
async fn nonnative_input_does_not_invent_a_service_execution_or_derived_product() {
    let bytes = b"ordinary text package with no native candidate";
    let mut result = output(bytes);
    reconcile("README.txt", bytes, &mut result).await.unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["binary_analysis"]["local_native_inputs"], 0);
    assert_eq!(result.details["binary_analysis"]["processed_inputs"], 0);
    assert_eq!(result.details["binary_analysis"]["manifests"], json!([]));
    assert!(
        result.details["raw_report"]["results"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(binary_remote::drafts(CHECK, &result).unwrap().is_empty());
}

#[tokio::test]
async fn valid_report_retains_full_manifest_real_input_binding_and_inner_expiry() {
    let bytes = native();
    let report = manifest(&bytes, None);
    let completed = report["analysis"]["completed_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    let mut result = output(&bytes);
    add_report(&mut result, report.clone(), &[]);
    reconcile("controlled.elf", &bytes, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    let entry = &result.details["binary_analysis"]["manifests"][0];
    assert_eq!(entry["manifest"], report);
    assert_eq!(
        entry["manifest_sha256"],
        sha256(&serde_json::to_vec(&report).unwrap())
    );
    assert_eq!(entry["validation"]["input_bytes_verified"], true);
    assert_eq!(
        result.valid_until,
        Some(completed + Duration::seconds(3600))
    );
    let drafts = binary_remote::drafts(CHECK, &result).unwrap();
    assert_eq!(drafts.len(), 2);
    assert!(drafts.iter().all(|draft| draft.check_name == CHECK));
    assert!(entry.get("malware_safe").is_none());
}

#[tokio::test]
async fn ambiguous_sections_duplicate_reports_and_result_or_subject_substitution_fail() {
    let bytes = native();
    let report = manifest(&bytes, None);
    for case in [
        "duplicate_section",
        "duplicate_report",
        "result_input",
        "manifest_input",
        "typed_sha",
        "subject",
        "producer_pin",
    ] {
        let mut result = output(&bytes);
        let key = add_report(&mut result, report.clone(), &[]);
        match case {
            "duplicate_section" => {
                let section =
                    result.details["raw_report"]["results"][&key]["result"]["sections"][0].clone();
                result.details["raw_report"]["results"][&key]["result"]["sections"]
                    .as_array_mut()
                    .unwrap()
                    .push(section);
            }
            "duplicate_report" => {
                result.details["raw_report"]["results"]["second-copy"] =
                    result.details["raw_report"]["results"][&key].clone()
            }
            "result_input" => {
                result.details["raw_report"]["results"][&key]["sha256"] =
                    json!(sha256(b"another input"))
            }
            "manifest_input" | "typed_sha" | "producer_pin" => {
                let mut changed = report.clone();
                if case == "producer_pin" {
                    changed["producer"]["driver_sha256"] = json!(sha256(b"another driver"));
                    changed["producer"]["identity_sha256"] =
                        json!(producer_identity_sha256(&changed["producer"]).unwrap());
                } else {
                    changed["input"]["sha256"] = json!(if case == "typed_sha" {
                        "A".repeat(64)
                    } else {
                        sha256(b"different manifest input")
                    });
                }
                result.details["raw_report"]["results"][&key]["result"]["sections"][0]["body"] =
                    json!(serde_json::to_string(&changed).unwrap());
            }
            "subject" => result.details["subject"] = json!(sha256(b"another package")),
            _ => unreachable!(),
        }
        assert!(
            reconcile("controlled.elf", &bytes, &mut result)
                .await
                .is_err(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn stale_inner_analysis_is_not_refreshed_by_new_sdk_timestamps() {
    let bytes = native();
    let mut report = manifest(&bytes, None);
    report["analysis"]["started_at"] = json!((Utc::now() - Duration::hours(3)).to_rfc3339());
    report["analysis"]["completed_at"] = json!((Utc::now() - Duration::hours(2)).to_rfc3339());
    let mut result = output(&bytes);
    let key = add_report(&mut result, report.clone(), &[]);
    // A long service execution ends recently, but the embedded analysis did not.
    result.details["raw_report"]["results"][&key]["response"]["milestones"]["service_completed"] =
        json!((Utc::now() - Duration::seconds(1)).to_rfc3339());
    reconcile("controlled.elf", &bytes, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    assert!(result.valid_until.unwrap() < Utc::now());
    assert!(
        result.details["binary_analysis"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().contains("is stale"))
    );
    let mut result = output(&bytes);
    let key = add_report(&mut result, report, &[]);
    result.details["raw_report"]["results"][&key]["response"]["milestones"]["service_started"] =
        json!((Utc::now() - Duration::seconds(5)).to_rfc3339());
    assert!(
        reconcile("controlled.elf", &bytes, &mut result)
            .await
            .is_err(),
        "old analysis cannot be placed inside a new service execution"
    );
}

#[tokio::test]
async fn decoded_outputs_require_the_actual_producing_service_extracted_edge() {
    let decoded = b"harmless decoded text";
    let mut bytes = b"\x7fELF".to_vec();
    bytes.extend(decoded.iter().map(|byte| byte ^ 0x5a));
    let report = manifest(&bytes, Some((decoded, 4)));
    for edge in [vec![], vec![sha256(b"unrelated child")]] {
        let mut result = output(&bytes);
        add_report(&mut result, report.clone(), &edge);
        assert!(reconcile("encoded.elf", &bytes, &mut result).await.is_err());
    }
    let mut result = output(&bytes);
    add_report(&mut result, report, &[sha256(decoded)]);
    reconcile("encoded.elf", &bytes, &mut result).await.unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(binary_remote::drafts(CHECK, &result).unwrap().len(), 3);
    assert_eq!(
        result.details["binary_analysis"]["manifests"][0]["validation"]["input_bytes_verified"],
        true
    );
}

#[tokio::test]
async fn verified_decoded_native_child_requires_its_own_report_even_if_remote_type_is_text() {
    let child = b"\x7fELFcontrolled decoded child, never executed";
    let mut parent = b"\x7fELF".to_vec();
    parent.extend(child.iter().map(|byte| byte ^ 0x5a));
    let report = manifest(&parent, Some((child, 4)));
    let mut result = output(&parent);
    add_report(&mut result, report.clone(), &[sha256(child)]);
    result.details["raw_report"]["file_infos"][sha256(child)] =
        json!({"sha256":sha256(child),"size":child.len(),"type":"text/plain"});
    reconcile("encoded.elf", &parent, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    assert_eq!(
        result.details["binary_analysis"]["missing_inputs"],
        json!([sha256(child)])
    );
    let mut result = output(&parent);
    add_report(&mut result, report, &[sha256(child)]);
    add_report(&mut result, manifest(child, None), &[]);
    reconcile("encoded.elf", &parent, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["binary_analysis"]["processed_inputs"], 2);
    assert!(
        result.details["binary_analysis"]["missing_inputs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let entries = result.details["binary_analysis"]["manifests"]
        .as_array()
        .unwrap();
    let child_entry = entries
        .iter()
        .find(|entry| entry["input_sha256"] == sha256(child))
        .unwrap();
    assert_eq!(child_entry["validation"]["input_bytes_verified"], true);
    assert_eq!(
        child_entry["logical_paths"],
        json!([format!("derived/{}/{}", sha256(&parent), sha256(child))])
    );
    assert_eq!(binary_remote::drafts(CHECK, &result).unwrap().len(), 5);
}

#[tokio::test]
async fn identical_binary_bytes_at_two_archive_paths_keep_both_aliases_in_receipt_and_drafts() {
    let bytes = native();
    let package = archive(&[("a.so", &bytes), ("nested/copy.so", &bytes)]);
    let mut result = output(&package);
    add_report(&mut result, manifest(&bytes, None), &[]);
    reconcile("controlled.whl", &package, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["binary_analysis"]["local_native_inputs"], 1);
    let entries = result.details["binary_analysis"]["manifests"]
        .as_array()
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "one content analysis may retain multiple observed paths"
    );
    let paths: Vec<String> = serde_json::from_value(entries[0]["logical_paths"].clone()).unwrap();
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().any(|p| p.ends_with("a.so")));
    assert!(paths.iter().any(|p| p.ends_with("nested/copy.so")));
    assert_eq!(binary_remote::drafts(CHECK, &result).unwrap().len(), 2);
}

#[tokio::test]
async fn late_derivation_alias_survives_when_the_local_child_is_processed_before_its_parent() {
    let child = (0..10_000)
        .map(|nonce| format!("\u{7f}ELFcontrolled child nonce {nonce}").into_bytes())
        .find(|bytes| sha256(bytes).starts_with('0'))
        .unwrap();
    let child_sha = sha256(&child);
    let mut encoded_parent = b"\x7fELF".to_vec();
    encoded_parent.extend(child.iter().map(|byte| byte ^ 0x5a));
    let parent = (0..256)
        .map(|nonce| {
            let mut bytes = encoded_parent.clone();
            bytes.extend(format!("suffix nonce {nonce}").as_bytes());
            bytes
        })
        .find(|bytes| sha256(bytes) > child_sha)
        .unwrap();
    let parent_sha = sha256(&parent);
    assert!(
        child_sha < parent_sha,
        "exercise the adverse SHA iteration order"
    );
    let package = archive(&[("child.elf", &child), ("parent.elf", &parent)]);
    let mut result = output(&package);
    add_report(&mut result, manifest(&child, None), &[]);
    add_report(
        &mut result,
        manifest(&parent, Some((&child, 4))),
        std::slice::from_ref(&child_sha),
    );
    reconcile("controlled.whl", &package, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    let entries = result.details["binary_analysis"]["manifests"]
        .as_array()
        .unwrap();
    assert_eq!(
        entries[0]["input_sha256"], child_sha,
        "the child receipt was visited before its parent"
    );
    let paths: Vec<String> = serde_json::from_value(entries[0]["logical_paths"].clone()).unwrap();
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().any(|path| path.ends_with("child.elf")));
    assert!(paths.contains(&format!("derived/{parent_sha}/{child_sha}")));
    let drafts = binary_remote::drafts(CHECK, &result).unwrap();
    assert_eq!(
        drafts.len(),
        5,
        "the child C/pcode and parent C/pcode/decoded products all retain a receipt"
    );
    assert!(drafts.iter().all(|draft| draft.check_name == CHECK));
}

#[tokio::test]
async fn manifest_cannot_reclassify_independently_observed_text_as_a_native_input() {
    let bytes = b"ordinary known text, not an ELF image";
    let mut report = manifest(bytes, None);
    report["input"]["kind"] = json!("elf");
    let mut result = output(bytes);
    add_report(&mut result, report, &[]);
    assert!(
        reconcile("README.txt", bytes, &mut result).await.is_err(),
        "a self-declared native kind cannot replace locally observed text"
    );
}

#[tokio::test]
async fn repeated_incomplete_reconciliation_does_not_duplicate_coverage_reasons() {
    let bytes = native();
    let mut result = output(&bytes);
    result.details["coverage_reasons"] = json!(["preexisting independent coverage reason"]);
    reconcile("missing.elf", &bytes, &mut result).await.unwrap();
    let first = result.details["coverage_reasons"].clone();
    let mut replay = result.clone();
    reconcile("missing.elf", &bytes, &mut replay).await.unwrap();
    assert_eq!(replay.outcome, Outcome::Inconclusive);
    assert_eq!(replay.details["coverage_reasons"], first);
    assert_eq!(first.as_array().unwrap().len(), 2);
    assert_eq!(
        replay.details["binary_analysis"]["missing_inputs"],
        json!([sha256(&bytes)])
    );
}

// Exercise the actual AL normalizer's explicit applicability behavior, then
// require binary reconciliation to enforce the authenticated execution record
// despite the remote classifier calling these locally observed ELF bytes text.
fn normalized_native_labeled_text(bytes: &[u8], manifest: &Value, mutation: &str) -> ScannerOutput {
    let sha = sha256(bytes);
    let now = Utc::now();
    let node = json!({"name":["misclassified.txt"],"type":"text/plain","sha256":sha,
        "size":bytes.len(),"children":{},"truncated":false,"score":0});
    let tree = json!({"tree":{sha.clone():node},"partial":false,"filtered":false,"supplementary":[],"classification":"U"});
    let started = manifest["analysis"]["started_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap()
        - Duration::seconds(1);
    let completed = manifest["analysis"]["completed_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap()
        + Duration::seconds(1);
    let service_result = |service: &str, tool: &str, sections: Value| {
        json!({"sha256":sha,"classification":"U",
        "created":(now-Duration::seconds(8)).to_rfc3339(),"expiry_ts":null,"partial":false,"drop_file":false,
        "response":{"service_name":service,"service_version":"4.7.0.1","service_tool_version":tool,
            "milestones":{"service_started":started.to_rfc3339(),"service_completed":completed.to_rfc3339()},
            "extracted":[],"supplementary":[]},"result":{"score":0,"sections":sections}})
    };
    let mut binary = service_result(
        SERVICE,
        "controlled-binary-tool",
        json!([{"title_text":SECTION_TITLE,
        "body":serde_json::to_string(manifest).unwrap(),"depth":0,"heuristic":null,"tags":{}}]),
    );
    let mut version = "4.7.0.1";
    let mut configuration = "BinaryFixture1";
    match mutation {
        "wrong_configuration" => configuration = "DifferentConfiguration",
        "wrong_tool" => binary["response"]["service_tool_version"] = json!("different-tool"),
        "wrong_version" => {
            version = "4.7.0.2";
            binary["response"]["service_version"] = json!(version);
        }
        "stale" => binary["created"] = json!((now - Duration::hours(2)).to_rfc3339()),
        "future" => binary["created"] = json!((now + Duration::minutes(1)).to_rfc3339()),
        "partial" => binary["partial"] = json!(true),
        "drop_file" => binary["drop_file"] = json!(true),
        "valid" | "empty_cached" => {}
        _ => panic!("unknown controlled fixture mutation"),
    }
    let suffix = if mutation == "empty_cached" { ".e" } else { "" };
    let binary_key = format!(
        "{sha}.{SERVICE}.v{}.c{configuration}{suffix}",
        version.replace('.', "_")
    );
    let yara_key = format!("{sha}.ControlledYARA.v4_7_0_1.cYaraFixture1");
    let report = json!({"sid":"controlled-native-classifier-override","state":"completed",
        "files":[{"name":"misclassified.txt","sha256":sha,"size":bytes.len()}],"file_count":1,"max_score":0,
        "error_count":0,"errors":{},"results":{binary_key:binary,yara_key:service_result("ControlledYARA","controlled-yara-tool",json!([]))},
        "params":{"ignore_cache":false,"services":{"selected":[SERVICE,"ControlledYARA"],"excluded":[],"rescan":[],"resubmit":[]},"service_spec":{}},
        "file_tree":tree["tree"],"file_infos":{sha.clone():{"sha256":sha,"size":bytes.len(),"type":"text/plain"}},
        "missing_result_keys":[],"missing_error_keys":[],"missing_file_keys":[]});
    let policy = AssemblylinePolicy {
        required_services: BTreeMap::from([
            (
                SERVICE.into(),
                AssemblylineServicePin {
                    version: "4.7.0.1".into(),
                    tool_version: Some("controlled-binary-tool".into()),
                    configuration_key: "BinaryFixture1".into(),
                    applies_to: vec!["executable/".into()],
                },
            ),
            (
                "ControlledYARA".into(),
                AssemblylineServicePin {
                    version: "4.7.0.1".into(),
                    tool_version: Some("controlled-yara-tool".into()),
                    configuration_key: "YaraFixture1".into(),
                    applies_to: vec![],
                },
            ),
        ]),
        deny_rules: vec![],
        informational_rules: vec![],
        allow_empty_files: false,
        max_result_age_seconds: 3600,
    };
    normalize_at(
        &sha,
        "controlled-native-classifier-override",
        &report,
        &tree,
        &policy,
        now,
    )
    .unwrap()
}

#[tokio::test]
async fn actual_normalizer_out_of_scope_service_cannot_bypass_binary_pin_and_execution_requirements()
 {
    let bytes = native();
    let manifest = manifest(&bytes, None);
    for mutation in [
        "valid",
        "wrong_configuration",
        "wrong_tool",
        "wrong_version",
        "stale",
        "future",
        "partial",
        "drop_file",
        "empty_cached",
    ] {
        let mut result = normalized_native_labeled_text(&bytes, &manifest, mutation);
        assert_eq!(
            result.outcome,
            Outcome::Pass,
            "the universal service covers remote text: {mutation}"
        );
        let coverage = result.details["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pair| pair["service"] == SERVICE)
            .unwrap();
        assert_eq!(coverage["status"], "not_applicable");
        assert_eq!(coverage["applicable"], false);
        let reconciled = reconcile("misclassified.txt", &bytes, &mut result).await;
        if mutation == "valid" {
            reconciled.unwrap();
            assert_eq!(
                result.outcome,
                Outcome::Pass,
                "a pinned fresh result may cover independently observed native bytes"
            );
        } else if mutation == "partial" || mutation == "drop_file" {
            reconciled.unwrap();
            assert_eq!(
                result.outcome,
                Outcome::Inconclusive,
                "partial/dropped reports remain retained observations, never complete: {mutation}"
            );
            assert_eq!(
                result.details["binary_analysis"]["manifests"][0]["service_validation"]["complete"],
                false
            );
            assert_eq!(
                result.details["binary_analysis"]["manifests"][0]["manifest"],
                manifest
            );
        } else {
            assert!(
                reconciled.is_err(),
                "manifest identity cannot replace normalized service execution checks: {mutation}"
            );
        }
    }
}

#[tokio::test]
async fn missing_ambiguous_or_rebound_normalized_execution_records_cannot_support_a_binary_manifest()
 {
    let bytes = native();
    let manifest = manifest(&bytes, None);
    for mutation in [
        "missing_pair",
        "duplicate_pair",
        "missing_record",
        "duplicate_record",
        "wrong_key",
    ] {
        let mut result = output(&bytes);
        add_report(&mut result, manifest.clone(), &[]);
        match mutation {
            "missing_pair" => result.details["coverage"] = json!([]),
            "duplicate_pair" => {
                let pair = result.details["coverage"][0].clone();
                result.details["coverage"]
                    .as_array_mut()
                    .unwrap()
                    .push(pair);
            }
            "missing_record" => result.details["coverage"][0]["results"] = json!([]),
            "duplicate_record" => {
                let record = result.details["coverage"][0]["results"][0].clone();
                result.details["coverage"][0]["results"]
                    .as_array_mut()
                    .unwrap()
                    .push(record);
            }
            "wrong_key" => {
                result.details["coverage"][0]["results"][0]["result_key"] =
                    json!("different-result-key")
            }
            _ => unreachable!(),
        }
        assert!(
            reconcile("controlled.elf", &bytes, &mut result)
                .await
                .is_err(),
            "{mutation}"
        );
    }
}

#[tokio::test]
async fn out_of_scope_normalized_result_expiry_caps_the_binary_receipt() {
    let bytes = native();
    let mut result = output(&bytes);
    add_report(&mut result, manifest(&bytes, None), &[]);
    let expiry = Utc::now() + Duration::seconds(20);
    result.details["coverage"][0]["results"][0]["valid_until"] = json!(expiry.to_rfc3339());
    reconcile("controlled.elf", &bytes, &mut result)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.valid_until, Some(expiry));
}

fn encoded_parent(decoded: &[u8]) -> Vec<u8> {
    let mut parent = b"\x7fELF".to_vec();
    parent.extend(decoded.iter().map(|byte| byte ^ 0x5a));
    parent
}

fn add_remote_graph_file(result: &mut ScannerOutput, bytes: &[u8]) {
    let sha = sha256(bytes);
    let files = result.details["files"].as_array_mut().unwrap();
    if !files.iter().any(|file| file == &sha) {
        files.push(json!(sha));
    }
    result.details["raw_report"]["file_infos"][&sha] =
        json!({"sha256":sha,"size":bytes.len(),"type":"text/plain"});
}

#[tokio::test]
async fn verified_xor_archive_native_members_require_reports_despite_remote_text_labels() {
    let child = native();
    let readme = b"ordinary decoded archive text";
    let decoded = archive(&[("payload/native.elf", &child), ("README", readme)]);
    let parent = encoded_parent(&decoded);
    let mut base = output(&parent);
    add_report(
        &mut base,
        manifest(&parent, Some((&decoded, 4))),
        &[sha256(&decoded)],
    );
    add_remote_graph_file(&mut base, &child);
    add_remote_graph_file(&mut base, readme);
    let mut missing = base.clone();
    reconcile("encoded.elf", &parent, &mut missing)
        .await
        .unwrap();
    assert_eq!(missing.outcome, Outcome::Inconclusive);
    assert_eq!(
        missing.details["binary_analysis"]["missing_inputs"],
        json!([sha256(&child)])
    );
    add_report(&mut base, manifest(&child, None), &[]);
    reconcile("encoded.elf", &parent, &mut base).await.unwrap();
    assert_eq!(base.outcome, Outcome::Pass);
    let child_entry = base.details["binary_analysis"]["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["input_sha256"] == sha256(&child))
        .unwrap();
    assert_eq!(child_entry["validation"]["input_bytes_verified"], true);
    assert!(
        child_entry["logical_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path.as_str().unwrap().contains("payload/native.elf"))
    );
    assert_eq!(binary_remote::drafts(CHECK, &base).unwrap().len(), 5);
}

#[tokio::test]
async fn decoded_archive_non_native_members_cannot_disappear_from_the_actual_remote_graph() {
    let child = native();
    let readme = b"non-native content still needs graph accounting";
    let decoded = archive(&[("native.elf", &child), ("README", readme)]);
    let parent = encoded_parent(&decoded);
    let mut result = output(&parent);
    add_report(
        &mut result,
        manifest(&parent, Some((&decoded, 4))),
        &[sha256(&decoded)],
    );
    add_report(&mut result, manifest(&child, None), &[]);
    let checked = reconcile("encoded.elf", &parent, &mut result).await;
    assert!(
        checked.is_err() || result.outcome == Outcome::Inconclusive,
        "native analysis alone cannot account for an omitted ordinary decoded archive member"
    );
    if checked.is_ok() {
        assert_eq!(
            result.details["binary_analysis"]["decoded_inventory"]["missing_files"],
            json!([sha256(readme)])
        );
    }
}

#[tokio::test]
async fn decoded_archive_empty_member_requires_explicit_empty_content_policy_without_a_fake_execution()
 {
    let child = native();
    let decoded = archive(&[("native.elf", &child), ("__init__.py", b"")]);
    let parent = encoded_parent(&decoded);
    let mut base = output(&parent);
    add_report(
        &mut base,
        manifest(&parent, Some((&decoded, 4))),
        &[sha256(&decoded)],
    );
    add_report(&mut base, manifest(&child, None), &[]);
    let mut strict = base.clone();
    let checked = reconcile("encoded.elf", &parent, &mut strict).await;
    assert!(checked.is_err() || strict.outcome == Outcome::Inconclusive);
    binary_remote::reconcile_with_empty_policy(
        &policy(),
        "encoded.elf",
        Arc::from(parent.as_slice()),
        &mut base,
        3600,
        true,
    )
    .await
    .unwrap();
    assert_eq!(base.outcome, Outcome::Pass);
    assert_eq!(
        base.details["binary_analysis"]["decoded_inventory"]["known_empty_content"],
        json!([sha256(b"")])
    );
    assert_eq!(base.details["coverage"].as_array().unwrap().len(), 2);
    assert!(
        base.details["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .all(|pair| pair["sha256"] != sha256(b""))
    );
    assert!(
        base.details["binary_analysis"]["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["input_sha256"] != sha256(b""))
    );
}

#[tokio::test]
async fn malformed_unsupported_and_unsafe_decoded_archives_fail_closed() {
    let unsafe_zip = archive(&[("../escape.elf", b"\x7fELFcontrolled fixture")]);
    for decoded in [
        b"PK\x03\x04broken ZIP".to_vec(),
        b"7z\xbc\xaf\x27\x1cunsupported compression".to_vec(),
        vec![0x1f, 0x8b, 0, 0, 0],
        unsafe_zip,
    ] {
        let parent = encoded_parent(&decoded);
        let mut result = output(&parent);
        add_report(
            &mut result,
            manifest(&parent, Some((&decoded, 4))),
            &[sha256(&decoded)],
        );
        assert!(
            reconcile("encoded.elf", &parent, &mut result)
                .await
                .is_err(),
            "verified XOR mathematics cannot establish complete inspection of malformed or unsupported archives"
        );
    }
}

#[tokio::test]
async fn valid_legacy_tar_without_ustar_magic_cannot_hide_decoded_native_members() {
    let child = native();
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_old();
    header.set_mode(0o644);
    header.set_size(child.len() as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, "native.elf", child.as_slice())
        .unwrap();
    let decoded = builder.into_inner().unwrap();
    assert_ne!(&decoded[257..262], b"ustar");
    // Independently prove this is a real bounded TAR member, not random bytes
    // or a malformed-input rejection that could mask the classification gap.
    let mut parsed = tar::Archive::new(Cursor::new(&decoded));
    assert_eq!(parsed.entries().unwrap().count(), 1);
    let parent = encoded_parent(&decoded);
    let mut result = output(&parent);
    add_report(
        &mut result,
        manifest(&parent, Some((&decoded, 4))),
        &[sha256(&decoded)],
    );
    let checked = reconcile("encoded.elf", &parent, &mut result).await;
    assert!(
        checked.is_err() || result.outcome == Outcome::Inconclusive,
        "a decoded V7 TAR must be inspected or held; its missing native member cannot disappear behind text classification"
    );
}

#[tokio::test]
async fn derived_archive_input_limits_apply_across_separate_inline_outputs() {
    let all: Vec<Vec<u8>> = (0..258)
        .map(|index| format!("\u{7f}ELFcontrolled derived native leaf {index}").into_bytes())
        .collect();
    let first_names: Vec<_> = (0..129).map(|index| format!("first-{index}.elf")).collect();
    let second_names: Vec<_> = (129..258)
        .map(|index| format!("second-{index}.elf"))
        .collect();
    let first_refs: Vec<_> = first_names
        .iter()
        .zip(&all[..129])
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let second_refs: Vec<_> = second_names
        .iter()
        .zip(&all[129..])
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let decoded = [archive(&first_refs), archive(&second_refs)];
    let mut parent = encoded_parent(&decoded[0]);
    let second_offset = parent.len();
    parent.extend(decoded[1].iter().map(|byte| byte ^ 0x5a));
    let mut report = manifest(&parent, Some((&decoded[0], 4)));
    let mut second = report["outputs"][2].clone();
    second["sha256"] = json!(sha256(&decoded[1]));
    second["size"] = json!(decoded[1].len());
    second["data_base64"] = json!(STANDARD.encode(&decoded[1]));
    second["derivation"]["source_spans"] = json!([{"offset":second_offset,"length":decoded[1].len(),"sha256":sha256(&parent[second_offset..])}]);
    report["outputs"].as_array_mut().unwrap().push(second);
    let mut result = output(&parent);
    add_report(
        &mut result,
        report,
        &decoded
            .iter()
            .map(|bytes| sha256(bytes))
            .collect::<Vec<_>>(),
    );
    for leaf in &all {
        add_remote_graph_file(&mut result, leaf);
    }
    let error = reconcile("encoded.elf", &parent, &mut result)
        .await
        .expect_err(
            "two individually bounded archives must not reset the global distinct-input budget",
        );
    let message = format!("{error:#}");
    assert!(
        message.contains("limit") || message.contains("exceed") || message.contains("bound"),
        "{message}"
    );
}

#[tokio::test]
async fn compressed_inline_outputs_cannot_reset_the_global_native_byte_budget() {
    // Nine graph nodes and compact inline ZIPs stay below the count/manifest
    // limits. Their four individually permitted 16MiB native members plus the
    // original input exceed the aggregate 64MiB capture budget.
    let leaves: Vec<Vec<u8>> = (0..4)
        .map(|index| {
            let mut bytes = vec![0; 16 * 1024 * 1024];
            bytes[..4].copy_from_slice(b"\x7fELF");
            *bytes.last_mut().unwrap() = index;
            bytes
        })
        .collect();
    let decoded: Vec<Vec<u8>> = leaves
        .iter()
        .map(|bytes| {
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            zip.start_file(
                "native.elf",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
            zip.finish().unwrap().into_inner()
        })
        .collect();
    assert!(decoded.iter().map(Vec::len).sum::<usize>() < 200 * 1024);
    let mut parent = b"\x7fELF".to_vec();
    let mut offsets = Vec::new();
    for bytes in &decoded {
        offsets.push(parent.len());
        parent.extend(bytes.iter().map(|byte| byte ^ 0x5a));
    }
    let mut report = manifest(&parent, Some((&decoded[0], offsets[0])));
    for index in 1..decoded.len() {
        let mut next = report["outputs"][2].clone();
        let bytes = &decoded[index];
        let offset = offsets[index];
        next["sha256"] = json!(sha256(bytes));
        next["size"] = json!(bytes.len());
        next["data_base64"] = json!(STANDARD.encode(bytes));
        next["derivation"]["source_spans"] = json!([{"offset":offset,"length":bytes.len(),"sha256":sha256(&parent[offset..offset+bytes.len()])}]);
        report["outputs"].as_array_mut().unwrap().push(next);
    }
    let mut result = output(&parent);
    add_report(
        &mut result,
        report,
        &decoded
            .iter()
            .map(|bytes| sha256(bytes))
            .collect::<Vec<_>>(),
    );
    for leaf in &leaves {
        add_remote_graph_file(&mut result, leaf);
    }
    assert_eq!(result.details["files"].as_array().unwrap().len(), 9);
    let error = reconcile("encoded.elf", &parent, &mut result)
        .await
        .expect_err("aggregate decoded native bytes must remain bounded across all outputs");
    let message = format!("{error:#}");
    assert!(
        message.contains("limit") || message.contains("exceed") || message.contains("bound"),
        "{message}"
    );
}
