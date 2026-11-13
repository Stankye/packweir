//! Contract fixtures only; actual Ghidra qualification is a separate live gate.
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use packweir::{
    binary_analysis::{
        BinaryAnalysisPolicy, MAX_MANIFEST_BYTES, MAX_OUTPUT_BYTES, MAX_OUTPUTS,
        default_candidate_kinds, parse_manifest, producer_identity_sha256, validate_manifest,
    },
    model::sha256,
};
use serde_json::{Value, json};

fn now() -> DateTime<Utc> {
    "2026-11-12T18:00:00Z".parse().unwrap()
}
fn input() -> Vec<u8> {
    let mut bytes = b"\x7fELF".to_vec();
    bytes.extend(b"harmless static marker".iter().map(|byte| byte ^ 0x5a));
    bytes
}
fn fixture() -> (Vec<u8>, Value, BinaryAnalysisPolicy) {
    let bytes = input();
    let digest = sha256(&bytes);
    let mut producer = json!({"engine":"Ghidra","engine_version":"12.2",
        "engine_archive_sha256":sha256(b"pinned engine archive"),"jdk_version":"25.0.5+8",
        "jdk_archive_sha256":sha256(b"pinned JDK archive"),"decompiler_sha256":sha256(b"pinned native decompiler"),
        "scripts_sha256":sha256(b"pinned scripts"),"profile_sha256":sha256(b"pinned complete profile"),
        "driver_sha256":sha256(b"pinned wrapper source")});
    let identity = producer_identity_sha256(&producer).unwrap();
    producer["identity_sha256"] = json!(identity);
    let text_output = |kind: &str, media: &str, operation: &str, content: &[u8]| {
        json!({
        "kind":kind,"media_type":media,"sha256":sha256(content),"size":content.len(),"data_base64":STANDARD.encode(content),
        "derivation":{"operation":operation,"version":"12.2","input_sha256":digest,
            "parameters":{"function_entry":"00101000"},"source_spans":[{"offset":0,"length":bytes.len(),"sha256":digest}]}})
    };
    let decoded = b"harmless static marker";
    let manifest = json!({"schema_version":"packweir.binary-analysis.v1",
        "input":{"sha256":digest,"size":bytes.len(),"kind":"elf"},"producer":producer,
        "analysis":{"started_at":"2026-11-12T17:59:00Z","completed_at":"2026-11-12T17:59:30Z",
            "status":"complete","timed_out":false,"errors":[],"warnings":[],"language_id":"x86:LE:64:default",
            "compiler_spec_id":"gcc","requested_capabilities":["decompile","pcode","decode_xor"],
            "capabilities":{"decompile":"complete","pcode":"complete","decode_xor":"complete"},
            "functions_total":1,"functions_decompiled":1,"functions_failed":0,"export_truncated":false,
            "log_sha256":sha256(b"actual execution log bytes would be bound here")},
        "observations":[{"kind":"function","name":"decoder","value":"Observed INT_XOR; input bytes are never executed by the validator"}],
        "outputs":[text_output("decompiled_c","text/x-c","ghidra.decompile",b"void decoder(void) { /* observed decompilation */ }\n"),
            text_output("pcode","text/plain","ghidra.pcode",b"INT_XOR source, 0x5a\n"),
            {"kind":"decoded_bytes","media_type":"application/octet-stream","sha256":sha256(decoded),"size":decoded.len(),
                "data_base64":STANDARD.encode(decoded),"derivation":{"operation":"xor.decode","version":"1",
                    "input_sha256":digest,"parameters":{"key_hex":"5a"},
                    "source_spans":[{"offset":4,"length":decoded.len(),"sha256":sha256(&bytes[4..])}]}}]});
    let policy = BinaryAnalysisPolicy {
        service: "PackweirGhidra".into(),
        identity_sha256: identity,
        required_capabilities: vec!["decompile".into(), "pcode".into(), "decode_xor".into()],
        informational_warnings: vec![],
        candidate_kinds: default_candidate_kinds(),
    };
    (bytes, manifest, policy)
}
fn validate(
    bytes: &[u8],
    manifest: &Value,
    policy: &BinaryAnalysisPolicy,
) -> anyhow::Result<packweir::binary_analysis::ValidatedManifest> {
    validate_manifest(
        policy,
        &sha256(bytes),
        bytes.len() as u64,
        "elf",
        Some(bytes),
        manifest,
        now(),
    )
}

#[test]
fn complete_observations_bind_every_identity_input_and_output_without_a_safety_verdict() {
    let (bytes, manifest, policy) = fixture();
    let raw = serde_json::to_string(&manifest).unwrap();
    let parsed = parse_manifest(&raw).unwrap();
    let validated = validate(&bytes, &parsed, &policy).unwrap();
    assert!(validated.complete && validated.input_bytes_verified);
    assert_eq!(
        validated.manifest_sha256,
        sha256(&serde_json::to_vec(&manifest).unwrap())
    );
    assert_eq!(validated.producer_identity_sha256, policy.identity_sha256);
    assert_eq!(validated.details["manifest"], manifest);
    assert_eq!(validated.details["validation"]["complete"], true);
    assert_eq!(validated.details["input_sha256"], sha256(&bytes));
    assert_eq!(validated.outputs.len(), 3);
    assert_eq!(validated.outputs[2].bytes, b"harmless static marker");
    assert_eq!(validated.outputs[2].metadata["source_spans_verified"], true);
    assert_eq!(validated.outputs[2].metadata["xor_recomputed"], true);
    assert!(
        validated
            .outputs
            .iter()
            .all(|output| output.metadata["semantic_equivalence_verified"] == false)
    );
    assert_eq!(validated.outputs[0].metadata["xor_recomputed"], false);
    assert_eq!(
        validated.details["validation"]["outputs"][0],
        validated.outputs[0].metadata
    );
    assert_eq!(
        validated.details["validation"]["outputs"][2],
        validated.outputs[2].metadata
    );
    assert!(
        validated
            .outputs
            .iter()
            .all(|output| output.metadata.get("data_base64").is_none())
    );
    assert!(validated.details.get("malware_safe").is_none());
}

#[test]
fn producer_identity_binds_all_fields_and_excludes_only_the_identity_itself() {
    let (_, manifest, _) = fixture();
    let producer = &manifest["producer"];
    let expected = producer_identity_sha256(producer).unwrap();
    let mut changed = producer.clone();
    changed["identity_sha256"] = json!("f".repeat(64));
    assert_eq!(producer_identity_sha256(&changed).unwrap(), expected);
    for field in [
        "engine",
        "engine_version",
        "engine_archive_sha256",
        "jdk_version",
        "jdk_archive_sha256",
        "decompiler_sha256",
        "scripts_sha256",
        "profile_sha256",
        "driver_sha256",
    ] {
        let mut changed = producer.clone();
        changed[field] = json!(if field.ends_with("_sha256") {
            sha256(field.as_bytes())
        } else {
            "changed".into()
        });
        assert_ne!(
            producer_identity_sha256(&changed).unwrap(),
            expected,
            "{field}"
        );
    }
    let mut changed = producer.clone();
    changed["ignored_tool_path"] = json!("/tmp/unpinned-tool");
    assert!(producer_identity_sha256(&changed).is_err());
}

#[test]
fn producer_pin_and_expected_input_cannot_be_substituted() {
    let (bytes, manifest, policy) = fixture();
    for field in ["sha256", "size", "kind"] {
        let mut changed = manifest.clone();
        changed["input"][field] = match field {
            "sha256" => json!(sha256(b"other")),
            "size" => json!(999),
            _ => json!("pe"),
        };
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
    let mut changed = manifest.clone();
    changed["producer"]["driver_sha256"] = json!(sha256(b"changed source"));
    changed["producer"]["identity_sha256"] =
        json!(producer_identity_sha256(&changed["producer"]).unwrap());
    assert!(validate(&bytes, &changed, &policy).is_err());
    let mut wrong_bytes = bytes.clone();
    wrong_bytes[0] ^= 1;
    assert!(
        validate_manifest(
            &policy,
            &sha256(&bytes),
            bytes.len() as u64,
            "elf",
            Some(&wrong_bytes),
            &manifest,
            now()
        )
        .is_err()
    );
}

#[test]
fn unsupported_timeout_errors_warnings_and_partial_exports_are_retained_as_incomplete() {
    let (bytes, manifest, policy) = fixture();
    for (field, value) in [
        ("status", json!("unsupported")),
        ("status", json!("incomplete")),
        ("status", json!("error")),
        ("timed_out", json!(true)),
        ("errors", json!(["native decompiler failed"])),
        ("warnings", json!(["unsupported instruction"])),
        ("export_truncated", json!(true)),
        ("language_id", Value::Null),
        ("compiler_spec_id", Value::Null),
    ] {
        let mut changed = manifest.clone();
        changed["analysis"][field] = value;
        let output = validate(&bytes, &changed, &policy).unwrap();
        assert!(!output.complete, "{field}");
        assert_eq!(output.details["manifest"], changed);
    }
}

#[test]
fn selected_function_or_zero_function_reports_cannot_claim_complete_decompilation() {
    let (bytes, manifest, policy) = fixture();
    for (total, decompiled, failed) in [(2, 1, 0), (1, 0, 1), (0, 0, 0)] {
        let mut changed = manifest.clone();
        changed["analysis"]["functions_total"] = json!(total);
        changed["analysis"]["functions_decompiled"] = json!(decompiled);
        changed["analysis"]["functions_failed"] = json!(failed);
        assert!(!validate(&bytes, &changed, &policy).unwrap().complete);
    }
    let mut impossible = manifest;
    impossible["analysis"]["functions_failed"] = json!(1);
    assert!(validate(&bytes, &impossible, &policy).is_err());
}

#[test]
fn missing_required_capability_and_missing_attributable_outputs_stay_incomplete() {
    let (bytes, mut manifest, policy) = fixture();
    manifest["analysis"]["requested_capabilities"] = json!(["decompile"]);
    manifest["analysis"]["capabilities"]["pcode"] = json!("not_requested");
    manifest["analysis"]["capabilities"]["decode_xor"] = json!("not_requested");
    manifest["outputs"] = json!([manifest["outputs"][0].clone()]);
    assert!(!validate(&bytes, &manifest, &policy).unwrap().complete);
    let (bytes, mut manifest, policy) = fixture();
    manifest["outputs"] = json!([]);
    assert!(!validate(&bytes, &manifest, &policy).unwrap().complete);
    manifest["analysis"]["capabilities"]["decompile"] = json!("not_requested");
    assert!(validate(&bytes, &manifest, &policy).is_err());
}

#[test]
fn empty_and_whitespace_text_cannot_complete_a_decompiler_capability() {
    let (bytes, manifest, policy) = fixture();
    for index in [0, 1] {
        for content in [
            b"".as_slice(),
            b" \t\r\n".as_slice(),
            b"\x01\x02".as_slice(),
        ] {
            let mut changed = manifest.clone();
            changed["outputs"][index]["size"] = json!(content.len());
            changed["outputs"][index]["sha256"] = json!(sha256(content));
            changed["outputs"][index]["data_base64"] = json!(STANDARD.encode(content));
            if content.is_empty() {
                assert!(validate(&bytes, &changed, &policy).is_err());
            } else {
                let validated = validate(&bytes, &changed, &policy).unwrap();
                assert!(!validated.complete);
                assert_eq!(validated.outputs[index].bytes, content);
                assert!(
                    validated.details["validation"]["reasons"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|reason| reason.as_str().unwrap().contains("no meaningful text"))
                );
            }
        }
    }
}

#[test]
fn complete_function_coverage_requires_distinct_matching_exported_entry_sets() {
    let (bytes, manifest, policy) = fixture();
    let mut missing = manifest.clone();
    missing["analysis"]["functions_total"] = json!(3);
    missing["analysis"]["functions_decompiled"] = json!(3);
    let validated = validate(&bytes, &missing, &policy).unwrap();
    assert!(!validated.complete);
    assert_eq!(
        validated.outputs.len(),
        3,
        "valid partial observations remain available"
    );

    let mut full = manifest.clone();
    full["analysis"]["functions_total"] = json!(2);
    full["analysis"]["functions_decompiled"] = json!(2);
    for index in [0, 1] {
        let mut second = manifest["outputs"][index].clone();
        second["derivation"]["parameters"]["function_entry"] = json!("ram:00102000");
        full["outputs"].as_array_mut().unwrap().push(second);
    }
    assert!(validate(&bytes, &full, &policy).unwrap().complete);

    let mut mismatched = full.clone();
    mismatched["outputs"][4]["derivation"]["parameters"]["function_entry"] = json!("ram:00103000");
    assert!(
        !validate(&bytes, &mismatched, &policy).unwrap().complete,
        "equal counts do not replace the requirement for matching C/pcode function identities"
    );
    let mut duplicate = manifest.clone();
    duplicate["outputs"]
        .as_array_mut()
        .unwrap()
        .push(manifest["outputs"][0].clone());
    assert!(!validate(&bytes, &duplicate, &policy).unwrap().complete);
    let mut omitted = manifest.clone();
    omitted["outputs"][0]["derivation"]["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("function_entry");
    assert!(!validate(&bytes, &omitted, &policy).unwrap().complete);
    for entry in [
        json!(""),
        json!("x".repeat(257)),
        json!("entry\nother"),
        json!(7),
    ] {
        let mut invalid = manifest.clone();
        invalid["outputs"][0]["derivation"]["parameters"]["function_entry"] = entry;
        assert!(validate(&bytes, &invalid, &policy).is_err());
    }
}

#[test]
fn exact_informational_warnings_preserve_raw_diagnostics_without_masking_failures() {
    let (bytes, mut manifest, mut policy) = fixture();
    let warning = "Ignoring leading '_' chars on no-return name '___raise_securityfailure' specified in file: /opt/ghidra/Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn";
    manifest["analysis"]["warnings"] = json!([warning]);
    let strict = validate(&bytes, &manifest, &policy).unwrap();
    assert!(!strict.complete);
    assert_eq!(
        strict.details["validation"]["acknowledged_warnings"],
        json!([])
    );
    assert_eq!(
        strict.details["validation"]["unacknowledged_warnings"],
        json!([warning])
    );
    policy.informational_warnings = vec![warning.into()];
    let acknowledged = validate(&bytes, &manifest, &policy).unwrap();
    assert!(acknowledged.complete);
    assert_eq!(
        acknowledged.details["manifest"]["analysis"]["warnings"],
        json!([warning])
    );
    assert_eq!(
        acknowledged.details["validation"]["informational_warning_policy"],
        json!([warning])
    );
    assert_eq!(
        acknowledged.details["validation"]["acknowledged_warnings"],
        json!([warning])
    );
    assert_eq!(
        acknowledged.details["validation"]["unacknowledged_warnings"],
        json!([])
    );
    for altered in [
        format!("{warning}."),
        warning.to_lowercase(),
        "unknown analysis warning".into(),
    ] {
        let mut changed = manifest.clone();
        changed["analysis"]["warnings"] = json!([warning, altered]);
        let validated = validate(&bytes, &changed, &policy).unwrap();
        assert!(!validated.complete);
        assert_eq!(
            validated.details["validation"]["acknowledged_warnings"],
            json!([warning])
        );
        assert_eq!(
            validated.details["validation"]["unacknowledged_warnings"],
            json!([altered])
        );
    }
    for (field, value) in [
        ("errors", json!([warning])),
        ("timed_out", json!(true)),
        ("export_truncated", json!(true)),
        ("status", json!("incomplete")),
    ] {
        let mut changed = manifest.clone();
        changed["analysis"][field] = value;
        assert!(
            !validate(&bytes, &changed, &policy).unwrap().complete,
            "{field}"
        );
    }
    policy.identity_sha256 = sha256(b"different producer");
    assert!(
        validate(&bytes, &manifest, &policy).is_err(),
        "warning acknowledgment cannot replace the producer pin"
    );
}

#[test]
fn future_unordered_or_malformed_times_are_rejected() {
    let (bytes, manifest, policy) = fixture();
    for (field, value) in [
        ("started_at", "2026-11-12T17:59:31Z"),
        ("completed_at", "2026-11-12T18:00:01Z"),
        ("started_at", "not-a-time"),
    ] {
        let mut changed = manifest.clone();
        changed["analysis"][field] = json!(value);
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
}

#[test]
fn unverified_xor_source_bytes_cannot_produce_complete_transform_evidence() {
    let (bytes, manifest, policy) = fixture();
    let output = validate_manifest(
        &policy,
        &sha256(&bytes),
        bytes.len() as u64,
        "elf",
        None,
        &manifest,
        now(),
    )
    .unwrap();
    assert!(!output.complete && !output.input_bytes_verified);
    assert_eq!(output.outputs[2].metadata["source_spans_verified"], false);
    assert_eq!(output.outputs[2].metadata["xor_recomputed"], false);
}

#[test]
fn xor_verification_checks_the_actual_result_not_only_its_self_reported_hash() {
    let (bytes, manifest, policy) = fixture();
    for (field, value) in [
        ("key_hex", json!("00")),
        ("key_hex", json!("5A")),
        ("key_hex", json!("5")),
        ("key_hex", json!("")),
        ("key_hex", json!("0x5a")),
        ("key_hex", json!("5a".repeat(33))),
    ] {
        let mut changed = manifest.clone();
        changed["outputs"][2]["derivation"]["parameters"][field] = value;
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
    let mut changed = manifest.clone();
    let wrong = b"harmless static markes";
    changed["outputs"][2]["data_base64"] = json!(STANDARD.encode(wrong));
    changed["outputs"][2]["sha256"] = json!(sha256(wrong));
    changed["outputs"][2]["size"] = json!(wrong.len());
    assert!(validate(&bytes, &changed, &policy).is_err());
    for value in [json!("2"), json!("unknown")] {
        let mut changed = manifest.clone();
        changed["outputs"][2]["derivation"]["version"] = value;
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
}

#[test]
fn source_spans_cannot_be_overflowed_relocated_or_forged() {
    let (bytes, manifest, policy) = fixture();
    for (field, value) in [
        ("offset", json!(u64::MAX)),
        ("offset", json!(3)),
        ("length", json!(0)),
        ("length", json!(999)),
        ("sha256", json!(sha256(b"forged source"))),
    ] {
        let mut changed = manifest.clone();
        changed["outputs"][2]["derivation"]["source_spans"][0][field] = value;
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
    let mut changed = manifest;
    changed["outputs"][0]["derivation"]["input_sha256"] = json!(sha256(b"unrelated"));
    assert!(validate(&bytes, &changed, &policy).is_err());
}

#[test]
fn base64_size_digest_media_and_decompiler_version_are_strict() {
    let (bytes, manifest, policy) = fixture();
    for (field, value) in [
        ("data_base64", json!("%%%%")),
        ("data_base64", json!("YQ")),
        ("data_base64", json!("YQ==\n")),
        ("size", json!(1)),
        ("sha256", json!("A".repeat(64))),
        ("media_type", json!("text/html")),
    ] {
        let mut changed = manifest.clone();
        changed["outputs"][0][field] = value;
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
    let mut changed = manifest;
    changed["outputs"][0]["derivation"]["version"] = json!("unpinned");
    assert!(validate(&bytes, &changed, &policy).is_err());
}

#[test]
fn unknown_fields_paths_nested_parameters_and_duplicates_are_rejected_before_collapse() {
    let (bytes, manifest, policy) = fixture();
    for location in ["top", "producer", "output", "derivation"] {
        let mut changed = manifest.clone();
        match location {
            "top" => changed["path"] = json!("../../outside"),
            "producer" => changed["producer"]["path"] = json!("/tmp/tool"),
            "output" => changed["outputs"][0]["path"] = json!("../../outside"),
            _ => changed["outputs"][0]["derivation"]["path"] = json!("../../outside"),
        }
        assert!(validate(&bytes, &changed, &policy).is_err());
    }
    let mut changed = manifest.clone();
    changed["outputs"][0]["derivation"]["parameters"]["nested"] = json!({"command":"not scalar"});
    assert!(validate(&bytes, &changed, &policy).is_err());
    let raw = serde_json::to_string(&manifest).unwrap();
    for changed in [
        raw.replacen(
            "\"schema_version\":",
            "\"schema_version\":\"other\",\"schema_version\":",
            1,
        ),
        raw.replacen(
            "\"key_hex\":\"5a\"",
            "\"key_hex\":\"00\",\"key_hex\":\"5a\"",
            1,
        ),
    ] {
        assert!(parse_manifest(&changed).is_err());
    }
    let mut changed = manifest;
    changed["analysis"]
        .as_object_mut()
        .unwrap()
        .remove("language_id");
    assert!(parse_manifest(&serde_json::to_string(&changed).unwrap()).is_err());
}

#[test]
fn manifest_and_inline_output_limits_are_enforced_individually_and_combined() {
    let (bytes, manifest, policy) = fixture();
    assert!(
        parse_manifest(
            &(" ".repeat(MAX_MANIFEST_BYTES) + &serde_json::to_string(&manifest).unwrap())
        )
        .is_err()
    );
    let mut changed = manifest.clone();
    changed["outputs"] = json!(vec![manifest["outputs"][0].clone(); MAX_OUTPUTS + 1]);
    assert!(validate(&bytes, &changed, &policy).is_err());
    let mut changed = manifest.clone();
    let content = vec![b'x'; MAX_OUTPUT_BYTES + 1];
    changed["outputs"][0]["data_base64"] = json!(STANDARD.encode(&content));
    changed["outputs"][0]["sha256"] = json!(sha256(&content));
    changed["outputs"][0]["size"] = json!(content.len());
    assert!(validate(&bytes, &changed, &policy).is_err());
    let mut changed = manifest.clone();
    let content = vec![b'x'; 140_000];
    let mut large = manifest["outputs"][0].clone();
    large["data_base64"] = json!(STANDARD.encode(&content));
    large["sha256"] = json!(sha256(&content));
    large["size"] = json!(content.len());
    changed["outputs"] = json!([large.clone(), large]);
    assert!(serde_json::to_vec(&changed).unwrap().len() < MAX_MANIFEST_BYTES);
    assert!(validate(&bytes, &changed, &policy).is_err());
}

#[test]
fn defaults_exclude_generic_binary_and_policy_fields_are_strict_and_bounded() {
    let (bytes, manifest, policy) = fixture();
    let mut serialized = serde_json::to_value(&policy).unwrap();
    serialized
        .as_object_mut()
        .unwrap()
        .remove("candidate_kinds");
    serialized
        .as_object_mut()
        .unwrap()
        .remove("informational_warnings");
    let defaults: BinaryAnalysisPolicy = serde_json::from_value(serialized).unwrap();
    assert_eq!(defaults.candidate_kinds, default_candidate_kinds());
    assert!(defaults.informational_warnings.is_empty());
    assert!(!defaults.candidate_kinds.iter().any(|kind| kind == "binary"));
    let mut out_of_scope = policy.clone();
    out_of_scope.candidate_kinds = vec!["pe".into()];
    assert!(!validate(&bytes, &manifest, &out_of_scope).unwrap().complete);
    for field in [
        "identity_sha256",
        "required_capabilities",
        "candidate_kinds",
        "service",
    ] {
        let mut changed = serde_json::to_value(&policy).unwrap();
        changed[field] = match field {
            "identity_sha256" => json!("a".repeat(63)),
            "service" => json!("../tool"),
            "required_capabilities" => json!(["decompile", "decompile"]),
            _ => json!(["elf", "image"]),
        };
        let parsed: BinaryAnalysisPolicy = serde_json::from_value(changed).unwrap();
        assert!(parsed.validate().is_err());
    }
    for warnings in [
        vec!["duplicate".into(), "duplicate".into()],
        vec!["".into()],
        vec!["invalid\0warning".into()],
        vec!["x".repeat(4097)],
        (0..33).map(|n| format!("warning {n}")).collect(),
    ] {
        let mut invalid = policy.clone();
        invalid.informational_warnings = warnings;
        assert!(invalid.validate().is_err());
    }
}
