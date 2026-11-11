use packweir::{
    config::{CommandScanner, PinnedResource, ScannerDriver},
    licenses::{LicenseDecision, LicensePolicy, SCANCODE_VERSION},
    model::{Outcome, sha256},
    scanner,
    store::Job,
};
use serde_json::{Value, json};
use sha1::Digest;
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

fn policy() -> LicensePolicy {
    LicensePolicy {
        allowed: vec!["MIT".into(), "Apache-2.0".into()],
        denied: vec!["GPL-3.0-only".into()],
        allow_unknown: false,
    }
}
fn job(bytes: &[u8], name: &str) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        subject: sha256(bytes),
        configuration: "license-test".into(),
        filename: name.into(),
        lease: uuid::Uuid::new_v4(),
        context_revision: 0,
    }
}
fn fixture() -> &'static Path {
    static PROGRAM: OnceLock<PathBuf> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/license-fixture")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let program = directory.join(format!("license-fixture{}", std::env::consts::EXE_SUFFIX));
        let status = std::process::Command::new("rustc")
            .args(["--edition=2024"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/license_fixture.rs"))
            .arg("-o")
            .arg(&program)
            .status()
            .unwrap();
        assert!(status.success());
        program
    })
}
fn report(bytes: &[u8], expression: Value) -> Value {
    let detections = expression
        .as_str()
        .map(|e| json!([{"license_expression_spdx":e}]))
        .unwrap_or_else(|| json!([]));
    json!({"headers":[{"tool_name":"scancode-toolkit","tool_version":SCANCODE_VERSION,"options":{"input":["__INPUT__"],"--license":true,"--copyright":true,"--package":true,"--info":true,"--strip-root":true},
        "errors":[],"end_timestamp":"2026-11-11T00:00:00Z","extra_data":{"files_count":1}}],
        "files":[{"path":"f00000/LICENSE","type":"file","size":bytes.len(),"sha1":hex::encode(sha1::Sha1::digest(bytes)),"scan_errors":[],"detected_license_expression_spdx":expression,"license_detections":detections,"license_clues":[],"copyrights":[],"package_data":[]}]})
}
fn resource(directory: &Path, name: &str, bytes: &[u8]) -> PinnedResource {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    PinnedResource {
        path: path.to_string_lossy().into(),
        sha256: sha256(bytes),
    }
}
fn scanner(directory: &Path, report: &Value, policy: LicensePolicy, mode: &str) -> CommandScanner {
    CommandScanner {
        program: fixture().to_string_lossy().into(),
        args: vec![],
        version: SCANCODE_VERSION.into(),
        timeout_seconds: 3,
        environment: BTreeMap::new(),
        program_sha256: Some(sha256(&std::fs::read(fixture()).unwrap())),
        resources: BTreeMap::from([
            (
                "report".into(),
                resource(
                    directory,
                    "report.json",
                    &serde_json::to_vec(report).unwrap(),
                ),
            ),
            ("mode".into(), resource(directory, "mode", mode.as_bytes())),
        ]),
        driver: ScannerDriver::Scancode { policy },
    }
}

#[test]
fn spdx_boolean_choices_exceptions_and_custom_references_keep_their_meaning() {
    let policy = policy();
    policy.validate().unwrap();
    let choice = policy.assess("GPL-3.0-only OR MIT").unwrap();
    assert_eq!(choice.decision, LicenseDecision::Allowed);
    assert_eq!(choice.acceptable_branch, Some(vec!["MIT".into()]));
    assert_eq!(
        policy.assess("MIT AND GPL-3.0-only").unwrap().decision,
        LicenseDecision::Denied
    );
    assert_eq!(
        policy
            .assess("(MIT OR GPL-3.0-only) AND Apache-2.0")
            .unwrap()
            .decision,
        LicenseDecision::Allowed
    );
    assert_eq!(
        policy.assess("LicenseRef-Private").unwrap().decision,
        LicenseDecision::Unknown
    );
    assert_eq!(
        policy.assess("LicenseRef-Private OR MIT").unwrap().decision,
        LicenseDecision::Allowed
    );
    assert_eq!(
        policy
            .assess("LicenseRef-Private AND GPL-3.0-only")
            .unwrap()
            .decision,
        LicenseDecision::Denied
    );
    let mut exception = policy.clone();
    exception
        .allowed
        .push("GPL-2.0-only WITH Classpath-exception-2.0".into());
    exception.allowed.push("LicenseRef-Private".into());
    exception.validate().unwrap();
    assert_eq!(
        exception
            .assess("GPL-2.0-only WITH Classpath-exception-2.0")
            .unwrap()
            .decision,
        LicenseDecision::Allowed
    );
    assert_eq!(
        exception.assess("GPL-2.0-only").unwrap().decision,
        LicenseDecision::Denied
    );
    assert_eq!(
        exception.assess("LicenseRef-Private").unwrap().decision,
        LicenseDecision::Allowed
    );
    for bad in [
        "MIT OR",
        "definitely-not-a-license",
        "MIT WITH no-such-exception",
    ] {
        assert!(policy.assess(bad).is_err());
    }
    for invalid in [
        LicensePolicy {
            allowed: vec!["MIT OR Apache-2.0".into()],
            ..policy.clone()
        },
        LicensePolicy {
            allowed: vec!["MIT".into()],
            denied: vec!["MIT".into()],
            allow_unknown: false,
        },
        LicensePolicy {
            allowed: vec![],
            ..policy
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[tokio::test]
async fn license_driver_distinguishes_detected_declared_unknown_and_conflicting_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let bytes = b"license fixture";
    for (expression, expected) in [
        (json!("MIT"), Outcome::Pass),
        (json!("MIT OR GPL-3.0-only"), Outcome::Pass),
        (json!("MIT AND GPL-3.0-only"), Outcome::Fail),
        (json!("LicenseRef-Private"), Outcome::Inconclusive),
        (Value::Null, Outcome::Inconclusive),
    ] {
        let report = report(bytes, expression);
        let scanner = scanner(directory.path(), &report, policy(), "");
        let result = scanner::run(
            &scanner,
            &job(bytes, "LICENSE"),
            bytes,
            &json!({"documents":[{"kind":"sbom","document":{"license":"MIT"}}]}),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, expected);
        assert_eq!(result.details["files"][0]["sha256"], sha256(bytes));
    }
    let mut declared = report(bytes, Value::Null);
    declared["files"][0]["package_data"] = json!([{"declared_license_expression_spdx":"MIT"}]);
    let result = scanner::run(
        &scanner(directory.path(), &declared, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    let mut conflicting = report(bytes, json!("MIT"));
    conflicting["files"][0]["package_data"] =
        json!([{"declared_license_expression_spdx":"Apache-2.0"}]);
    let result = scanner::run(
        &scanner(directory.path(), &conflicting, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    assert_eq!(result.details["files"][0]["conflicting"], true);
    let mut permissive = policy();
    permissive.allow_unknown = true;
    let result = scanner::run(
        &scanner(directory.path(), &declared, permissive.clone(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["files"][0]["unknown_allowed"], true);
    let result = scanner::run(
        &scanner(
            directory.path(),
            &report(bytes, json!("LicenseRef-Untrusted")),
            permissive,
            "",
        ),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
}

#[tokio::test]
async fn partial_substituted_and_failed_license_scans_cannot_approve() {
    let directory = tempfile::tempdir().unwrap();
    let bytes = b"license fixture";
    let good = report(bytes, json!("MIT"));
    let mut bad = Vec::new();
    let mut report = good.clone();
    report["files"] = json!([]);
    bad.push(report);
    let mut report = good.clone();
    report["files"][0]["sha1"] = json!("0".repeat(40));
    bad.push(report);
    let mut report = good.clone();
    report["files"][0]["scan_errors"] = json!(["timed out"]);
    bad.push(report);
    let mut report = good.clone();
    report["files"][0]["path"] = json!("../outside");
    bad.push(report);
    let mut report = good.clone();
    report["headers"][0]["options"]["--license"] = json!(false);
    bad.push(report);
    let mut report = good.clone();
    report["headers"][0]["tool_version"] = json!("unqualified");
    bad.push(report);
    let mut report = good.clone();
    report["headers"][0]["errors"] = json!(["scan failed"]);
    bad.push(report);
    let mut report = good.clone();
    report["files"][0]
        .as_object_mut()
        .unwrap()
        .remove("detected_license_expression_spdx");
    bad.push(report);
    let mut report = good.clone();
    report["files"]
        .as_array_mut()
        .unwrap()
        .push(good["files"][0].clone());
    bad.push(report);
    for report in bad {
        assert!(
            scanner::run(
                &scanner(directory.path(), &report, policy(), ""),
                &job(bytes, "LICENSE"),
                bytes,
                &json!({})
            )
            .await
            .is_err()
        );
    }
    let mut contradiction = good.clone();
    contradiction["files"][0]["license_detections"] =
        json!([{"license_expression_spdx":"GPL-3.0-only"}]);
    let result = scanner::run(
        &scanner(directory.path(), &contradiction, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    let mut clues = good.clone();
    clues["files"][0]["license_clues"] = json!([{"license_expression_spdx":"GPL-3.0-only"}]);
    let result = scanner::run(
        &scanner(directory.path(), &clues, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Inconclusive);
    let mut reordered = self::report(bytes, json!("MIT AND Apache-2.0"));
    reordered["files"][0]["license_detections"] =
        json!([{"license_expression_spdx":"Apache-2.0"},{"license_expression_spdx":"MIT"}]);
    let result = scanner::run(
        &scanner(directory.path(), &reordered, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    let mut absorbed = self::report(bytes, json!("MIT OR (MIT AND Apache-2.0)"));
    absorbed["files"][0]["license_detections"] = json!([{"license_expression_spdx":"MIT"}]);
    let result = scanner::run(
        &scanner(directory.path(), &absorbed, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    let mut declaration_order = self::report(bytes, json!("MIT OR Apache-2.0"));
    declaration_order["files"][0]["package_data"] =
        json!([{"declared_license_expression_spdx":"Apache-2.0 OR MIT"}]);
    let result = scanner::run(
        &scanner(directory.path(), &declaration_order, policy(), ""),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    for mode in ["mutate", "huge", "sleep"] {
        let mut config = scanner(directory.path(), &good, policy(), mode);
        config.timeout_seconds = 1;
        assert!(
            scanner::run(&config, &job(bytes, "LICENSE"), bytes, &json!({}))
                .await
                .is_err()
        );
    }
    let result = scanner::run(
        &scanner(directory.path(), &good, policy(), "exit"),
        &job(bytes, "LICENSE"),
        bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Error);
}

#[tokio::test]
async fn bounded_archive_leaves_are_scanned_and_traversal_is_rejected_before_the_tool() {
    let directory = tempfile::tempdir().unwrap();
    let content = b"license fixture";
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("LICENSE", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(content).unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    let result = scanner::run(
        &scanner(
            directory.path(),
            &report(content, json!("MIT")),
            policy(),
            "",
        ),
        &job(&bytes, "package.whl"),
        &bytes,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["files"][0]["path"], "package.whl!/LICENSE");
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("../LICENSE", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(content).unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    assert!(
        scanner::run(
            &scanner(
                directory.path(),
                &report(content, json!("MIT")),
                policy(),
                ""
            ),
            &job(&bytes, "package.whl"),
            &bytes,
            &json!({})
        )
        .await
        .is_err()
    );
    let tar_bytes = |name: &str| {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, &content[..])
            .unwrap();
        builder.into_inner().unwrap()
    };
    let compress = |bytes: &[u8]| {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    };
    let tgz = compress(&tar_bytes("LICENSE"));
    let result = scanner::run(
        &scanner(
            directory.path(),
            &report(content, json!("MIT")),
            policy(),
            "",
        ),
        &job(&tgz, "package.tgz"),
        &tgz,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    let mut concatenated = tgz;
    concatenated.extend(compress(&tar_bytes("COPYING")));
    assert!(
        scanner::run(
            &scanner(
                directory.path(),
                &report(content, json!("MIT")),
                policy(),
                ""
            ),
            &job(&concatenated, "package.tgz"),
            &concatenated,
            &json!({})
        )
        .await
        .is_err()
    );
    let mut alias = zip::ZipWriter::new(Cursor::new(Vec::new()));
    alias
        .start_file("a", zip::write::SimpleFileOptions::default())
        .unwrap();
    alias.write_all(content).unwrap();
    alias
        .start_file("a!/LICENSE", zip::write::SimpleFileOptions::default())
        .unwrap();
    alias.write_all(content).unwrap();
    let alias = alias.finish().unwrap().into_inner();
    assert!(
        scanner::run(
            &scanner(
                directory.path(),
                &report(content, json!("MIT")),
                policy(),
                "exit"
            ),
            &job(&alias, "package.whl"),
            &alias,
            &json!({})
        )
        .await
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires PACKWEIR_TEST_SCANCODE pointing to ScanCode Toolkit 32.5.0"]
async fn real_scancode_reports_complete_leaf_licenses_and_holds_unknowns() {
    let program = std::env::var("PACKWEIR_TEST_SCANCODE").expect("PACKWEIR_TEST_SCANCODE required");
    let config = CommandScanner {
        program: program.clone(),
        args: vec![],
        version: SCANCODE_VERSION.into(),
        timeout_seconds: 300,
        environment: BTreeMap::new(),
        program_sha256: Some(sha256(&std::fs::read(program).unwrap())),
        resources: BTreeMap::new(),
        driver: ScannerDriver::Scancode { policy: policy() },
    };
    let mit = b"SPDX-License-Identifier: MIT\nCopyright 2026 Packweir test contributors\n";
    let clean = scanner::run(&config, &job(mit, "LICENSE"), mit, &json!({}))
        .await
        .unwrap();
    assert_eq!(clean.outcome, Outcome::Pass, "{}", clean.details);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("LICENSE", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(mit).unwrap();
    let package = zip.finish().unwrap().into_inner();
    let packaged = scanner::run(&config, &job(&package, "fixture.whl"), &package, &json!({}))
        .await
        .unwrap();
    assert_eq!(packaged.outcome, Outcome::Pass, "{}", packaged.details);
    let unknown = b"plain payload without any licensing declaration";
    let unresolved = scanner::run(&config, &job(unknown, "payload.txt"), unknown, &json!({}))
        .await
        .unwrap();
    assert_eq!(
        unresolved.outcome,
        Outcome::Inconclusive,
        "{}",
        unresolved.details
    );
    let denied = b"SPDX-License-Identifier: GPL-3.0-only\n";
    let denied = scanner::run(&config, &job(denied, "LICENSE"), denied, &json!({}))
        .await
        .unwrap();
    assert_eq!(denied.outcome, Outcome::Fail, "{}", denied.details);
}
