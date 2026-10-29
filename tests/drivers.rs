mod support;
use chrono::{Duration, Utc};
use packweir::{
    config::{
        CommandScanner, Config, OsvDatabase, PackageBinding, PinnedResource, ScannerDriver,
        SourceBinding,
    },
    model::{Outcome, sha256},
    scanner,
    store::Job,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    path::Path,
};
use support::fixture_program;

const REVISION: &str = "1111111111111111111111111111111111111111";
const BUILDER: &str =
    "https://github.com/example/builder/.github/workflows/build.yml@refs/tags/v1.0.0";

fn source() -> SourceBinding {
    SourceBinding {
        repository: "npm".into(),
        origin: "https://registry.example.test/package.tgz".into(),
        source_uri: "https://github.com/example/project".into(),
        source_revision: REVISION.into(),
    }
}
fn package() -> PackageBinding {
    PackageBinding {
        repository: source().repository,
        origin: source().origin,
        ecosystem: "npm".into(),
        name: "ansi-html".into(),
        version: "0.0.7".into(),
    }
}
fn bundle() -> Value {
    json!({"identities":[{"repository":source().repository,"origin":source().origin}],"documents":[{"kind":"attestation","document":{"test":"mocked verification input"}}]})
}
fn job() -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        subject: sha256(b"fixture"),
        configuration: "test".into(),
        filename: "fixture".into(),
        lease: uuid::Uuid::new_v4(),
        context_revision: 0,
    }
}
fn report() -> Value {
    json!({"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2", "subject":[{"digest":{"sha256":sha256(b"fixture")}}], "predicate":{"builder":{"id":BUILDER},"invocation":{"configSource":{"uri":"git+https://github.com/example/project@refs/tags/v1.0.0","digest":{"sha1":REVISION}}}}})
}
fn hipcheck_report() -> Value {
    json!({"repo_owner":"example","repo_name":"project","repo_head":REVISION,"hipcheck_version":"3.15.0",
    "passing":[{"name":"example/custom","passed":true,"value":{"observed":3}}],"failing":[],"errored":[],"recommendation":{"kind":"Pass"}})
}
fn osv_report(vulnerable: bool) -> Value {
    json!({"results":[{"source":{"type":"lockfile"},"packages":[{"package":{"ecosystem":"npm","name":"ansi-html","version":"0.0.7"},"vulnerabilities":if vulnerable {json!([{"id":"GHSA-test","modified":"2026-10-01T00:00:00Z"}])} else {json!([])}}]}]})
}
fn resource(path: &Path, bytes: &[u8]) -> PinnedResource {
    std::fs::write(path, bytes).unwrap();
    PinnedResource {
        path: path.to_string_lossy().into_owned(),
        sha256: sha256(bytes),
    }
}
fn archive(path: &str) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(path, zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"{}").unwrap();
    zip.finish().unwrap().into_inner()
}
fn database(temp: &Path) -> OsvDatabase {
    let path = temp.join("npm.zip");
    let bytes = archive("TEST.json");
    std::fs::write(&path, &bytes).unwrap();
    OsvDatabase {
        path: path.to_string_lossy().into_owned(),
        sha256: sha256(&bytes),
        revision: "test-snapshot".into(),
        published_at: Utc::now() - Duration::hours(1),
        expires_at: Utc::now() + Duration::hours(1),
    }
}
fn scanner(temp: &Path, driver: ScannerDriver, report: Value, code: i32) -> CommandScanner {
    let mut resources = BTreeMap::from([
        (
            "report".into(),
            resource(
                &temp.join("report.json"),
                &serde_json::to_vec(&report).unwrap(),
            ),
        ),
        (
            "status".into(),
            resource(&temp.join("status"), code.to_string().as_bytes()),
        ),
    ]);
    if matches!(driver, ScannerDriver::Hipcheck { .. }) {
        resources.insert(
            "policy".into(),
            resource(&temp.join("policy.kdl"), b"test policy"),
        );
        resources.insert(
            "execution".into(),
            resource(&temp.join("exec.kdl"), b"test execution configuration"),
        );
    }
    CommandScanner {
        program: fixture_program().to_string_lossy().into_owned(),
        program_sha256: Some(sha256(&std::fs::read(fixture_program()).unwrap())),
        version: "test-double".into(),
        timeout_seconds: 5,
        args: vec![],
        environment: BTreeMap::new(),
        resources,
        driver,
    }
}
fn slsa_driver() -> ScannerDriver {
    ScannerDriver::Slsa {
        builder_id: BUILDER.into(),
        sources: vec![source()],
    }
}
fn hipcheck_driver() -> ScannerDriver {
    ScannerDriver::Hipcheck {
        policy: "policy".into(),
        execution: "execution".into(),
        required_analyses: vec!["example/custom".into()],
        sources: vec![source()],
        plugins: BTreeMap::from([(
            "example/custom".into(),
            PinnedResource {
                path: fixture_program().to_string_lossy().into_owned(),
                sha256: sha256(&std::fs::read(fixture_program()).unwrap()),
            },
        )]),
    }
}

#[tokio::test]
async fn slsa_requires_verified_subject_builder_source_and_exact_commit() {
    let temp = tempfile::tempdir().unwrap();
    let good = report();
    let scanner = scanner(temp.path(), slsa_driver(), good.clone(), 0);
    let output = scanner::run(&scanner, &job(), b"fixture", &bundle())
        .await
        .unwrap();
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(output.details["verified"][0]["statement"], good);
    let mut wrong_commit = good.clone();
    wrong_commit["predicate"]["invocation"]["configSource"]["digest"]["sha1"] =
        json!("2".repeat(40));
    let mut wrong_source = good.clone();
    wrong_source["predicate"]["invocation"]["configSource"]["uri"] =
        json!("git+https://github.com/example/project.evil@refs/tags/v1");
    let mut wrong_builder = good.clone();
    wrong_builder["predicate"]["builder"]["id"] = json!("attacker");
    let mut wrong_subject = good.clone();
    wrong_subject["subject"][0]["digest"]["sha256"] = json!("0".repeat(64));
    let mut unsupported = good;
    unsupported["predicateType"] = json!("unknown");
    for bad in [
        wrong_commit,
        wrong_source,
        wrong_builder,
        wrong_subject,
        unsupported,
    ] {
        let mut scanner = scanner.clone();
        scanner.resources.insert(
            "report".into(),
            resource(
                &temp.path().join("report.json"),
                &serde_json::to_vec(&bad).unwrap(),
            ),
        );
        assert_ne!(
            scanner::run(&scanner, &job(), b"fixture", &bundle())
                .await
                .unwrap()
                .outcome,
            Outcome::Pass
        );
    }
}

#[tokio::test]
async fn slsa_v1_uses_only_the_matching_resolved_source_and_rejects_conflicting_descriptors() {
    let temp = tempfile::tempdir().unwrap();
    let mut report = json!({"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"digest":{"sha256":sha256(b"fixture")}}],
        "predicate":{"runDetails":{"builder":{"id":BUILDER}},"buildDefinition":{"resolvedDependencies":[{"uri":"git+https://github.com/example/project@refs/heads/main","digest":{"gitCommit":REVISION}}]}}});
    let scanner = scanner(temp.path(), slsa_driver(), report.clone(), 0);
    assert_eq!(
        scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    let duplicate = report["predicate"]["buildDefinition"]["resolvedDependencies"][0].clone();
    report["predicate"]["buildDefinition"]["resolvedDependencies"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let mut scanner = scanner;
    scanner.resources.insert(
        "report".into(),
        resource(
            &temp.path().join("report.json"),
            &serde_json::to_vec(&report).unwrap(),
        ),
    );
    assert_eq!(
        scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .unwrap()
            .outcome,
        Outcome::Inconclusive
    );
}

#[tokio::test]
async fn every_registered_alias_requires_a_mapping_for_all_three_drivers() {
    let temp = tempfile::tempdir().unwrap();
    for (driver, report) in [
        (slsa_driver(), report()),
        (hipcheck_driver(), hipcheck_report()),
        (
            ScannerDriver::Osv {
                packages: vec![package()],
                databases: BTreeMap::from([("npm".into(), database(temp.path()))]),
            },
            osv_report(false),
        ),
    ] {
        let scanner = scanner(temp.path(), driver, report, 0);
        let mut evidence = bundle();
        evidence["identities"]
            .as_array_mut()
            .unwrap()
            .push(json!({"repository":"npm","origin":"https://attacker.example/alias.tgz"}));
        assert_eq!(
            scanner::run(&scanner, &job(), b"fixture", &evidence)
                .await
                .unwrap()
                .outcome,
            Outcome::Inconclusive
        );
        assert_eq!(
            scanner::run(&scanner, &job(), b"fixture", &json!({}))
                .await
                .unwrap()
                .outcome,
            Outcome::Inconclusive
        );
    }
}

#[tokio::test]
async fn osv_distinguishes_findings_failures_missing_coverage_and_clean_reports() {
    let temp = tempfile::tempdir().unwrap();
    let driver = ScannerDriver::Osv {
        packages: vec![package()],
        databases: BTreeMap::from([("npm".into(), database(temp.path()))]),
    };
    let mut missing = osv_report(false);
    missing["results"][0]["packages"] = json!([]);
    let mut wrong_version = osv_report(false);
    wrong_version["results"][0]["packages"][0]["package"]["version"] = json!("0.0.8");
    for (report, code, outcome) in [
        (osv_report(false), 0, Outcome::Pass),
        (osv_report(true), 1, Outcome::Fail),
        (osv_report(true), 0, Outcome::Inconclusive),
        (osv_report(false), 1, Outcome::Inconclusive),
        (osv_report(false), 127, Outcome::Error),
        (osv_report(false), 128, Outcome::Unsupported),
        (missing, 0, Outcome::Inconclusive),
        (wrong_version, 0, Outcome::Inconclusive),
    ] {
        let scanner = scanner(temp.path(), driver.clone(), report, code);
        let result = scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .unwrap();
        assert_eq!(result.outcome, outcome);
        if outcome == Outcome::Pass {
            assert!(result.valid_until.is_some());
            assert!(
                result.details["coverage"]
                    .as_str()
                    .unwrap()
                    .contains("transitive")
            );
        }
    }
}

#[tokio::test]
async fn osv_rejects_stale_substituted_and_unsafe_database_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let good = database(temp.path());
    for future in [false, true] {
        let mut snapshot = good.clone();
        if future {
            snapshot.published_at = Utc::now() + Duration::minutes(1);
        } else {
            snapshot.expires_at = Utc::now() - Duration::minutes(1);
        }
        let scanner = scanner(
            temp.path(),
            ScannerDriver::Osv {
                packages: vec![package()],
                databases: BTreeMap::from([("npm".into(), snapshot)]),
            },
            osv_report(false),
            0,
        );
        assert_eq!(
            scanner::run(&scanner, &job(), b"fixture", &bundle())
                .await
                .unwrap()
                .outcome,
            Outcome::Inconclusive
        );
    }
    let mut substituted = good.clone();
    substituted.sha256 = "0".repeat(64);
    let scanner = scanner(
        temp.path(),
        ScannerDriver::Osv {
            packages: vec![package()],
            databases: BTreeMap::from([("npm".into(), substituted)]),
        },
        osv_report(false),
        0,
    );
    assert!(
        scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .is_err()
    );
    let mut cloaked = archive("TEST.json");
    let central = cloaked.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
    cloaked[central + 46..central + 55].copy_from_slice(b"HIDE.json");
    for bytes in [archive("../outside.json"), cloaked] {
        std::fs::write(&good.path, &bytes).unwrap();
        let mut bad = good.clone();
        bad.sha256 = sha256(&bytes);
        let mut scanner = scanner.clone();
        scanner.driver = ScannerDriver::Osv {
            packages: vec![package()],
            databases: BTreeMap::from([("npm".into(), bad)]),
        };
        assert!(
            scanner::run(&scanner, &job(), b"fixture", &bundle())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn hipcheck_requires_explicit_custom_analyses_and_keeps_findings_and_errors() {
    let temp = tempfile::tempdir().unwrap();
    let good = hipcheck_report();
    let mut failure = good.clone();
    failure["failing"] = failure["passing"].take();
    failure["failing"][0]["passed"] = json!(false);
    failure["passing"] = json!([]);
    let mut missing = good.clone();
    missing["passing"] = json!([]);
    let mut investigate = good.clone();
    investigate["recommendation"]["kind"] = json!("Investigate");
    let mut error = good.clone();
    error["errored"] = json!([{"name":"example/other","error":{"msg":"service unavailable"}}]);
    let mut wrong = good.clone();
    wrong["repo_head"] = json!("2".repeat(40));
    for (report, outcome) in [
        (good, Outcome::Pass),
        (failure, Outcome::Fail),
        (missing, Outcome::Inconclusive),
        (investigate, Outcome::Inconclusive),
        (error, Outcome::Inconclusive),
        (wrong, Outcome::Inconclusive),
    ] {
        let scanner = scanner(temp.path(), hipcheck_driver(), report, 0);
        let result = scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .unwrap();
        assert_eq!(result.outcome, outcome);
        if outcome == Outcome::Pass {
            assert_eq!(
                result.details["reports"][0]["report"]["passing"][0]["value"]["observed"],
                3
            );
        }
    }
}

#[test]
fn driver_configuration_rejects_ambiguous_bindings_and_fake_trust_checks() {
    let temp = tempfile::tempdir().unwrap();
    for driver in [
        slsa_driver(),
        hipcheck_driver(),
        ScannerDriver::Osv {
            packages: vec![package()],
            databases: BTreeMap::from([("npm".into(), database(temp.path()))]),
        },
    ] {
        let scanner = scanner(temp.path(), driver.clone(), json!({}), 0);
        scanner.validate().unwrap();
        let mut bad = scanner.clone();
        bad.program_sha256 = None;
        assert!(bad.validate().is_err());
        let mut bad = scanner.clone();
        bad.args.push("--help".into());
        assert!(bad.validate().is_err());
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        let good_name = if matches!(driver, ScannerDriver::Slsa { .. }) {
            "provenance"
        } else {
            "analysis"
        };
        config.scanners.insert(good_name.into(), scanner.clone());
        let decoded: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(config.fingerprint(), decoded.fingerprint());
        config.scanners.clear();
        let name = if matches!(driver, ScannerDriver::Slsa { .. }) {
            "agent"
        } else {
            "provenance"
        };
        config.scanners.insert(name.into(), scanner);
        assert!(config.validate().is_err());
    }
    let mut scanner = scanner(temp.path(), slsa_driver(), json!({}), 0);
    if let ScannerDriver::Slsa { sources, .. } = &mut scanner.driver {
        sources.push(source());
    }
    assert!(scanner.validate().is_err());
    scanner.driver = hipcheck_driver();
    if let ScannerDriver::Hipcheck {
        required_analyses, ..
    } = &mut scanner.driver
    {
        required_analyses.clear();
    }
    assert!(scanner.validate().is_err());
}

#[tokio::test]
async fn raw_attestations_preserve_original_bytes_and_reject_ambiguous_wrappers() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let temp = tempfile::tempdir().unwrap();
    let mut scanner = scanner(temp.path(), slsa_driver(), report(), 0);
    let original = b"{\"z\":2,\n \"a\":1}\n";
    scanner.resources.insert(
        "raw_expected".into(),
        resource(&temp.path().join("raw"), original),
    );
    let mut evidence = bundle();
    evidence["documents"][0]["document"] = json!({"raw_base64":STANDARD.encode(original)});
    assert_eq!(
        scanner::run(&scanner, &job(), b"fixture", &evidence)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    evidence["documents"][0]["document"]["other"] = json!(true);
    assert!(
        scanner::run(&scanner, &job(), b"fixture", &evidence)
            .await
            .is_err()
    );
    evidence["documents"][0]["document"] = json!({"raw_base64":"not-base64"});
    assert!(
        scanner::run(&scanner, &job(), b"fixture", &evidence)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn hipcheck_plugin_substitution_and_contradictory_reports_cannot_approve() {
    let temp = tempfile::tempdir().unwrap();
    let mut scanner = scanner(temp.path(), hipcheck_driver(), hipcheck_report(), 0);
    if let ScannerDriver::Hipcheck { plugins, .. } = &mut scanner.driver {
        plugins.get_mut("example/custom").unwrap().sha256 = "0".repeat(64);
    }
    assert!(
        scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .is_err()
    );
    scanner.driver = hipcheck_driver();
    let mut duplicate = hipcheck_report();
    duplicate["failing"] = duplicate["passing"].clone();
    duplicate["failing"][0]["passed"] = json!(false);
    let mut contradictory = hipcheck_report();
    contradictory["passing"][0]["passed"] = json!(false);
    for report in [duplicate, contradictory] {
        scanner.resources.insert(
            "report".into(),
            resource(
                &temp.path().join("report.json"),
                &serde_json::to_vec(&report).unwrap(),
            ),
        );
        assert!(
            scanner::run(&scanner, &job(), b"fixture", &bundle())
                .await
                .is_err()
        );
    }
}
