use base64::{Engine, engine::general_purpose::STANDARD};
use packweir::{
    config::{CommandScanner, Config, PinnedResource, ScannerDriver},
    model::{Outcome, sha256},
    scanner,
    store::Job,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::OnceLock,
};

fn fixture_program() -> &'static Path {
    static PROGRAM: OnceLock<PathBuf> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/scanner-fixture");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("scanner-fixture{}", std::env::consts::EXE_SUFFIX));
        let status = std::process::Command::new("rustc")
            .args(["--edition=2024", "tests/support/scanner_fixture.rs", "-o"])
            .arg(&path)
            .status()
            .expect("Rust compiler required for test subprocess fixture");
        assert!(status.success());
        path
    })
}

pub fn signature(result: &str, bytes: &[u8]) -> Value {
    json!({"kind":"sigstore_bundle", "origin":"publisher_declared", "document":{
        "mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json", "fixture_result":result,
        "messageSignature":{"messageDigest":{"algorithm":"SHA2_256", "digest":STANDARD.encode(hex::decode(sha256(bytes)).unwrap())}},
        "verificationMaterial":{"certificate":{"rawBytes":"fixture"}, "tlogEntries":[{"inclusionProof":{}}]}
    }})
}

fn job(bytes: &[u8]) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        subject: sha256(bytes),
        configuration: "fixture-configuration".into(),
        filename: "fixture".into(),
        lease: uuid::Uuid::new_v4(),
        context_revision: 0,
    }
}

fn verifier(directory: &Path) -> CommandScanner {
    let root = directory.join("root.json");
    std::fs::write(&root, b"trusted-root fixture").unwrap();
    CommandScanner {
        program: fixture_program().to_string_lossy().into_owned(),
        args: vec![],
        version: "test-fixture".into(),
        timeout_seconds: 2,
        environment: BTreeMap::new(),
        program_sha256: Some(sha256(&std::fs::read(fixture_program()).unwrap())),
        resources: BTreeMap::from([(
            "root".into(),
            PinnedResource {
                path: root.to_string_lossy().into_owned(),
                sha256: sha256(b"trusted-root fixture"),
            },
        )]),
        driver: ScannerDriver::Sigstore {
            certificate_identity: "fixture@example.test".into(),
            certificate_oidc_issuer: "https://issuer.example.test".into(),
            trusted_root: "root".into(),
        },
    }
}

#[test]
fn verifier_configuration_rejects_weakened_or_mislabelled_verification() {
    let temp = tempfile::tempdir().unwrap();
    let scanner = verifier(temp.path());
    scanner.validate().unwrap();
    let mut bad = scanner.clone();
    bad.program_sha256 = None;
    assert!(bad.validate().is_err());
    let mut bad = scanner.clone();
    bad.args.push("--insecure-ignore-tlog".into());
    assert!(bad.validate().is_err());
    let mut bad = scanner.clone();
    bad.environment
        .insert("COSIGN_EXPERIMENTAL".into(), "1".into());
    assert!(bad.validate().is_err());
    let mut bad = scanner.clone();
    bad.resources.clear();
    assert!(bad.validate().is_err());
    let mut bad = scanner.clone();
    bad.resources.get_mut("root").unwrap().sha256 = "not-a-digest".into();
    assert!(bad.validate().is_err());
    let mut bad = scanner.clone();
    bad.driver = ScannerDriver::Sigstore {
        certificate_identity: " ".into(),
        certificate_oidc_issuer: "issuer".into(),
        trusted_root: "root".into(),
    };
    assert!(bad.validate().is_err());
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    for name in [
        "agent",
        "provenance",
        "inventory",
        "integrity",
        "archive_safety",
    ] {
        config.scanners.clear();
        config.scanners.insert(name.into(), scanner.clone());
        assert!(config.validate().is_err());
    }
}

#[test]
fn tool_resource_and_identity_revisions_change_evidence_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    config
        .scanners
        .insert("required_signature".into(), verifier(temp.path()));
    let original = config.fingerprint();
    let mut changed = config.clone();
    changed
        .scanners
        .get_mut("required_signature")
        .unwrap()
        .resources
        .get_mut("root")
        .unwrap()
        .sha256 = "a".repeat(64);
    assert_ne!(original, changed.fingerprint());
    let mut changed = config.clone();
    changed
        .scanners
        .get_mut("required_signature")
        .unwrap()
        .program_sha256 = Some("b".repeat(64));
    assert_ne!(original, changed.fingerprint());
    let mut changed = config;
    if let ScannerDriver::Sigstore {
        certificate_identity,
        ..
    } = &mut changed
        .scanners
        .get_mut("required_signature")
        .unwrap()
        .driver
    {
        *certificate_identity = "other@example.test".into();
    }
    assert_ne!(original, changed.fingerprint());
}

#[test]
fn sigstore_configuration_roundtrips_toml_and_legacy_commands_keep_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    config
        .scanners
        .insert("required_signature".into(), verifier(temp.path()));
    let serialized = toml::to_string(&config).unwrap();
    let decoded: Config = toml::from_str(&serialized).unwrap();
    decoded.validate().unwrap();
    assert_eq!(config.fingerprint(), decoded.fingerprint());
    let legacy: CommandScanner =
        serde_json::from_value(json!({"program":fixture_program(), "version":"legacy"})).unwrap();
    legacy.validate().unwrap();
    assert!(matches!(legacy.driver, ScannerDriver::Command));
    assert!(legacy.resources.is_empty());
    assert!(legacy.program_sha256.is_none());
}

#[tokio::test]
async fn protocol_adapter_receives_verified_read_only_resource_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let mut scanner = verifier(temp.path());
    scanner.driver = ScannerDriver::Command;
    scanner.args = vec!["protocol".into()];
    let policy = temp.path().join("policy.kdl");
    std::fs::write(&policy, b"policy fixture").unwrap();
    scanner.resources = BTreeMap::from([(
        "policy".into(),
        PinnedResource {
            path: policy.to_string_lossy().into_owned(),
            sha256: sha256(b"policy fixture"),
        },
    )]);
    let result = scanner::run(&scanner, &job(b"fixture"), b"fixture", &json!({}))
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["resource_seen"], true);
}

#[tokio::test]
async fn substituted_program_resource_and_subject_cannot_run() {
    let temp = tempfile::tempdir().unwrap();
    let scanner = verifier(temp.path());
    let bundle = json!({"documents":[signature("pass", b"fixture")]});
    let mut changed = scanner.clone();
    changed.program_sha256 = Some("0".repeat(64));
    assert!(
        scanner::run(&changed, &job(b"fixture"), b"fixture", &bundle)
            .await
            .is_err()
    );
    std::fs::write(&scanner.resources["root"].path, b"substituted root").unwrap();
    assert!(
        scanner::run(&scanner, &job(b"fixture"), b"fixture", &bundle)
            .await
            .is_err()
    );
    assert!(
        scanner::run(&scanner, &job(b"other"), b"fixture", &bundle)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sigstore_driver_binds_success_to_subject_signer_root_and_bundle() {
    let temp = tempfile::tempdir().unwrap();
    let scanner = verifier(temp.path());
    let document = signature("pass", b"fixture");
    let digest = sha256(&serde_json::to_vec(&document["document"]).unwrap());
    let bundle = json!({"documents":[signature("reject", b"fixture"), document]});
    let result = scanner::run(&scanner, &job(b"fixture"), b"fixture", &bundle)
        .await
        .unwrap();
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.details["verified_subject"], sha256(b"fixture"));
    assert_eq!(result.details["bundle_digest"], digest);
    assert_eq!(
        result.details["evidence_digest"],
        sha256(&serde_json::to_vec(&bundle).unwrap())
    );
    assert_eq!(
        result.details["trusted_root_digest"],
        scanner.resources["root"].sha256
    );
    for field in [
        "trusted_identity",
        "signature_verified",
        "policy_matched",
        "transparency_verified",
    ] {
        assert_eq!(result.details[field], true);
    }
    let mut current_type = signature("pass", b"fixture");
    current_type["document"]["mediaType"] =
        json!("application/vnd.dev.sigstore.bundle+json;version=0.3");
    assert_eq!(
        scanner::run(
            &scanner,
            &job(b"fixture"),
            b"fixture",
            &json!({"documents":[current_type]})
        )
        .await
        .unwrap()
        .outcome,
        Outcome::Pass
    );
}

#[tokio::test]
async fn missing_unsupported_unbound_or_unproven_bundles_never_approve() {
    let temp = tempfile::tempdir().unwrap();
    let scanner = verifier(temp.path());
    let base = signature("pass", b"fixture");
    let mut dsse = base.clone();
    dsse["document"]["dsseEnvelope"] = json!({});
    let mut no_log = base.clone();
    no_log["document"]["verificationMaterial"]["tlogEntries"] = json!([]);
    let mut no_cert = base.clone();
    no_cert["document"]["verificationMaterial"]["certificate"] = Value::Null;
    let mut old_format = base;
    old_format["document"]["mediaType"] = json!("legacy");
    for documents in [
        vec![],
        vec![signature("pass", b"other")],
        vec![dsse],
        vec![no_log],
        vec![no_cert],
        vec![old_format],
        vec![signature("reject", b"fixture")],
        vec![signature("pass", b"fixture"); 9],
    ] {
        let result = scanner::run(
            &scanner,
            &job(b"fixture"),
            b"fixture",
            &json!({"documents":documents}),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, Outcome::Inconclusive);
    }
    let mut wrong_document = signature("pass", b"fixture");
    wrong_document["blob_digest"] = json!("0".repeat(64));
    assert!(
        scanner::run(
            &scanner,
            &job(b"fixture"),
            b"fixture",
            &json!({"documents":[wrong_document]})
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn sigstore_subprocess_timeout_and_output_limits_cannot_approve() {
    let temp = tempfile::tempdir().unwrap();
    let mut scanner = verifier(temp.path());
    scanner.timeout_seconds = 1;
    for mode in ["sleep", "huge"] {
        assert!(
            scanner::run(
                &scanner,
                &job(b"fixture"),
                b"fixture",
                &json!({"documents":[signature(mode, b"fixture")]})
            )
            .await
            .is_err()
        );
    }
    let candidates = json!({"documents":[signature("slow-reject", b"fixture"), signature("slow-reject", b"fixture")]});
    assert!(
        scanner::run(&scanner, &job(b"fixture"), b"fixture", &candidates)
            .await
            .is_err(),
        "candidate attempts must share one timeout budget"
    );
}

#[tokio::test]
async fn resource_and_executable_sizes_are_bounded_before_execution() {
    let temp = tempfile::tempdir().unwrap();
    let mut scanner = verifier(temp.path());
    let large = temp.path().join("large-resource");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(8 * 1024 * 1024 + 1)
        .unwrap();
    scanner.resources.get_mut("root").unwrap().path = large.to_string_lossy().into_owned();
    assert!(
        scanner::run(&scanner, &job(b"fixture"), b"fixture", &json!({}))
            .await
            .is_err()
    );
    let mut scanner = verifier(temp.path());
    let large = temp.path().join("large-executable");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(256 * 1024 * 1024 + 1)
        .unwrap();
    scanner.program = large.to_string_lossy().into_owned();
    assert!(
        scanner::run(&scanner, &job(b"fixture"), b"fixture", &json!({}))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires PACKWEIR_TEST_COSIGN pointing to the pinned Cosign 3.1.4 executable"]
async fn real_cosign_checks_upstream_signature_and_rejects_tampering() {
    let program = std::env::var("PACKWEIR_TEST_COSIGN").unwrap();
    let bytes = include_bytes!("fixtures/sigstore/cosign_checksums.txt");
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigstore/trusted_root.json");
    let signature: Value = serde_json::from_slice(include_bytes!(
        "fixtures/sigstore/cosign_checksums.txt.sigstore.json"
    ))
    .unwrap();
    let bundle = json!({"documents":[{"kind":"sigstore_bundle", "document":signature}]});
    let scanner = CommandScanner {
        program_sha256: Some(sha256(&std::fs::read(&program).unwrap())),
        program,
        version: "3.1.4".into(),
        args: vec![],
        timeout_seconds: 20,
        environment: BTreeMap::new(),
        resources: BTreeMap::from([(
            "root".into(),
            PinnedResource {
                sha256: sha256(&std::fs::read(&root).unwrap()),
                path: root.to_string_lossy().into_owned(),
            },
        )]),
        driver: ScannerDriver::Sigstore {
            certificate_identity: "keyless@projectsigstore.iam.gserviceaccount.com".into(),
            certificate_oidc_issuer: "https://accounts.google.com".into(),
            trusted_root: "root".into(),
        },
    };
    assert_eq!(
        scanner::run(&scanner, &job(bytes), bytes, &bundle)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    let mut current_type = bundle.clone();
    current_type["documents"][0]["document"]["mediaType"] =
        json!("application/vnd.dev.sigstore.bundle+json;version=0.3");
    assert_eq!(
        scanner::run(&scanner, &job(bytes), bytes, &current_type)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    for wrong_issuer in [false, true] {
        let mut wrong = scanner.clone();
        if let ScannerDriver::Sigstore {
            certificate_identity,
            certificate_oidc_issuer,
            ..
        } = &mut wrong.driver
        {
            if wrong_issuer {
                *certificate_oidc_issuer = "https://attacker.example".into();
            } else {
                *certificate_identity = "attacker@example.test".into();
            }
        }
        assert_ne!(
            scanner::run(&wrong, &job(bytes), bytes, &bundle)
                .await
                .unwrap()
                .outcome,
            Outcome::Pass
        );
    }
    let mut tampered = bundle.clone();
    tampered["documents"][0]["document"]["messageSignature"]["signature"] =
        json!(STANDARD.encode([0; 64]));
    assert_ne!(
        scanner::run(&scanner, &job(bytes), bytes, &tampered)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    let mut tampered = bundle.clone();
    tampered["documents"][0]["document"]["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        ["rootHash"] = json!(STANDARD.encode([0; 32]));
    assert_ne!(
        scanner::run(&scanner, &job(bytes), bytes, &tampered)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    assert_ne!(
        scanner::run(&scanner, &job(&changed), &changed, &bundle)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
}
