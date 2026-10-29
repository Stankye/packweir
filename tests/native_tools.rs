use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use packweir::{
    config::{
        CommandScanner, OsvDatabase, PackageBinding, PinnedResource, ScannerDriver, SourceBinding,
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

fn source(uri: &str, revision: &str) -> SourceBinding {
    SourceBinding {
        repository: "npm".into(),
        origin: "https://registry.example.test/fixture.tgz".into(),
        source_uri: uri.into(),
        source_revision: revision.into(),
    }
}
fn evidence(source: &SourceBinding) -> Value {
    json!({"identities":[{"repository":source.repository,"origin":source.origin}],"documents":[]})
}
fn job(bytes: &[u8]) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        subject: sha256(bytes),
        configuration: "native-test".into(),
        filename: "fixture".into(),
        lease: uuid::Uuid::new_v4(),
        context_revision: 0,
    }
}
fn scanner(variable: &str, version: &str, driver: ScannerDriver) -> CommandScanner {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let program = std::env::var(variable).expect("native test executable path required");
    CommandScanner {
        program_sha256: Some(sha256(&std::fs::read(&program).unwrap())),
        program,
        version: version.into(),
        args: vec![],
        environment: BTreeMap::new(),
        resources: BTreeMap::new(),
        driver,
        timeout_seconds: 180,
    }
}
fn pinned(path: &Path) -> PinnedResource {
    PinnedResource {
        path: path.to_string_lossy().into_owned(),
        sha256: sha256(&std::fs::read(path).unwrap()),
    }
}

#[tokio::test]
#[ignore = "requires PACKWEIR_TEST_SLSA pointing to SLSA Verifier 2.7.1 and transparency-log connectivity"]
async fn real_slsa_verifies_its_release_and_rejects_wrong_source_revision() {
    let expected = source(
        "https://github.com/slsa-framework/slsa-verifier",
        "ea584f4502babc6f60d9bc799dbbb13c1caa9ee6",
    );
    let builder = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.0.0";
    let scanner = scanner(
        "PACKWEIR_TEST_SLSA",
        "2.7.1",
        ScannerDriver::Slsa {
            builder_id: builder.into(),
            sources: vec![expected.clone()],
        },
    );
    let bytes = std::fs::read(&scanner.program).unwrap();
    let provenance = if cfg!(windows) {
        include_bytes!("fixtures/slsa/slsa-verifier-windows-amd64.exe.intoto.jsonl").as_slice()
    } else {
        include_bytes!("fixtures/slsa/slsa-verifier-linux-amd64.intoto.jsonl").as_slice()
    };
    let mut bundle = evidence(&expected);
    bundle["documents"] =
        json!([{"kind":"attestation","document":{"raw_base64":STANDARD.encode(provenance)}}]);
    let output = scanner::run(&scanner, &job(&bytes), &bytes, &bundle)
        .await
        .unwrap();
    assert_eq!(output.outcome, Outcome::Pass, "{:?}", output.details);
    assert_eq!(
        output.details["verified"][0]["source_revision"],
        expected.source_revision
    );
    let mut wrong = scanner.clone();
    if let ScannerDriver::Slsa { sources, .. } = &mut wrong.driver {
        sources[0].source_revision = "0".repeat(40);
    }
    assert_ne!(
        scanner::run(&wrong, &job(&bytes), &bytes, &bundle)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
    let mut wrong = scanner.clone();
    if let ScannerDriver::Slsa { sources, .. } = &mut wrong.driver {
        sources[0].source_uri = "https://github.com/attacker/project".into();
    }
    assert_ne!(
        scanner::run(&wrong, &job(&bytes), &bytes, &bundle)
            .await
            .unwrap()
            .outcome,
        Outcome::Pass
    );
}

#[tokio::test]
#[ignore = "requires PACKWEIR_TEST_OSV pointing to OSV-Scanner 2.7.0"]
async fn real_osv_scans_pinned_offline_snapshots_and_distinguishes_fixed_versions() {
    let temp = tempfile::tempdir().unwrap();
    let mapping = source("https://github.com/example/project", &"1".repeat(40));
    let cases = [
        ("npm", "@packweir/fixture"),
        ("PyPI", "packweir-fixture"),
        ("crates.io", "packweir-fixture"),
        ("Maven", "dev.packweir:fixture"),
        ("NuGet", "packweir.fixture"),
    ];
    let expires_at = Utc::now() + Duration::hours(1);
    let mut databases = BTreeMap::new();
    for (index, (ecosystem, name)) in cases.iter().enumerate() {
        let mut advisory: Value =
            serde_json::from_slice(include_bytes!("fixtures/osv/PACKWEIR-TEST-0001.json")).unwrap();
        advisory["affected"][0]["package"] = json!({"ecosystem":ecosystem,"name":name});
        advisory["affected"][0]
            .as_object_mut()
            .unwrap()
            .remove("ranges");
        advisory["affected"][0]["versions"] = json!(["1.0.0"]);
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(
            "PACKWEIR-TEST-0001.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(&serde_json::to_vec(&advisory).unwrap())
            .unwrap();
        let bytes = zip.finish().unwrap().into_inner();
        let path = temp.path().join(format!("database-{index}.zip"));
        std::fs::write(&path, &bytes).unwrap();
        databases.insert(
            (*ecosystem).into(),
            OsvDatabase {
                path: path.to_string_lossy().into_owned(),
                sha256: sha256(&bytes),
                revision: "synthetic-test-only".into(),
                published_at: Utc::now() - Duration::hours(1),
                expires_at,
            },
        );
    }
    for (version, outcome) in [("1.0.0", Outcome::Fail), ("2.0.0", Outcome::Pass)] {
        let packages: Vec<_> = cases
            .iter()
            .enumerate()
            .map(|(index, (ecosystem, name))| PackageBinding {
                repository: mapping.repository.clone(),
                origin: format!("https://registry.example.test/fixture-{index}.tgz"),
                ecosystem: (*ecosystem).into(),
                name: (*name).into(),
                version: version.into(),
            })
            .collect();
        let bundle = json!({"identities":packages.iter().map(|p|json!({"repository":p.repository,"origin":p.origin})).collect::<Vec<_>>()});
        let scanner = scanner(
            "PACKWEIR_TEST_OSV",
            "2.7.0",
            ScannerDriver::Osv {
                packages,
                databases: databases.clone(),
            },
        );
        let output = scanner::run(&scanner, &job(b"fixture"), b"fixture", &bundle)
            .await
            .unwrap();
        assert_eq!(output.outcome, outcome, "{:?}", output.details);
        assert_eq!(output.valid_until, Some(expires_at));
        assert_eq!(output.details["packages"].as_array().unwrap().len(), 5);
    }
}

#[tokio::test]
#[ignore = "requires PACKWEIR_TEST_HIPCHECK pointing to Hipcheck 3.15.0 and public source/plugin downloads"]
async fn real_hipcheck_runs_a_pinned_policy_and_retains_plugin_analysis() {
    let temp = tempfile::tempdir().unwrap();
    let identity = std::env::var("PACKWEIR_TEST_HIPCHECK_IDENTITY")
        .expect("pinned identity plugin path required");
    let git = std::env::var("PACKWEIR_TEST_HIPCHECK_GIT").expect("pinned git plugin path required");
    let mapping = source(
        "https://github.com/Stankye/packweir",
        "1e24fe620318a49ae829a498108b24d3291a8a8f",
    );
    let mut scanner = scanner(
        "PACKWEIR_TEST_HIPCHECK",
        "3.15.0",
        ScannerDriver::Hipcheck {
            policy: "policy".into(),
            execution: "execution".into(),
            required_analyses: vec!["mitre/identity".into()],
            sources: vec![mapping.clone()],
            plugins: BTreeMap::from([
                ("mitre/identity".into(), pinned(Path::new(&identity))),
                ("mitre/git".into(), pinned(Path::new(&git))),
            ]),
        },
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hipcheck");
    scanner
        .resources
        .insert("policy".into(), pinned(&root.join("policy.kdl")));
    scanner
        .resources
        .insert("execution".into(), pinned(&root.join("Exec.kdl")));
    for (name, program) in [("identity", identity), ("git", git)] {
        let arch = if cfg!(windows) {
            "x86_64-pc-windows-msvc"
        } else {
            "x86_64-unknown-linux-gnu"
        };
        let dependency = if name == "identity" {
            "dependencies {\n plugin \"mitre/git\" version=\"0.6.0\" manifest=\"./resource-git_manifest\"\n}\n"
        } else {
            ""
        };
        let manifest = format!(
            "publisher \"mitre\"\nname \"{name}\"\nversion \"0.6.0\"\nlicense \"Apache-2.0\"\nentrypoint {{\n on arch=\"{arch}\" {}\n}}\n{dependency}",
            serde_json::to_string(&program).unwrap()
        );
        let path = temp.path().join(format!("{name}.kdl"));
        std::fs::write(&path, manifest).unwrap();
        scanner
            .resources
            .insert(format!("{name}_manifest"), pinned(&path));
    }
    if let Some(path) = std::env::var_os("PATH") {
        scanner
            .environment
            .insert("PATH".into(), path.to_string_lossy().into_owned());
    }
    let output = scanner::run(&scanner, &job(b"fixture"), b"fixture", &evidence(&mapping))
        .await
        .unwrap();
    assert_eq!(output.outcome, Outcome::Pass, "{:?}", output.details);
    assert_eq!(
        output.details["reports"][0]["report"]["passing"][0]["name"],
        "mitre/identity"
    );
}
