mod support;
use chrono::{Duration, Utc};
use packweir::{
    config::{CommandScanner, Config, OsvDatabase, PinnedResource, ScannerDriver},
    identity::{self, DeliveryScope},
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

fn resource(root: &Path, name: &str, bytes: &[u8]) -> PinnedResource {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    PinnedResource {
        path: path.to_string_lossy().into(),
        sha256: sha256(bytes),
    }
}
fn scanner(root: &Path, report: &Value, code: i32) -> CommandScanner {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("fixture.json", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"{}").unwrap();
    let database = resource(root, "npm.zip", &zip.finish().unwrap().into_inner());
    let binary = support::fixture_program();
    CommandScanner {
        program: binary.to_string_lossy().into(),
        program_sha256: Some(sha256(&std::fs::read(binary).unwrap())),
        args: vec![],
        version: "fixture".into(),
        timeout_seconds: 5,
        environment: BTreeMap::new(),
        resources: BTreeMap::from([
            (
                "report".into(),
                resource(root, "report.json", &serde_json::to_vec(report).unwrap()),
            ),
            (
                "status".into(),
                resource(root, "status", code.to_string().as_bytes()),
            ),
        ]),
        driver: ScannerDriver::OsvObserved {
            databases: BTreeMap::from([(
                "npm".into(),
                OsvDatabase {
                    path: database.path,
                    sha256: database.sha256,
                    revision: "snapshot".into(),
                    published_at: Utc::now() - Duration::hours(1),
                    expires_at: Utc::now() + Duration::hours(1),
                },
            )]),
        },
    }
}
fn bundle() -> Value {
    let config = Config::load(Path::new("packweir.toml")).unwrap();
    let mut package = identity::observe(
        &config.repositories["npm"],
        &"https://registry.npmjs.org/ansi-html/-/ansi-html-0.0.7.tgz"
            .parse()
            .unwrap(),
        "",
    )
    .unwrap();
    package.basis = "registry_metadata_observed".into();
    json!({"identities":[DeliveryScope {repository:"npm".into(),origin:"https://registry.npmjs.org/ansi-html/-/ansi-html-0.0.7.tgz".into(),filename:"ansi-html-0.0.7.tgz".into(),package:Some(package)}],"documents":[]})
}
fn job() -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        lease: uuid::Uuid::new_v4(),
        subject: sha256(b"fixture"),
        filename: "fixture".into(),
        configuration: "fixture".into(),
        context_revision: 0,
    }
}
fn report(findings: bool) -> Value {
    json!({"results":[{"packages":[{"package":{"ecosystem":"npm","name":"ansi-html","version":"0.0.7"},"vulnerabilities":if findings{json!([{"id":"GHSA-test"}])}else{json!([])}}]}]})
}

#[tokio::test]
async fn observed_osv_scans_exact_registry_coordinates_and_retains_coverage() {
    let root = tempfile::tempdir().unwrap();
    for (vulnerable, code, expected) in [
        (false, 0, Outcome::Pass),
        (true, 1, Outcome::Fail),
        (true, 0, Outcome::Inconclusive),
    ] {
        let scanner = scanner(root.path(), &report(vulnerable), code);
        let result = scanner::run(&scanner, &job(), b"fixture", &bundle())
            .await
            .unwrap();
        assert_eq!(result.outcome, expected);
        assert_eq!(result.details["mapping_origin"], "registry_observed");
        assert_eq!(result.details["publisher_identity_verified"], false);
        assert!(result.valid_until.is_some());
    }
    let mut wrong = report(false);
    wrong["results"][0]["packages"][0]["package"]["version"] = json!("9.9.9");
    assert_eq!(
        scanner::run(
            &scanner(root.path(), &wrong, 0),
            &job(),
            b"fixture",
            &bundle()
        )
        .await
        .unwrap()
        .outcome,
        Outcome::Inconclusive
    );
}

#[tokio::test]
async fn unbound_malformed_ambiguous_or_uncovered_observations_cannot_approve() {
    let root = tempfile::tempdir().unwrap();
    let scanner = scanner(root.path(), &report(false), 0);
    let good = bundle();
    let mut cases = vec![json!({"identities":[]}), json!({"identities":[{}]})];
    let mut unbound = good.clone();
    unbound["identities"][0]["package"]["basis"] = json!("registry_path_observed");
    cases.push(unbound);
    let mut fake = good.clone();
    fake["identities"][0]["package"]["purl"] = json!("pkg:npm/other@0.0.7");
    cases.push(fake);
    let mut duplicate = good.clone();
    duplicate["identities"]
        .as_array_mut()
        .unwrap()
        .push(good["identities"][0].clone());
    cases.push(duplicate);
    let mut uncovered = good.clone();
    let config = Config::load(Path::new("packweir.toml")).unwrap();
    uncovered["identities"][0]["package"] = serde_json::to_value(
        identity::observe(
            &config.repositories["nuget"],
            &"https://api.nuget.org/flat/example/1.0/example.1.0.nupkg"
                .parse()
                .unwrap(),
            "",
        )
        .unwrap(),
    )
    .unwrap();
    cases.push(uncovered);
    for input in cases {
        assert_eq!(
            scanner::run(&scanner, &job(), b"fixture", &input)
                .await
                .unwrap()
                .outcome,
            Outcome::Inconclusive
        );
    }
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    config.scanners.insert("provenance".into(), scanner);
    assert!(
        config.validate().is_err(),
        "observed vulnerability checks cannot impersonate provenance"
    );
}

fn versioned_bundle(key: &str, version: &str) -> (Value, &'static str, String) {
    let config = Config::load(Path::new("packweir.toml")).unwrap();
    let (url, route, ecosystem) = match key {
        "npm" => (
            format!("https://registry.npmjs.org/ansi-html/-/ansi-html-{version}.tgz"),
            String::new(),
            "npm",
        ),
        "pypi" => (
            format!("https://files.pythonhosted.org/ansi_html-{version}-py3-none-any.whl"),
            String::new(),
            "PyPI",
        ),
        "cargo" => (
            "https://static.crates.io/download".into(),
            format!("_cargo/ansi-html/{version}/download"),
            "crates.io",
        ),
        "nuget" => (
            format!("https://api.nuget.org/flat/ansi.html/{version}/ansi.html.{version}.nupkg"),
            String::new(),
            "NuGet",
        ),
        "maven" => (
            format!(
                "https://repo.maven.apache.org/maven2/dev/packweir/fixture/{version}/fixture-{version}.jar"
            ),
            String::new(),
            "Maven",
        ),
        _ => unreachable!(),
    };
    let mut package=identity::observe(&config.repositories[key],&url.parse().unwrap(),&route)
        .unwrap_or_else(||panic!("test version {key}:{version} must reach the OSV version guard, not be rejected by path observation"));
    if matches!(key, "npm" | "pypi") {
        package.basis = "registry_metadata_observed".into();
    }
    let name = package.name.clone();
    (
        json!({"identities":[DeliveryScope{repository:key.into(),origin:url,filename:"fixture".into(),package:Some(package)}],"documents":[]}),
        ecosystem,
        name,
    )
}

async fn scan_version(key: &str, version: &str) -> Outcome {
    let root = tempfile::tempdir().unwrap();
    let (bundle, ecosystem, name) = versioned_bundle(key, version);
    let observed_version = bundle["identities"][0]["package"]["version"]
        .as_str()
        .unwrap();
    let clean = json!({"results":[{"packages":[{"package":{"ecosystem":ecosystem,"name":name,"version":observed_version},"vulnerabilities":[]}]}]});
    let mut command = scanner(root.path(), &clean, 0);
    if let ScannerDriver::OsvObserved { databases } = &mut command.driver {
        let database = databases.remove("npm").unwrap();
        databases.insert(ecosystem.into(), database);
    }
    scanner::run(&command, &job(), b"fixture", &bundle)
        .await
        .unwrap()
        .outcome
}

#[test]
fn unsupported_nuget_coordinates_are_rejected_before_osv_scanning() {
    let config = Config::load(Path::new("packweir.toml")).unwrap();
    for version in ["1.x", "latest1", "1.0.0_latest"] {
        let origin =
            format!("https://api.nuget.org/flat/ansi.html/{version}/ansi.html.{version}.nupkg");
        assert!(
            identity::observe(&config.repositories["nuget"], &origin.parse().unwrap(), "")
                .is_none(),
            "unsupported NuGet observation: {version}"
        );
    }
}

#[tokio::test]
async fn clean_matching_output_cannot_approve_ranges_tags_or_unsupported_versions() {
    // These spellings reach the scanner. The fixture always reports clean,
    // exact observed-coordinate coverage with exit zero.
    // Those outputs must not turn unsupported version syntax into approval.
    for (ecosystem, version) in [
        ("npm", "1.x"),
        ("npm", "latest1"),
        ("npm", "main2026"),
        ("npm", "1.0"),
        ("cargo", "1.x"),
        ("cargo", "latest1"),
        ("cargo", "1.0"),
        ("pypi", "1.x"),
        ("pypi", "latest1"),
        ("pypi", "release2026"),
        ("nuget", "1.0.0.1"),
        ("nuget", "1.0.0.1-rc.1"),
        ("maven", "1.x"),
        ("maven", "latest1"),
        ("maven", "release2026"),
        ("maven", "main1"),
    ] {
        assert_eq!(
            scan_version(ecosystem, version).await,
            Outcome::Inconclusive,
            "{ecosystem}:{version}"
        );
    }
}

#[tokio::test]
async fn concrete_prereleases_and_supported_literal_spellings_keep_exact_coverage() {
    for (ecosystem, version) in [
        ("npm", "1.2.3"),
        ("npm", "1.2.3-beta.1+build7"),
        ("cargo", "0.2.0-alpha.1"),
        ("pypi", "1.0rc1"),
        ("pypi", "1.0.post1"),
        ("pypi", "1.0.dev1"),
        ("pypi", "1.0+local1"),
        ("nuget", "1"),
        ("nuget", "1.0"),
        ("nuget", "1.0.0.0"),
        ("nuget", "0001.0000.0000.0000+build7"),
        ("nuget", "1.0.0-rc.1+build7"),
        ("nuget", "1.0.0-RC.1+Build7"),
        ("maven", "1.0.0.Final"),
        ("maven", "2.0.0-rc1"),
        ("maven", "2.0.0-SNAPSHOT"),
    ] {
        assert_eq!(
            scan_version(ecosystem, version).await,
            Outcome::Pass,
            "{ecosystem}:{version}"
        );
    }
}

#[test]
fn manual_osv_mappings_use_the_same_qualified_literal_version_boundary() {
    use packweir::config::PackageBinding;
    for (key, version, accepted) in [
        ("npm", "1.x", false),
        ("npm", "latest1", false),
        ("npm", "1.2.3-beta.1", true),
        ("cargo", "1.0", false),
        ("cargo", "1.0.0-rc.1", true),
        ("pypi", "latest2026", false),
        ("pypi", "1.0rc1", true),
        ("nuget", "1.x", false),
        ("nuget", "1.0", true),
        ("nuget", "1.0.0.0", false),
        ("maven", "release2026", false),
        ("maven", "1!1", false),
        ("maven", "1.0.Final", true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (_, ecosystem, name) = versioned_bundle(key, "1.0.0");
        let mut command = scanner(root.path(), &report(false), 0);
        let ScannerDriver::OsvObserved { mut databases } = command.driver else {
            unreachable!()
        };
        let database = databases.remove("npm").unwrap();
        databases.insert(ecosystem.into(), database);
        command.driver = ScannerDriver::Osv {
            packages: vec![PackageBinding {
                repository: key.into(),
                origin: "https://registry.example.test/fixture".into(),
                ecosystem: ecosystem.into(),
                name,
                version: version.into(),
            }],
            databases,
        };
        let mut settings = Config::load(Path::new("packweir.toml")).unwrap();
        settings.scanners.insert("vulnerabilities".into(), command);
        assert_eq!(settings.validate().is_ok(), accepted, "{key}:{version}");
    }
}
