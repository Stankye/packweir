use chrono::{Duration, Utc};
use packweir::{
    config::Config,
    inventory::{self, Limits},
    model::{Decision, Evidence, Outcome, sha256},
    network,
    policy::Policy,
    registry,
    storage::BlobStore,
};
use serde_json::json;
use std::io::{Cursor, Write};

fn evidence(check: &str, outcome: Outcome) -> Evidence {
    Evidence {
        subject: "artifact".into(),
        check: check.into(),
        configuration: "config".into(),
        tool_version: "1".into(),
        outcome,
        created_at: Utc::now() - Duration::seconds(1),
        expires_at: Utc::now() + Duration::hours(1),
        details: json!({}),
        references: vec![],
    }
}
#[test]
fn required_checks_fail_closed() {
    let policy = Policy::default();
    for outcome in [Outcome::Error, Outcome::Inconclusive, Outcome::Unsupported] {
        assert!(matches!(
            policy.evaluate(
                "artifact",
                "config",
                &[evidence("inventory", outcome)],
                Utc::now()
            ),
            Decision::Pending(_)
        ));
    }
    assert!(matches!(
        policy.evaluate("artifact", "config", &[], Utc::now()),
        Decision::Pending(_)
    ));
    assert!(matches!(
        policy.evaluate(
            "artifact",
            "config",
            &[evidence("inventory", Outcome::Fail)],
            Utc::now()
        ),
        Decision::Denied(_)
    ));
    assert_eq!(
        policy.evaluate(
            "artifact",
            "config",
            &[evidence("inventory", Outcome::Pass)],
            Utc::now()
        ),
        Decision::Approved
    );
}

#[test]
fn routed_file_names_remain_visible_and_cannot_change_the_encoded_target() {
    let public = "https://gateway.example/".parse().unwrap();
    let original: url::Url =
        "https://files.example/packages/pkg-1.0+build-py3-none-any.whl#sha256=abc"
            .parse()
            .unwrap();
    let routed: url::Url = registry::wrap(&public, "pypi", &original).parse().unwrap();
    assert!(routed.path().ends_with("pkg-1.0+build-py3-none-any.whl"));
    assert_eq!(routed.fragment(), original.fragment());
    let encoded = routed.path().split_once("/_fetch/").unwrap().1;
    let decoded = percent_encoding::percent_decode_str(encoded)
        .decode_utf8()
        .unwrap();
    assert_eq!(registry::unwrap_path(&decoded).unwrap(), original);
    let token = encoded.split('/').next().unwrap();
    assert_eq!(registry::unwrap_path(token).unwrap(), original);
    assert!(registry::unwrap_path(&format!("{token}/other.whl")).is_err());
    assert!(registry::unwrap_path(&format!("{token}/../other.whl")).is_err());
    for target in [
        "https://files.example/pkg%2Bbuild.whl?download=1#sha256=abc",
        "https://files.example/unicode-%CE%BB%20file.whl",
    ] {
        let original = target.parse().unwrap();
        let wrapped: url::Url = registry::wrap(&public, "pypi", &original).parse().unwrap();
        let encoded = wrapped.path().split_once("/_fetch/").unwrap().1;
        let decoded = percent_encoding::percent_decode_str(encoded)
            .decode_utf8()
            .unwrap();
        assert_eq!(registry::unwrap_path(&decoded).unwrap(), original);
    }
    let directory: url::Url = "https://files.example/flat/".parse().unwrap();
    let routed: url::Url = registry::wrap(&public, "nuget", &directory)
        .parse()
        .unwrap();
    let prefix = routed.path().split_once("/_fetch/").unwrap().1;
    assert_eq!(
        registry::unwrap_path(&format!("{prefix}package/1.0/package.nupkg"))
            .unwrap()
            .as_str(),
        "https://files.example/flat/package/1.0/package.nupkg"
    );
    assert!(registry::unwrap_path(&format!("{prefix}../other")).is_err());
    assert!(registry::unwrap_path(&format!("{prefix}https://attacker.example/package")).is_err());
}
#[test]
fn evidence_cannot_cross_subject_configuration_or_time() {
    let policy = Policy::default();
    let good = evidence("inventory", Outcome::Pass);
    assert!(matches!(
        policy.evaluate("other", "config", std::slice::from_ref(&good), Utc::now()),
        Decision::Pending(_)
    ));
    assert!(matches!(
        policy.evaluate(
            "artifact",
            "changed",
            std::slice::from_ref(&good),
            Utc::now()
        ),
        Decision::Pending(_)
    ));
    let mut old = good.clone();
    old.expires_at = Utc::now() - Duration::seconds(1);
    assert!(matches!(
        policy.evaluate("artifact", "config", &[old], Utc::now()),
        Decision::Pending(_)
    ));
    let mut future = good;
    future.created_at = Utc::now() + Duration::hours(1);
    assert!(matches!(
        policy.evaluate("artifact", "config", &[future], Utc::now()),
        Decision::Pending(_)
    ));
}
#[test]
fn agent_requires_explicit_trust_binding_and_cannot_override_integrity() {
    let mut policy = Policy {
        required: vec!["agent".into()],
        ..Default::default()
    };
    let mut agent = evidence("agent", Outcome::Pass);
    assert!(matches!(
        policy.evaluate("artifact", "config", &[agent.clone()], Utc::now()),
        Decision::Pending(_)
    ));
    policy.trust_agent = true;
    assert!(matches!(
        policy.evaluate("artifact", "config", &[agent.clone()], Utc::now()),
        Decision::Pending(_)
    ));
    agent.details = json!({"model":"local/model@digest","prompt_digest":"a","toolset_digest":"b","evidence_digest":"c","trace_digest":"d"});
    assert_eq!(
        policy.evaluate("artifact", "config", &[agent.clone()], Utc::now()),
        Decision::Approved
    );
    for check in ["integrity", "archive_safety", "required_signature"] {
        assert!(matches!(
            policy.evaluate(
                "artifact",
                "config",
                &[agent.clone(), evidence(check, Outcome::Fail)],
                Utc::now()
            ),
            Decision::Denied(_)
        ));
    }
}
#[test]
fn nested_binary_inventory_and_sbom_attribution() {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("module/native.so", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"\x7fELFexample").unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    let inventory = inventory::inspect("example.whl", &bytes, Limits::default()).unwrap();
    assert!(inventory.files.iter().any(|f| f.kind == "elf"));
    assert_eq!(inventory.subject, sha256(&bytes));
    assert_eq!(
        inventory::sbom_format(&inventory::cyclonedx(&inventory)).unwrap(),
        "cyclonedx"
    );
    assert_eq!(
        inventory::sbom_format(&inventory::spdx(&inventory)).unwrap(),
        "spdx"
    );
}
#[test]
fn archive_traversal_and_expansion_limits_reject() {
    for path in ["../escape", "C:/Windows/escape"] {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(path, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"data").unwrap();
        assert!(
            inventory::inspect(
                "bad.whl",
                &zip.finish().unwrap().into_inner(),
                Limits::default()
            )
            .is_err()
        );
    }
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("payload", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&[0; 100]).unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    assert!(
        inventory::inspect(
            "bomb.zip",
            &bytes,
            Limits {
                expanded_bytes: 10,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn zip_header_disagreements_cannot_hide_a_different_filename_or_compression() {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("evil.exe", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"harmless regression fixture").unwrap();
    let original = zip.finish().unwrap().into_inner();
    assert!(inventory::inspect("fixture.zip", &original, Limits::default()).is_ok());
    let central = original
        .windows(4)
        .position(|v| v == b"PK\x01\x02")
        .unwrap();
    let mut renamed = original.clone();
    // Only the central directory claims a benign name; streaming readers still see evil.exe.
    renamed[central + 46..central + 54].copy_from_slice(b"safe.txt");
    let mut compression = original;
    // Change the local compression method without changing the central directory.
    compression[8..10].copy_from_slice(&99u16.to_le_bytes());
    for bytes in [renamed, compression] {
        assert!(inventory::inspect("cloaked.whl", &bytes, Limits::default()).is_err());
    }
}

#[test]
fn unsupported_compression_is_not_approved_as_an_opaque_file() {
    for bytes in [
        b"BZhfake".as_slice(),
        b"\xfd7zXZ\0fake",
        b"7z\xbc\xaf\x27\x1cfake",
        b"Rar!fake",
        &[0x28, 0xb5, 0x2f, 0xfd],
    ] {
        assert!(inventory::inspect("payload", bytes, Limits::default()).is_err());
    }
}

#[test]
fn gzip_members_and_tar_entries_are_all_inspected() {
    use flate2::{Compression, write::GzEncoder};
    let mut first = GzEncoder::new(Vec::new(), Compression::default());
    first.write_all(b"first").unwrap();
    let mut second = GzEncoder::new(Vec::new(), Compression::default());
    second.write_all(b"second").unwrap();
    let mut bytes = first.finish().unwrap();
    bytes.extend(second.finish().unwrap());
    let result = inventory::inspect("members.gz", &bytes, Limits::default()).unwrap();
    assert!(
        result
            .files
            .iter()
            .any(|f| f.sha256 == sha256(b"firstsecond"))
    );

    let mut archive = tar::Builder::new(Vec::new());
    for name in ["one/", "two/", "three/"] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_size(0);
        header.set_cksum();
        archive
            .append_data(&mut header, name, std::io::empty())
            .unwrap();
    }
    let bytes = archive.into_inner().unwrap();
    assert!(
        inventory::inspect(
            "directories.tar",
            &bytes,
            Limits {
                files: 2,
                ..Limits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn npm_integrity_and_native_urls_are_preserved_through_rewriting() {
    let config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let repo = &config.repositories["npm"];
    let mut metadata = json!({"name":"example","versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/example/-/example-1.0.0.tgz","integrity":"sha512-aGVsbG8="}}}});
    registry::rewrite_json(&mut metadata, repo, "npm", &config.public_url).unwrap();
    let rewritten = metadata["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    assert!(rewritten.starts_with("http://127.0.0.1:8080/r/npm/_fetch/"));
    let rewritten_url: url::Url = rewritten.parse().unwrap();
    let token = rewritten_url
        .path()
        .split_once("/_fetch/")
        .unwrap()
        .1
        .split('/')
        .next()
        .unwrap();
    assert_eq!(rewritten_url.fragment(), Some("sha512=aGVsbG8="));
    assert_eq!(
        registry::unwrap(token).unwrap().fragment(),
        Some("sha512=aGVsbG8=")
    );
    assert_eq!(
        metadata["versions"]["1.0.0"]["dist"]["integrity"],
        "sha512-aGVsbG8="
    );
}
#[test]
fn pypi_html_does_not_forward_scripts_or_metadata_bypass() {
    let config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let repo = &config.repositories["pypi"];
    let html = "<script>evil()</script><a href=\"https://files.pythonhosted.org/a.whl#sha256=abc\" data-requires-python=\"&gt;=3.10\" data-core-metadata=\"true\">a.whl</a>";
    let output =
        registry::rewrite_html(html, &repo.upstream, repo, "pypi", &config.public_url).unwrap();
    assert!(!output.contains("evil"));
    assert!(!output.contains("data-core-metadata"));
    assert!(output.contains("data-requires-python"));
    assert!(output.contains("/r/pypi/_fetch/"));
}
#[test]
fn origin_allowlist_is_exact() {
    let config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let repo = &config.repositories["npm"];
    for url in [
        "https://registry.npmjs.org.attacker.invalid/x",
        "http://registry.npmjs.org/x",
        "https://user:pass@registry.npmjs.org/x",
        "https://registry.npmjs.org:444/x",
    ] {
        assert!(!network::allowed(repo, &url.parse().unwrap()));
    }
    assert!(network::allowed(
        repo,
        &"https://registry.npmjs.org/x".parse().unwrap()
    ));
}
#[test]
fn integrity_mismatches_are_rejected() {
    let url = format!(
        "https://files.pythonhosted.org/a.whl#sha256={}",
        sha256(b"expected")
    )
    .parse()
    .unwrap();
    assert!(network::verify_fragment(&url, b"expected").is_ok());
    assert!(network::verify_fragment(&url, b"substitution").is_err());
}

#[test]
fn pypi_client_hash_fragments_remain_visible() {
    let config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let target: url::Url = format!(
        "https://files.pythonhosted.org/a.whl#sha256={}",
        sha256(b"wheel")
    )
    .parse()
    .unwrap();
    let wrapped: url::Url = registry::wrap(&config.public_url, "pypi", &target)
        .parse()
        .unwrap();
    assert_eq!(wrapped.fragment(), target.fragment());
    let token = wrapped
        .path()
        .split_once("/_fetch/")
        .unwrap()
        .1
        .split('/')
        .next()
        .unwrap();
    assert_eq!(registry::unwrap(token).unwrap(), target);
}

#[test]
fn discovery_routes_do_not_match_artifact_name_substrings() {
    use packweir::model::Ecosystem;
    for (ecosystem, path) in [
        (
            Ecosystem::Nuget,
            "/v3-flatcontainer/query-tools/1.0/query-tools.1.0.nupkg",
        ),
        (Ecosystem::Pypi, "/packages/simple-package/file.whl"),
        (Ecosystem::Maven, "/group/notmaven-metadata.xml"),
    ] {
        assert!(!registry::is_metadata(
            ecosystem,
            &format!("https://example.org{path}").parse().unwrap()
        ));
    }
    assert!(registry::is_metadata(
        Ecosystem::Nuget,
        &"https://example.org/query?q=test".parse().unwrap()
    ));
    assert!(registry::is_metadata(
        Ecosystem::Maven,
        &"https://example.org/group/maven-metadata.xml"
            .parse()
            .unwrap()
    ));
}

#[test]
fn cargo_metadata_cannot_forward_arbitrary_archive_bytes() {
    assert!(registry::validate_cargo_index(b"PK\x03\x04archive").is_err());
    assert!(
        registry::validate_cargo_index(
            b"{\"name\":\"fake\",\"vers\":\"1.0\",\"cksum\":\"invalid\"}"
        )
        .is_err()
    );
    let entry =
        serde_json::to_vec(&json!({"name":"example","vers":"1.0.0","cksum":"a".repeat(64)}))
            .unwrap();
    assert!(registry::validate_cargo_index(&entry).is_ok());
}

#[test]
fn native_authentication_does_not_grant_administrative_access() {
    use axum::http::{HeaderMap, header};
    use base64::Engine;
    let token = "r".repeat(32);
    let mut headers = HeaderMap::new();
    for value in [
        format!("Bearer {token}"),
        token.clone(),
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("user:{token}"))
        ),
    ] {
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        assert!(packweir::gateway::read_authorized(&headers, &token));
        assert!(!packweir::gateway::authorized(&headers, &"a".repeat(32)));
    }
    for value in ["Basic invalid!", "Bearer incorrect", ""] {
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        assert!(!packweir::gateway::read_authorized(&headers, &token));
    }
}

#[test]
fn configuration_rejects_unbounded_timeouts_and_embedded_credentials() {
    let original = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let mut config = original.clone();
    config.evidence_ttl_seconds = i64::MAX;
    assert!(config.validate().is_err());
    let mut config = original.clone();
    config.public_url = "http://user:password@localhost:8080/".parse().unwrap();
    assert!(config.validate().is_err());
    let mut config = original.clone();
    config.repositories.get_mut("npm").unwrap().upstream =
        "https://registry.npmjs.org/?token=secret".parse().unwrap();
    assert!(config.validate().is_err());
    assert!(original.validate().is_ok());
}

#[tokio::test]
async fn scanner_output_is_bounded() {
    assert!(
        packweir::scanner::read_bounded(&b"over budget"[..], 3)
            .await
            .is_err()
    );
    assert_eq!(
        packweir::scanner::read_bounded(&b"ok"[..], 3)
            .await
            .unwrap(),
        b"ok"
    );
}

#[tokio::test]
async fn redirects_cannot_escape_the_configured_upstream_path() {
    use axum::{Router, response::Redirect, routing::get};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let touched = Arc::new(AtomicBool::new(false));
    let seen = touched.clone();
    let app = Router::new()
        .route(
            "/allowed/package.tgz",
            get(|| async { Redirect::temporary("/outside") }),
        )
        .route(
            "/outside",
            get(move || {
                let seen = seen.clone();
                async move {
                    seen.store(true, Ordering::SeqCst);
                    "must not be fetched"
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/allowed/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let mut repo = config.repositories["npm"].clone();
    repo.upstream = origin.parse().unwrap();
    let result = network::fetch(
        &repo,
        &repo.upstream.join("package.tgz").unwrap(),
        None,
        1024,
        true,
    )
    .await;
    assert!(result.is_err());
    assert!(!touched.load(Ordering::SeqCst));
    server.abort();
}
#[tokio::test]
async fn blob_storage_verifies_and_rejects_traversal() {
    let root = tempfile::tempdir().unwrap();
    let store = BlobStore::new(&packweir::config::StorageConfig::Fs {
        root: root.path().to_string_lossy().into(),
    })
    .unwrap();
    let digest = store.put(b"approved".to_vec()).await.unwrap();
    assert_eq!(store.read(&digest).await.unwrap(), b"approved");
    assert!(store.read("../../secret").await.is_err());
    std::fs::write(
        root.path()
            .join(format!("blobs/sha256/{}/{}", &digest[..2], digest)),
        b"tampered",
    )
    .unwrap();
    assert!(store.read(&digest).await.is_err());
}
