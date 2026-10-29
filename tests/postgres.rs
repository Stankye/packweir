//! Requires PostgreSQL with CREATE DATABASE privilege; CI provides an isolated service.
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    config::Config,
    gateway::{self, AppState},
    model::{Decision, Evidence, Outcome},
    scanner,
    storage::BlobStore,
    store::Store,
};
use std::{
    io::{Cursor, Write},
    sync::Arc,
};
use tower::ServiceExt;

fn config(root: &std::path::Path, origin: &str) -> Config {
    let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    config.storage = packweir::config::StorageConfig::Fs {
        root: root.to_string_lossy().into(),
    };
    config.repositories.retain(|name, _| name == "npm");
    config.repositories.get_mut("npm").unwrap().upstream = origin.parse().unwrap();
    config.allow_private_upstreams = true;
    config
}

#[sqlx::test(migrations = "./migrations")]
async fn readiness_checks_dependencies_while_liveness_remains_available(pool: sqlx::PgPool) {
    let temp = tempfile::tempdir().unwrap();
    let settings = Arc::new(config(temp.path(), "http://127.0.0.1:1/"));
    let blobs = BlobStore::new(&settings.storage).unwrap();
    let app = gateway::router(AppState::new(
        settings,
        Store { pool: pool.clone() },
        blobs,
        "a".repeat(32),
        "r".repeat(32),
    ));
    let request = |path| Request::builder().uri(path).body(Body::empty()).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request("/ready"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    pool.close().await;
    let response = app.clone().oneshot(request("/ready")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        b"{\"ready\":false}"
    );
    assert_eq!(
        app.oneshot(request("/health")).await.unwrap().status(),
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn first_download_releases_no_bytes_until_worker_approves(pool: sqlx::PgPool) {
    let temp = tempfile::tempdir().unwrap();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        "package/package.json",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(b"{\"name\":\"fixture\"}").unwrap();
    let payload = zip.finish().unwrap().into_inner();
    let copy = payload.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/fixture.tgz",
                get(move || {
                    let bytes = copy.clone();
                    async move { bytes }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let config = Arc::new(config(temp.path(), &origin));
    let store = Store { pool };
    let blobs = BlobStore::new(&config.storage).unwrap();
    let app = gateway::router(AppState::new(
        config.clone(),
        store.clone(),
        blobs.clone(),
        "a".repeat(32),
        "r".repeat(32),
    ));
    let request = || {
        Request::builder()
            .uri("/r/npm/fixture.tgz")
            .header("authorization", format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    let first = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = first.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.windows(payload.len()).any(|w| w == payload));
    scanner::worker(config.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    let second = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        second
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        payload.as_slice()
    );
    let unauthorized = app
        .oneshot(
            Request::builder()
                .uri("/r/npm/fixture.tgz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    upstream.abort();
}

#[sqlx::test(migrations = "./migrations")]
async fn leases_and_document_revisions_prevent_stale_approval(pool: sqlx::PgPool) {
    let store = Store { pool };
    store
        .enqueue("subject", "configuration", "fixture.whl")
        .await
        .unwrap();
    let job = store.lease("configuration", 60).await.unwrap().unwrap();
    assert!(store.lease("configuration", 60).await.unwrap().is_none());
    let now = Utc::now();
    let finding = Evidence {
        subject: "subject".into(),
        configuration: "configuration".into(),
        check: "inventory".into(),
        tool_version: "1".into(),
        outcome: Outcome::Pass,
        created_at: now,
        expires_at: now + Duration::hours(1),
        details: serde_json::json!({}),
        references: vec![],
    };
    store
        .document("subject", "attestation", "publisher_declared", "digest")
        .await
        .unwrap();
    assert!(
        store
            .complete(&job, std::slice::from_ref(&finding))
            .await
            .is_err()
    );
    store
        .enqueue("subject", "configuration", "fixture.whl")
        .await
        .unwrap();
    let replacement = store.lease("configuration", 60).await.unwrap().unwrap();
    assert_ne!(replacement.lease, job.lease);
    assert!(
        store
            .complete(&job, std::slice::from_ref(&finding))
            .await
            .is_err()
    );
    store.complete(&replacement, &[finding]).await.unwrap();
    assert_eq!(
        store
            .evidence("subject", "configuration")
            .await
            .unwrap()
            .len(),
        1
    );
    store
        .document("subject", "attestation", "publisher_declared", "changed")
        .await
        .unwrap();
    let evidence = store.evidence("subject", "configuration").await.unwrap();
    assert!(evidence.is_empty());
    assert!(matches!(
        packweir::policy::Policy::default().evaluate(
            "subject",
            "configuration",
            &evidence,
            Utc::now()
        ),
        Decision::Pending(_)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn exhausted_leases_are_failed_and_do_not_pin_staging_forever(pool: sqlx::PgPool) {
    let store = Store { pool };
    store
        .enqueue("subject", "configuration", "fixture.whl")
        .await
        .unwrap();
    let job = store.lease("configuration", 60).await.unwrap().unwrap();
    sqlx::query("UPDATE jobs SET attempts=3,lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(job.id)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(store.lease("configuration", 60).await.unwrap().is_none());
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE id=$1")
        .bind(job.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(state, "failed");
}

#[sqlx::test(migrations = "./migrations")]
async fn manual_rescan_invalidates_an_inflight_worker(pool: sqlx::PgPool) {
    let store = Store { pool };
    store
        .enqueue("subject", "configuration", "fixture.whl")
        .await
        .unwrap();
    let previous = store.lease("configuration", 60).await.unwrap().unwrap();
    store.invalidate("subject").await.unwrap();
    store
        .enqueue("subject", "configuration", "fixture.whl")
        .await
        .unwrap();
    assert!(store.complete(&previous, &[]).await.is_err());
    let current = store.lease("configuration", 60).await.unwrap().unwrap();
    assert_ne!(current.lease, previous.lease);
    assert!(current.context_revision > previous.context_revision);
    store.complete(&current, &[]).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn extensionless_cargo_downloads_still_require_approval(pool: sqlx::PgPool) {
    let temp = tempfile::tempdir().unwrap();
    let payload = b"unapproved-extensionless-package".to_vec();
    let checksum = packweir::model::sha256(&payload);
    let index = serde_json::to_string(
        &serde_json::json!({"name":"example","vers":"1.0.0","cksum":checksum}),
    )
    .unwrap();
    let app = Router::new()
        .route(
            "/ex/am/example",
            get(move || {
                let index = index.clone();
                async move { index }
            }),
        )
        .route(
            "/payload/example/1.0.0",
            get(move || {
                let payload = payload.clone();
                async move { payload }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut settings = config(temp.path(), &origin);
    let repo = settings.repositories.get_mut("npm").unwrap();
    repo.ecosystem = packweir::model::Ecosystem::Cargo;
    repo.cargo_download_template = Some(format!("{origin}payload/{{crate}}/{{version}}"));
    let blobs = BlobStore::new(&settings.storage).unwrap();
    let store = Store { pool };
    let gateway = gateway::router(AppState::new(
        Arc::new(settings),
        store.clone(),
        blobs,
        "a".repeat(32),
        "r".repeat(32),
    ));
    let response = gateway
        .oneshot(
            Request::builder()
                .uri("/r/npm/_cargo/example/1.0.0/download")
                .header("authorization", "r".repeat(32))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !body
            .windows(b"unapproved-extensionless-package".len())
            .any(|bytes| bytes == b"unapproved-extensionless-package")
    );
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(jobs, 1);
    server.abort();
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PACKWEIR_TEST_COSIGN pointing to Cosign 3.1.4"]
async fn real_cosign_bundle_ingestion_gates_delivery_and_changed_trust(pool: sqlx::PgPool) {
    use packweir::{
        config::CommandScanner,
        model::{Ecosystem, sha256},
    };
    use serde_json::json;
    let temp = tempfile::tempdir().unwrap();
    let payload = include_bytes!("fixtures/sigstore/cosign_checksums.txt").to_vec();
    let digest = sha256(&payload);
    let served = payload.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/checksums.txt",
                get(move || {
                    let copy = served.clone();
                    async move { copy }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let program = std::env::var("PACKWEIR_TEST_COSIGN").unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sigstore/trusted_root.json");
    let mut settings = config(temp.path(), &origin);
    settings.repositories.get_mut("npm").unwrap().ecosystem = Ecosystem::Maven;
    let verifier: CommandScanner = serde_json::from_value(json!({
        "program":program, "program_sha256":sha256(&std::fs::read(&program).unwrap()), "version":"3.1.4", "timeout_seconds":20,
        "resources":{"root":{"path":root, "sha256":sha256(&std::fs::read(&root).unwrap())}},
        "driver":{"kind":"sigstore", "trusted_root":"root", "certificate_identity":"keyless@projectsigstore.iam.gserviceaccount.com", "certificate_oidc_issuer":"https://accounts.google.com"}
    })).unwrap();
    settings
        .scanners
        .insert("required_signature".into(), verifier);
    settings.policy.required.push("required_signature".into());
    settings.validate().unwrap();
    let settings = Arc::new(settings);
    let store = Store { pool };
    let blobs = BlobStore::new(&settings.storage).unwrap();
    let app = gateway::router(AppState::new(
        settings.clone(),
        store.clone(),
        blobs.clone(),
        "a".repeat(32),
        "r".repeat(32),
    ));
    let download = || {
        Request::builder()
            .uri("/r/npm/checksums.txt")
            .header("authorization", format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(download()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(download()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let signature: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/sigstore/cosign_checksums.txt.sigstore.json"
    ))
    .unwrap();
    let ingested = app.clone().oneshot(Request::builder()
        .method("POST").uri(format!("/api/v1/artifacts/{digest}/documents"))
        .header("authorization", format!("Bearer {}", "a".repeat(32))).header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({"kind":"sigstore_bundle", "origin":"publisher_declared", "document":signature})).unwrap())).unwrap()).await.unwrap();
    assert_eq!(ingested.status(), StatusCode::CREATED);
    assert!(
        store
            .evidence(&digest, &settings.fingerprint())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        app.clone().oneshot(download()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    let approved = app.oneshot(download()).await.unwrap();
    assert_eq!(approved.status(), StatusCode::OK);
    assert_eq!(
        approved
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        payload
    );
    let mut changed = (*settings).clone();
    if let packweir::config::ScannerDriver::Sigstore {
        certificate_identity,
        ..
    } = &mut changed
        .scanners
        .get_mut("required_signature")
        .unwrap()
        .driver
    {
        *certificate_identity = "attacker@example.test".into();
    }
    let changed = Arc::new(changed);
    let app = gateway::router(AppState::new(
        changed.clone(),
        store.clone(),
        blobs.clone(),
        "a".repeat(32),
        "r".repeat(32),
    ));
    assert_eq!(
        app.clone().oneshot(download()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(changed, store, blobs, true).await.unwrap();
    assert_eq!(
        app.oneshot(download()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    upstream.abort();
}

#[sqlx::test(migrations = "./migrations")]
async fn native_driver_evidence_gates_delivery_and_expires_with_its_database(pool: sqlx::PgPool) {
    use packweir::{
        config::{
            CommandScanner, OsvDatabase, PackageBinding, PinnedResource, ScannerDriver,
            SourceBinding,
        },
        model::{Ecosystem, sha256},
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"fixture";
    let digest = sha256(bytes);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/fixture.bin", get(|| async { "fixture" })),
        )
        .await
        .unwrap()
    });
    let mut settings = config(temp.path(), &origin);
    settings.repositories.get_mut("npm").unwrap().ecosystem = Ecosystem::Maven;
    let binding = SourceBinding {
        repository: "npm".into(),
        origin: format!("{origin}fixture.bin"),
        source_uri: "https://github.com/example/project".into(),
        source_revision: "1".repeat(40),
    };
    let builder = "https://github.com/example/builder/.github/workflows/build.yml@refs/tags/v1.0.0";
    let resource = |name: &str, content: Vec<u8>| {
        let path = temp.path().join(name);
        std::fs::write(&path, &content).unwrap();
        PinnedResource {
            path: path.to_string_lossy().into_owned(),
            sha256: sha256(&content),
        }
    };
    let adapter = |driver, name: &str, report| CommandScanner {
        program: support::fixture_program().to_string_lossy().into_owned(),
        program_sha256: Some(sha256(&std::fs::read(support::fixture_program()).unwrap())),
        version: "test-double".into(),
        timeout_seconds: 5,
        args: vec![],
        environment: BTreeMap::new(),
        resources: BTreeMap::from([(
            "report".into(),
            resource(name, serde_json::to_vec(&report).unwrap()),
        )]),
        driver,
    };
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("TEST.json", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"{}").unwrap();
    let database = resource("npm.zip", zip.finish().unwrap().into_inner());
    let expires = Utc::now() + Duration::minutes(5);
    settings.scanners.insert("vulnerabilities".into(),adapter(ScannerDriver::Osv {packages:vec![PackageBinding {repository:binding.repository.clone(),origin:binding.origin.clone(),ecosystem:"Maven".into(),name:"dev.packweir:fixture".into(),version:"1.0.0".into()}],
        databases:BTreeMap::from([("Maven".into(),OsvDatabase {path:database.path,sha256:database.sha256,revision:"test".into(),published_at:Utc::now()-Duration::hours(1),expires_at:expires})])},"osv-report.json",
        json!({"results":[{"packages":[{"package":{"ecosystem":"Maven","name":"dev.packweir:fixture","version":"1.0.0"},"vulnerabilities":[]}]}]})));
    settings.scanners.insert("provenance".into(),adapter(ScannerDriver::Slsa {builder_id:builder.into(),sources:vec![binding.clone()]},"provenance-report.json",
        json!({"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"digest":{"sha256":digest}}],"predicate":{"builder":{"id":builder},"invocation":{"configSource":{"uri":"git+https://github.com/example/project@refs/heads/main","digest":{"sha1":binding.source_revision}}}}})));
    let mut hipcheck = adapter(
        ScannerDriver::Hipcheck {
            policy: "policy".into(),
            execution: "execution".into(),
            required_analyses: vec!["example/custom".into()],
            sources: vec![binding.clone()],
            plugins: BTreeMap::from([(
                "example/custom".into(),
                PinnedResource {
                    path: support::fixture_program().to_string_lossy().into_owned(),
                    sha256: sha256(&std::fs::read(support::fixture_program()).unwrap()),
                },
            )]),
        },
        "hipcheck-report.json",
        json!({"repo_owner":"example","repo_name":"project","repo_head":binding.source_revision,"passing":[{"name":"example/custom","passed":true}],"failing":[],"errored":[],"recommendation":{"kind":"Pass"}}),
    );
    hipcheck
        .resources
        .insert("policy".into(), resource("policy.kdl", b"test".to_vec()));
    hipcheck
        .resources
        .insert("execution".into(), resource("exec.kdl", b"test".to_vec()));
    settings.scanners.insert("source_posture".into(), hipcheck);
    settings.policy.required.extend([
        "provenance".into(),
        "vulnerabilities".into(),
        "source_posture".into(),
    ]);
    settings.validate().unwrap();
    let settings = Arc::new(settings);
    let store = Store { pool };
    let blobs = BlobStore::new(&settings.storage).unwrap();
    let app = gateway::router(AppState::new(
        settings.clone(),
        store.clone(),
        blobs.clone(),
        "a".repeat(32),
        "r".repeat(32),
    ));
    let request = || {
        Request::builder()
            .uri("/r/npm/fixture.bin")
            .header("authorization", format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let document = blobs
        .put(serde_json::to_vec(&json!({"mock":"attestation"})).unwrap())
        .await
        .unwrap();
    store
        .document(&digest, "attestation", "publisher_declared", &document)
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    let evidence = store
        .evidence(&digest, &settings.fingerprint())
        .await
        .unwrap();
    assert_eq!(
        evidence
            .iter()
            .find(|e| e.check == "vulnerabilities")
            .unwrap()
            .expires_at
            .timestamp_millis(),
        expires.timestamp_millis()
    );
    let inspection = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/artifacts/{digest}"))
                .header("authorization", format!("Bearer {}", "a".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let inspected: serde_json::Value =
        serde_json::from_slice(&inspection.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(inspected["identities"][0]["origin"], binding.origin);
    sqlx::query("UPDATE evidence SET expires_at=now()-interval '1 second' WHERE subject=$1 AND check_name='vulnerabilities'").bind(&digest).execute(&store.pool).await.unwrap();
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
}
