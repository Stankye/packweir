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
async fn delivery_scopes_isolate_aliases_and_explain_policy_while_sharing_bytes(
    pool: sqlx::PgPool,
) {
    use packweir::{
        config::{CommandScanner, PinnedResource, ScannerDriver},
        model::sha256,
        policy::{PolicyRequirements, PolicyScope},
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    let temp = tempfile::tempdir().unwrap();
    let payload = b"same harmless package bytes";
    let digest = sha256(payload);
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", upstream_listener.local_addr().unwrap());
    let other_manifest = json!({"name":"@other/pkg","versions":{"1.0":{"name":"@other/pkg","version":"1.0","dist":{"tarball":format!("{origin}@other/pkg/-/pkg-1.0.tgz")}}}});
    let acme_manifest = json!({"name":"@acme/pkg","versions":{"1.0":{"name":"@acme/pkg","version":"1.0","dist":{"tarball":format!("{origin}@acme/pkg/-/pkg-1.0.tgz")}}}});
    let upstream = tokio::spawn(async move {
        axum::serve(
            upstream_listener,
            Router::new()
                .route(
                    "/@other/pkg",
                    get(move || {
                        let value = other_manifest.clone();
                        async move { axum::Json(value) }
                    }),
                )
                .route(
                    "/@acme/pkg",
                    get(move || {
                        let value = acme_manifest.clone();
                        async move { axum::Json(value) }
                    }),
                )
                .fallback(get(|| async { "same harmless package bytes" })),
        )
        .await
        .unwrap()
    });
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), &origin);
    settings.public_url = format!("http://{}/", gateway_listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let additions = PolicyRequirements {
        revision: "review-v1".into(),
        required: vec!["review".into()],
        deny_on_failure: vec![],
    };
    let mut strict = settings.repositories["npm"].clone();
    strict.policy = Some(additions.clone());
    settings.repositories.insert("npm-strict".into(), strict);
    settings.policy_scopes.push(PolicyScope {
        name: "acme".into(),
        repository: "npm".into(),
        namespace: Some("@acme".into()),
        package: None,
        policy: additions,
    });
    let report =
        serde_json::to_vec(&json!({"outcome":"fail","details":{"reason":"test review failure"}}))
            .unwrap();
    let report_path = temp.path().join("report.json");
    std::fs::write(&report_path, &report).unwrap();
    let program = support::fixture_program();
    settings.scanners.insert(
        "review".into(),
        CommandScanner {
            program: program.to_string_lossy().into(),
            args: vec!["scope-report".into()],
            version: "fixture-v1".into(),
            timeout_seconds: 5,
            environment: BTreeMap::new(),
            program_sha256: Some(sha256(&std::fs::read(program).unwrap())),
            resources: BTreeMap::from([(
                "report".into(),
                PinnedResource {
                    path: report_path.to_string_lossy().into(),
                    sha256: sha256(&report),
                },
            )]),
            driver: ScannerDriver::Command,
        },
    );
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
    let server_app = app.clone();
    let gateway_server =
        tokio::spawn(async move { axum::serve(gateway_listener, server_app).await.unwrap() });
    let request = |path: &str| {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    let open = "/r/npm/@other/pkg/-/pkg-1.0.tgz";
    let protected = "/r/npm/@acme/pkg/-/pkg-1.0.tgz";
    let repository_protected = "/r/npm-strict/@other/pkg/-/pkg-1.0.tgz";
    for metadata in [
        "/r/npm/@other/pkg",
        "/r/npm/@acme/pkg",
        "/r/npm-strict/@other/pkg",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(metadata))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        app.clone().oneshot(request(open)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request(open)).await.unwrap().status(),
        StatusCode::OK
    );
    for route in [protected, repository_protected] {
        assert_eq!(
            app.clone().oneshot(request(route)).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        // Registering an alias must not revoke or lend the unrelated delivery's approval.
        assert_eq!(
            app.clone().oneshot(request(open)).await.unwrap().status(),
            StatusCode::OK
        );
        scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
            .await
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request(route)).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let unknown = "/r/npm/opaque.tgz";
    assert_eq!(
        app.clone()
            .oneshot(request(unknown))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(unknown))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let report: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(report["decision"]["state"], "denied");
    let scopes = report["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 4);
    let configurations: std::collections::BTreeSet<_> = scopes
        .iter()
        .map(|s| s["configuration"].as_str().unwrap())
        .collect();
    assert_eq!(configurations.len(), 4);
    let opaque = scopes
        .iter()
        .find(|s| s["scope"]["package"].is_null())
        .unwrap();
    assert_eq!(opaque["decision"]["state"], "pending");
    assert!(
        opaque["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["check"] == "package_identity" && c["status"] == "inconclusive")
    );
    let blob_count: i64 = sqlx::query_scalar("SELECT count(DISTINCT digest) FROM artifacts")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(blob_count, 1);
    let configuration_path = temp.path().join("cli.toml");
    std::fs::write(&configuration_path, toml::to_string(&*settings).unwrap()).unwrap();
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_packweir"))
        .args([
            "--config",
            configuration_path.to_str().unwrap(),
            "explain",
            &digest,
            "--repository",
            "npm-strict",
        ])
        .env("PACKWEIR_ADMIN_TOKEN", "a".repeat(32))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explanation = String::from_utf8(output.stdout).unwrap();
    assert!(
        explanation.contains("review: fail (required)")
            && explanation.contains("repository:npm-strict:review-v1")
    );
    assert!(!explanation.contains("Repository: npm\n"));
    let open_origin = format!("{origin}@other/pkg/-/pkg-1.0.tgz");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_packweir"))
        .args([
            "--config",
            configuration_path.to_str().unwrap(),
            "explain",
            &digest,
            "--repository",
            "npm",
            "--origin",
            &open_origin,
            "--json",
        ])
        .env("PACKWEIR_ADMIN_TOKEN", "a".repeat(32))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let filtered: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(filtered["decision"]["state"], "approved");
    assert_eq!(filtered["scopes"].as_array().unwrap().len(), 1);
    let selected = &filtered["scopes"][0];
    assert_eq!(selected["scope"]["origin"], open_origin);
    let stored:serde_json::Value=sqlx::query_scalar("SELECT document FROM decisions WHERE repository='npm' AND document->>'state'='approved' ORDER BY id DESC LIMIT 1")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(stored["scope"]["origin"], open_origin);
    assert!(stored["policy"]["layers"].is_array());
    let rescan = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/artifacts/{digest}/rescan"))
                .header("authorization", format!("Bearer {}", "a".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rescan.status(), StatusCode::ACCEPTED);
    let queued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE subject=$1 AND state='queued'")
            .bind(&digest)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(queued, 4);
    assert_eq!(
        app.clone().oneshot(request(open)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for _ in 0..4 {
        scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
            .await
            .unwrap();
    }
    assert_eq!(
        app.clone().oneshot(request(open)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request(protected))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(blobs.read(&digest).await.unwrap(), payload);
    gateway_server.abort();
    upstream.abort();
}

#[sqlx::test(migrations = false)]
async fn migration_preserves_legacy_blobs_but_requires_new_delivery_approval(pool: sqlx::PgPool) {
    use packweir::model::sha256;
    let temp = tempfile::tempdir().unwrap();
    let migration_directory = temp.path().join("old-migrations");
    std::fs::create_dir(&migration_directory).unwrap();
    std::fs::write(
        migration_directory.join("0001_initial.sql"),
        include_str!("../migrations/0001_initial.sql"),
    )
    .unwrap();
    sqlx::migrate::Migrator::new(migration_directory.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    let settings = Arc::new(config(temp.path(), "http://127.0.0.1:1/"));
    let store = Store { pool };
    let blobs = BlobStore::new(&settings.storage).unwrap();
    let bytes = b"retained legacy bytes";
    let digest = blobs.put(bytes.to_vec()).await.unwrap();
    let origin = "http://127.0.0.1:1/pkg/-/pkg-1.0.tgz";
    sqlx::query("INSERT INTO artifacts(repository,origin,digest,size,filename,content_type) VALUES('npm',$1,$2,$3,'pkg-1.0.tgz','application/octet-stream')")
        .bind(origin).bind(&digest).bind(bytes.len() as i64).execute(&store.pool).await.unwrap();
    store
        .enqueue(&digest, "legacy-deployment", "pkg-1.0.tgz")
        .await
        .unwrap();
    sqlx::migrate!().run(&store.pool).await.unwrap();
    assert!(
        store
            .artifact("npm", origin)
            .await
            .unwrap()
            .unwrap()
            .package
            .is_none()
    );
    assert_eq!(blobs.read(&digest).await.unwrap(), bytes);
    let app = gateway::router(AppState::new(
        settings.clone(),
        store.clone(),
        blobs.clone(),
        "a".repeat(32),
        "r".repeat(32),
    ));
    let request = || {
        Request::builder()
            .uri("/r/npm/pkg/-/pkg-1.0.tgz")
            .header("authorization", format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        store
            .artifact("npm", origin)
            .await
            .unwrap()
            .unwrap()
            .package
            .unwrap()
            .purl,
        "pkg:npm/pkg@1.0"
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(sha256(&blobs.read(&digest).await.unwrap()), digest);
    let state: String =
        sqlx::query_scalar("SELECT state FROM jobs WHERE configuration='legacy-deployment'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(state, "queued");
}

#[sqlx::test(migrations = "./migrations")]
async fn misleading_tarball_paths_and_conflicting_discovery_claims_cannot_skip_namespace_policy(
    pool: sqlx::PgPool,
) {
    use packweir::policy::{PolicyRequirements, PolicyScope};
    use serde_json::json;
    let temp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let tarball = format!("{origin}@other/widget/-/widget-1.0.tgz");
    let strict = json!({"name":"@acme/widget","versions":{"1.0":{"name":"@acme/widget","version":"1.0","dist":{"tarball":tarball}}}});
    let other = json!({"name":"@other/widget","versions":{"1.0":{"name":"@other/widget","version":"1.0","dist":{"tarball":tarball}}}});
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/@acme/widget",
                    get(move || {
                        let value = strict.clone();
                        async move { axum::Json(value) }
                    }),
                )
                .route(
                    "/@other/widget",
                    get(move || {
                        let value = other.clone();
                        async move { axum::Json(value) }
                    }),
                )
                .route(
                    "/@other/widget/-/widget-1.0.tgz",
                    get(|| async { "fixture" }),
                ),
        )
        .await
        .unwrap()
    });
    let mut settings = config(temp.path(), &origin);
    settings.policy_scopes.push(PolicyScope {
        name: "acme".into(),
        repository: "npm".into(),
        namespace: Some("@acme".into()),
        package: None,
        policy: PolicyRequirements {
            revision: "strict-v1".into(),
            required: vec!["publisher_signature".into()],
            deny_on_failure: vec![],
        },
    });
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
    let request = |path: &str| {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    let route = "/r/npm/@other/widget/-/widget-1.0.tgz";
    assert_eq!(
        app.clone().oneshot(request(route)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request(route)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        app.clone()
            .oneshot(request("/r/npm/@acme/widget"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(request(route)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for _ in 0..4 {
        scanner::worker(settings.clone(), store.clone(), blobs.clone(), true)
            .await
            .unwrap();
    }
    let artifact = store.artifact("npm", &tarball).await.unwrap().unwrap();
    assert_eq!(artifact.package.as_ref().unwrap().name, "@acme/widget");
    assert!(
        settings
            .effective_policy(&artifact.scope())
            .unwrap()
            .policy
            .required
            .contains(&"publisher_signature".into())
    );
    assert_eq!(
        app.clone().oneshot(request(route)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        app.clone()
            .oneshot(request("/r/npm/@other/widget"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(
        store
            .artifact("npm", &tarball)
            .await
            .unwrap()
            .unwrap()
            .package
            .is_none()
    );
    assert_eq!(
        app.oneshot(request(route)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
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
    let artifact = store.artifacts(&digest).await.unwrap().remove(0);
    let delivery_configuration = settings.delivery_fingerprint(&artifact.scope()).unwrap();
    assert!(
        store
            .evidence(&digest, &delivery_configuration)
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
    let artifact = store
        .artifact(&binding.repository, &binding.origin)
        .await
        .unwrap()
        .unwrap();
    let evidence = store
        .evidence(
            &digest,
            &settings.delivery_fingerprint(&artifact.scope()).unwrap(),
        )
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
