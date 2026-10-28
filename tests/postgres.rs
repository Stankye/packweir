//! Requires PostgreSQL with CREATE DATABASE privilege; CI provides an isolated service.
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
