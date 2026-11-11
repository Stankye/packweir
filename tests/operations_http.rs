use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use packweir::{
    config::Config,
    gateway::{self, AppState},
    storage::BlobStore,
    store::Store,
};
use std::sync::Arc;
use tower::ServiceExt;

#[sqlx::test(migrations = "./migrations")]
async fn operational_endpoints_require_admin_and_fail_without_database(pool: sqlx::PgPool) {
    let root = tempfile::tempdir().unwrap();
    let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    config.storage = packweir::config::StorageConfig::Fs {
        root: root.path().to_string_lossy().into(),
    };
    let blobs = BlobStore::new(&config.storage).unwrap();
    let app = gateway::router(AppState::new(
        Arc::new(config),
        Store { pool: pool.clone() },
        blobs,
        "a".repeat(32),
        "r".repeat(32),
    ));
    let request = |path: &str, token: Option<&str>| {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request.body(Body::empty()).unwrap()
    };
    for path in ["/metrics", "/api/v1/operations"] {
        for token in [None, Some("wrong"), Some(&"r".repeat(32))] {
            assert_eq!(
                app.clone()
                    .oneshot(request(path, token))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let response = app
            .clone()
            .oneshot(request(path, Some(&"a".repeat(32))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        if path == "/metrics" {
            assert_eq!(
                response.headers()["content-type"],
                "text/plain; version=0.0.4; charset=utf-8"
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let rendered = std::str::from_utf8(&bytes).unwrap();
            assert!(rendered.contains("# HELP") && rendered.contains("# TYPE"));
        }
    }
    pool.close().await;
    for path in ["/metrics", "/api/v1/operations"] {
        let response = app
            .clone()
            .oneshot(request(path, Some(&"a".repeat(32))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"{\"error\":\"operations_unavailable\"}");
    }
}
