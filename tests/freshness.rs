//! Mutable upstreams must never inherit approval for substituted or stale bytes.
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use http_body_util::BodyExt;
use packweir::{
    config::Config,
    gateway::{self, AppState},
    model::sha256,
    registry, scanner,
    storage::BlobStore,
    store::Store,
};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU16, AtomicUsize, Ordering},
};
use tower::ServiceExt;

const FIRST: &[u8] = b"first retained package fixture";
const SECOND: &[u8] = b"substituted package fixture";
const ROUTE: &str = "/r/npm/pkg/-/pkg-1.0.tgz";

#[derive(Clone)]
struct Upstream {
    payload: Arc<RwLock<Vec<u8>>>,
    status: Arc<AtomicU16>,
    requests: Arc<AtomicUsize>,
    outside_requests: Arc<AtomicUsize>,
    redirect: Arc<RwLock<Option<String>>>,
}

async fn package(State(upstream): State<Upstream>, headers: HeaderMap) -> Response {
    assert!(headers.get(header::AUTHORIZATION).is_none());
    upstream.requests.fetch_add(1, Ordering::SeqCst);
    let redirect = upstream.redirect.read().unwrap().clone();
    if let Some(location) = redirect {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response();
    }
    let bytes = upstream.payload.read().unwrap().clone();
    (
        StatusCode::from_u16(upstream.status.load(Ordering::SeqCst)).unwrap(),
        bytes,
    )
        .into_response()
}

async fn outside(State(upstream): State<Upstream>) -> &'static str {
    upstream.outside_requests.fetch_add(1, Ordering::SeqCst);
    "must not be fetched"
}

struct Fixture {
    _directory: tempfile::TempDir,
    upstream: Upstream,
    upstream_server: tokio::task::JoinHandle<()>,
    config: Arc<Config>,
    store: Store,
    blobs: BlobStore,
    app: Router,
    artifact_origin: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.upstream_server.abort();
    }
}

impl Fixture {
    async fn new(pool: sqlx::PgPool, max_age: Option<u64>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let upstream = Upstream {
            payload: Arc::new(RwLock::new(FIRST.to_vec())),
            status: Arc::new(AtomicU16::new(200)),
            requests: Arc::new(AtomicUsize::new(0)),
            outside_requests: Arc::new(AtomicUsize::new(0)),
            redirect: Arc::new(RwLock::new(None)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}/allowed/", listener.local_addr().unwrap());
        let server = Router::new()
            .route("/allowed/pkg/-/pkg-1.0.tgz", get(package))
            .route("/outside", get(outside))
            .with_state(upstream.clone());
        let upstream_server =
            tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
        let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
        config.storage = packweir::config::StorageConfig::Fs {
            root: directory.path().to_string_lossy().into_owned(),
        };
        config.allow_private_upstreams = true;
        config.repositories.retain(|name, _| name == "npm");
        let repo = config.repositories.get_mut("npm").unwrap();
        repo.upstream = Some(upstream_url.parse().unwrap());
        repo.cache_max_age_seconds = max_age;
        config.validate().unwrap();
        let config = Arc::new(config);
        let store = Store { pool };
        let blobs = BlobStore::new(&config.storage).unwrap();
        let app = gateway::router(AppState::new(
            config.clone(),
            store.clone(),
            blobs.clone(),
            "a".repeat(32),
            "r".repeat(32),
        ));
        Self {
            _directory: directory,
            upstream,
            upstream_server,
            config,
            store,
            blobs,
            app,
            artifact_origin: format!("{upstream_url}pkg/-/pkg-1.0.tgz"),
        }
    }

    async fn get(&self, route: &str, range: bool) -> (StatusCode, Vec<u8>) {
        let mut request = Request::builder()
            .uri(route)
            .header(header::AUTHORIZATION, format!("Bearer {}", "r".repeat(32)));
        if range {
            request = request.header(header::RANGE, "bytes=0-3");
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        (
            response.status(),
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    async fn stage_and_scan(&self, route: &str) {
        let (status, body) = self.get(route, false).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(!body.windows(FIRST.len()).any(|w| w == FIRST));
        self.scan().await;
    }

    async fn scan(&self) {
        scanner::worker(
            self.config.clone(),
            self.store.clone(),
            self.blobs.clone(),
            true,
        )
        .await
        .unwrap();
    }

    fn count(&self) -> usize {
        self.upstream.requests.load(Ordering::SeqCst)
    }

    async fn validation_time(&self, origin: &str, digest: &str) -> chrono::DateTime<Utc> {
        self.store
            .artifact_last_validated("npm", origin, digest)
            .await
            .unwrap()
            .unwrap()
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn fresh_hits_avoid_network_and_identical_revalidation_preserves_evidence(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, Some(3600)).await;
    fixture.stage_and_scan(ROUTE).await;
    assert_eq!(
        fixture.get(ROUTE, false).await,
        (StatusCode::OK, FIRST.to_vec())
    );
    assert_eq!(fixture.count(), 1);
    let digest = sha256(FIRST);
    let artifact = fixture
        .store
        .artifact("npm", &fixture.artifact_origin)
        .await
        .unwrap()
        .unwrap();
    let configuration = fixture
        .config
        .delivery_fingerprint(&artifact.scope())
        .unwrap();
    let before = fixture
        .store
        .evidence(&digest, &configuration)
        .await
        .unwrap();
    assert!(!before.is_empty());
    // Legacy rows and clock rollback must not grant indefinite freshness.
    for timestamp in ["now()-interval '2 hours'", "NULL", "now()+interval '1 day'"] {
        sqlx::query(&format!(
            "UPDATE artifacts SET last_validated_at={timestamp} WHERE repository='npm'"
        ))
        .execute(&fixture.store.pool)
        .await
        .unwrap();
        let previous_count = fixture.count();
        assert_eq!(
            fixture.get(ROUTE, false).await,
            (StatusCode::OK, FIRST.to_vec())
        );
        assert_eq!(fixture.count(), previous_count + 1);
        let after = fixture
            .store
            .evidence(&digest, &configuration)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(after).unwrap()
        );
        let validated = fixture
            .validation_time(&fixture.artifact_origin, &digest)
            .await;
        assert!(validated <= Utc::now());
        assert!((Utc::now() - validated).num_seconds() < 30);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_bytes_and_reverted_bytes_require_their_own_fresh_approval(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, Some(0)).await;
    fixture.stage_and_scan(ROUTE).await;
    assert_eq!(
        fixture.get(ROUTE, false).await,
        (StatusCode::OK, FIRST.to_vec())
    );
    *fixture.upstream.payload.write().unwrap() = SECOND.to_vec();
    let (status, pending) = fixture.get(ROUTE, true).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!pending.windows(SECOND.len()).any(|w| w == SECOND));
    let artifact = fixture
        .store
        .artifact("npm", &fixture.artifact_origin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(artifact.digest, sha256(SECOND));
    fixture.scan().await;
    assert_eq!(
        fixture.get(ROUTE, false).await,
        (StatusCode::OK, SECOND.to_vec())
    );
    *fixture.upstream.payload.write().unwrap() = FIRST.to_vec();
    assert_eq!(
        fixture.get(ROUTE, false).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.scan().await;
    assert_eq!(
        fixture.get(ROUTE, false).await,
        (StatusCode::OK, FIRST.to_vec())
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_cache_is_not_served_after_upstream_failures_or_disallowed_redirects(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, Some(0)).await;
    fixture.stage_and_scan(ROUTE).await;
    assert_eq!(fixture.get(ROUTE, false).await.0, StatusCode::OK);
    let digest = sha256(FIRST);
    let validated = fixture
        .validation_time(&fixture.artifact_origin, &digest)
        .await;
    for (upstream_status, expected) in
        [(500, StatusCode::BAD_GATEWAY), (404, StatusCode::NOT_FOUND)]
    {
        fixture
            .upstream
            .status
            .store(upstream_status, Ordering::SeqCst);
        let (status, body) = fixture.get(ROUTE, false).await;
        assert_eq!(status, expected);
        assert!(!body.windows(FIRST.len()).any(|w| w == FIRST));
        assert_eq!(
            fixture
                .validation_time(&fixture.artifact_origin, &digest)
                .await,
            validated
        );
    }
    fixture.upstream.status.store(200, Ordering::SeqCst);
    *fixture.upstream.redirect.write().unwrap() = Some("/outside".into());
    assert_eq!(fixture.get(ROUTE, false).await.0, StatusCode::BAD_GATEWAY);
    assert_eq!(fixture.upstream.outside_requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .validation_time(&fixture.artifact_origin, &digest)
            .await,
        validated
    );
    *fixture.upstream.redirect.write().unwrap() = None;
    fixture.upstream_server.abort();
    tokio::task::yield_now().await;
    let (status, body) = fixture.get(ROUTE, false).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(!body.windows(FIRST.len()).any(|w| w == FIRST));
}

#[sqlx::test(migrations = "./migrations")]
async fn integrity_substitution_does_not_refresh_or_replace_a_pinned_mapping(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, Some(0)).await;
    let digest = sha256(FIRST);
    let mut target: url::Url = fixture.artifact_origin.parse().unwrap();
    target.set_fragment(Some(&format!("sha256={digest}")));
    let wrapped: url::Url = registry::wrap(&fixture.config.public_url, "npm", &target)
        .parse()
        .unwrap();
    let route = wrapped.path();
    fixture.stage_and_scan(route).await;
    assert_eq!(fixture.get(route, false).await.0, StatusCode::OK);
    let validated = fixture.validation_time(target.as_str(), &digest).await;
    *fixture.upstream.payload.write().unwrap() = SECOND.to_vec();
    let (status, body) = fixture.get(route, true).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!body.windows(SECOND.len()).any(|w| w == SECOND));
    let retained = fixture
        .store
        .artifact("npm", target.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.digest, digest);
    assert_eq!(
        fixture.validation_time(target.as_str(), &digest).await,
        validated
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn immutable_default_reuses_retained_bytes_without_automatic_upstream_validation(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, None).await;
    fixture.stage_and_scan(ROUTE).await;
    fixture.upstream.status.store(500, Ordering::SeqCst);
    *fixture.upstream.payload.write().unwrap() = SECOND.to_vec();
    sqlx::query("UPDATE artifacts SET last_validated_at=NULL")
        .execute(&fixture.store.pool)
        .await
        .unwrap();
    assert_eq!(
        fixture.get(ROUTE, false).await,
        (StatusCode::OK, FIRST.to_vec())
    );
    assert_eq!(fixture.count(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn identity_registration_does_not_extend_upstream_freshness(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, Some(3600)).await;
    fixture.stage_and_scan(ROUTE).await;
    let digest = sha256(FIRST);
    let validated = fixture
        .validation_time(&fixture.artifact_origin, &digest)
        .await;
    let mut artifact = fixture
        .store
        .artifact("npm", &fixture.artifact_origin)
        .await
        .unwrap()
        .unwrap();
    artifact.package = None;
    fixture.store.register(&artifact).await.unwrap();
    assert_eq!(
        fixture
            .validation_time(&fixture.artifact_origin, &digest)
            .await,
        validated
    );
    assert_eq!(
        fixture.get(ROUTE, false).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        fixture
            .validation_time(&fixture.artifact_origin, &digest)
            .await,
        validated
    );
    fixture.scan().await;
    assert_eq!(fixture.get(ROUTE, false).await.0, StatusCode::OK);
    assert_eq!(fixture.count(), 1);
}

#[sqlx::test(migrations = false)]
async fn migration_preserves_blobs_but_does_not_invent_upstream_freshness(pool: sqlx::PgPool) {
    let old_migrations = tempfile::tempdir().unwrap();
    for (name, content) in [
        (
            "0001_initial.sql",
            include_str!("../migrations/0001_initial.sql"),
        ),
        (
            "0002_delivery_scopes.sql",
            include_str!("../migrations/0002_delivery_scopes.sql"),
        ),
    ] {
        std::fs::write(old_migrations.path().join(name), content).unwrap();
    }
    sqlx::migrate::Migrator::new(old_migrations.path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    let fixture = Fixture::new(pool, Some(3600)).await;
    let original_digest = fixture.blobs.put(FIRST.to_vec()).await.unwrap();
    sqlx::query("INSERT INTO artifacts(repository,origin,digest,size,filename,content_type) VALUES('npm',$1,$2,$3,'pkg-1.0.tgz','application/octet-stream')")
        .bind(&fixture.artifact_origin).bind(&original_digest).bind(FIRST.len() as i64)
        .execute(&fixture.store.pool).await.unwrap();
    sqlx::migrate!().run(&fixture.store.pool).await.unwrap();
    assert_eq!(
        fixture
            .store
            .artifact_last_validated("npm", &fixture.artifact_origin, &original_digest)
            .await
            .unwrap(),
        None
    );
    *fixture.upstream.payload.write().unwrap() = SECOND.to_vec();
    assert_eq!(
        fixture.get(ROUTE, false).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.count(), 1);
    let current = fixture
        .store
        .artifact("npm", &fixture.artifact_origin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.digest, sha256(SECOND));
    assert_eq!(fixture.blobs.read(&original_digest).await.unwrap(), FIRST);
    assert_eq!(fixture.blobs.read(&current.digest).await.unwrap(), SECOND);
}
