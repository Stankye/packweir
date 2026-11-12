//! End-to-end hosted release governance over the actual Axum router and worker.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    access::{AccessControl, Action, Grant, MavenOwnership, ServicePrincipal},
    config::{Config, RepositoryKind, StorageConfig},
    gateway::{self, AppState},
    hosted,
    maven::{self, ChecksumAlgorithm},
    model::{Decision, Evidence, Outcome, sha256},
    scanner,
    storage::BlobStore,
    store::Store,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    sync::Arc,
};
use tower::ServiceExt;
use uuid::Uuid;

const NAME: &str = "dev.private:library";
const BASE: &str = "dev/private/library/1.0.0/library-1.0.0";
const POM:&[u8]=b"<project><modelVersion>4.0.0</modelVersion><groupId>dev.private</groupId><artifactId>library</artifactId><version>1.0.0</version></project>";

fn jar() -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive
        .start_file("library.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(b"immutable library content").unwrap();
    archive.finish().unwrap().into_inner()
}
struct Fixture {
    app: Router,
    config: Arc<Config>,
    store: Store,
    blobs: BlobStore,
    _directory: tempfile::TempDir,
}
fn secrets() -> BTreeMap<String, String> {
    BTreeMap::from_iter(
        ["reader", "writer", "promoter", "other"]
            .map(|id| (id.into(), format!("{id}-{}", "x".repeat(40)))),
    )
}
impl Fixture {
    fn new(pool: sqlx::PgPool) -> Self {
        Self::with_proxy(pool, None)
    }
    fn with_proxy(pool: sqlx::PgPool, upstream: Option<&str>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
        config.repositories.retain(|name, _| name == "maven");
        let repo = config.repositories.get_mut("maven").unwrap();
        repo.kind = RepositoryKind::Hosted;
        repo.upstream = None;
        repo.download_origins.clear();
        repo.token_env = None;
        repo.cargo_download_template = None;
        repo.cache_max_age_seconds = None;
        repo.retain = true;
        if let Some(url) = upstream {
            let mut proxy = repo.clone();
            proxy.kind = RepositoryKind::Proxy;
            proxy.upstream = Some(url.parse().unwrap());
            proxy.retain = false;
            config.repositories.insert("public".into(), proxy);
            config.allow_private_upstreams = true;
        }
        config.max_download_bytes = 4096;
        config.storage = StorageConfig::Fs {
            root: directory.path().to_string_lossy().into(),
        };
        config.access.legacy_read_enabled = false;
        config.access.maven_owners = vec![MavenOwnership {
            additional_repositories: vec![],
            namespace: "dev.private".into(),
            repository: "maven".into(),
        }];
        let grants = |actions| {
            vec![Grant {
                repository: "maven".into(),
                namespace: Some("dev.private".into()),
                actions,
            }]
        };
        for (id, actions) in [
            ("reader", vec![Action::Read]),
            ("writer", vec![Action::Write]),
            ("promoter", vec![Action::Promote]),
            ("other", vec![Action::Write]),
        ] {
            let mut grant = grants(actions);
            if id == "other" {
                grant[0].namespace = Some("dev.other".into());
            }
            if id == "reader" && upstream.is_some() {
                grant.push(Grant {
                    repository: "public".into(),
                    namespace: None,
                    actions: vec![Action::Read],
                });
            }
            config.access.principals.insert(
                id.into(),
                ServicePrincipal {
                    token_env: format!("PACKWEIR_TEST_{}", id.to_uppercase()),
                    expires_at: None,
                    grants: grant,
                },
            );
        }
        config.validate().unwrap();
        let access =
            AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &secrets())
                .unwrap();
        let config = Arc::new(config);
        let store = Store { pool };
        let blobs = BlobStore::new(&config.storage).unwrap();
        let state = AppState::with_access(
            config.clone(),
            store.clone(),
            blobs.clone(),
            "a".repeat(32),
            "r".repeat(32),
            access,
        );
        Self {
            app: gateway::router(state),
            config,
            store,
            blobs,
            _directory: directory,
        }
    }
    fn reconfigure(&mut self, config: Config) {
        config.validate().unwrap();
        let access =
            AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &secrets())
                .unwrap();
        self.config = Arc::new(config);
        self.app = gateway::router(AppState::with_access(
            self.config.clone(),
            self.store.clone(),
            self.blobs.clone(),
            "a".repeat(32),
            "r".repeat(32),
            access,
        ));
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        who: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Value, Vec<u8>, axum::http::HeaderMap) {
        let token = match who {
            "admin" => "a".repeat(32),
            "legacy" => "r".repeat(32),
            "none" => String::new(),
            _ => format!("{who}-{}", "x".repeat(40)),
        };
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if who != "none" {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            bytes,
            headers,
        )
    }
    async fn create(&self, id: Uuid) -> Value {
        let (status, body, ..) = self
            .request(
                "POST",
                "/api/v1/repositories/maven/staging",
                "writer",
                serde_json::to_vec(&json!({"id":id,"name":NAME,"version":"1.0.0"})).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body
    }
    async fn upload(&self, id: Uuid, extension: &str, bytes: Vec<u8>) -> StatusCode {
        self.request(
            "PUT",
            &format!("/api/v1/staging/{id}/{BASE}.{extension}"),
            "writer",
            bytes,
        )
        .await
        .0
    }
    async fn stage_full(&self) -> (Uuid, String) {
        let id = Uuid::new_v4();
        self.create(id).await;
        assert_eq!(
            self.upload(id, "pom", POM.to_vec()).await,
            StatusCode::CREATED
        );
        assert_eq!(self.upload(id, "jar", jar()).await, StatusCode::CREATED);
        let (status, body, ..) = self
            .request(
                "POST",
                &format!("/api/v1/staging/{id}/seal"),
                "writer",
                vec![],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (id, body["manifest_digest"].as_str().unwrap().into())
    }
    async fn analyze(&self) {
        let mut jobs = 0;
        while let Some(job) = self
            .store
            .lease(&self.config.fingerprint(), 60)
            .await
            .unwrap()
        {
            scanner::analyze(&self.config, &self.store, &self.blobs, &job)
                .await
                .unwrap();
            jobs += 1;
        }
        assert!(jobs >= 2);
    }
    async fn action(
        &self,
        id: Uuid,
        action: &str,
        digest: &str,
        who: &str,
    ) -> (StatusCode, Value, Vec<u8>, axum::http::HeaderMap) {
        self.request(
            "POST",
            &format!("/api/v1/staging/{id}/{action}"),
            who,
            serde_json::to_vec(&json!({"manifest_digest":digest})).unwrap(),
        )
        .await
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn staged_native_files_are_invisible_until_atomic_promotion_and_revocation_is_terminal(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool);
    let (id, digest) = fixture.stage_full().await;
    for method in ["GET", "HEAD"] {
        for suffix in ["jar", "pom", "jar.sha256"] {
            let (status, _, bytes, headers) = fixture
                .request(
                    method,
                    &format!("/r/maven/{BASE}.{suffix}"),
                    "reader",
                    vec![],
                )
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(!headers.contains_key("x-packweir-sha256"));
            if method == "HEAD" {
                assert!(bytes.is_empty());
            }
        }
    }
    assert_eq!(
        fixture
            .request(
                "GET",
                "/r/maven/dev/private/library/maven-metadata.xml",
                "reader",
                vec![]
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture.action(id, "promote", &digest, "writer").await.0,
        StatusCode::FORBIDDEN
    );
    fixture.analyze().await;
    assert_eq!(
        fixture
            .action(id, "promote", &"0".repeat(64), "promoter")
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (status, receipt, ..) = fixture.action(id, "promote", &digest, "promoter").await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["actor"], "promoter");
    assert_eq!(receipt["files"].as_array().unwrap().len(), 2);
    let (status, _, bytes, headers) = fixture
        .request("GET", &format!("/r/maven/{BASE}.jar"), "reader", vec![])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, jar());
    assert_eq!(headers["x-packweir-sha256"], sha256(&bytes));
    let (_, _, checksum, _) = fixture
        .request(
            "GET",
            &format!("/r/maven/{BASE}.jar.sha256"),
            "reader",
            vec![],
        )
        .await;
    assert_eq!(checksum, sha256(&bytes).into_bytes());
    let (status, _, metadata, _) = fixture
        .request(
            "GET",
            "/r/maven/dev/private/library/maven-metadata.xml",
            "reader",
            vec![],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8(metadata)
            .unwrap()
            .contains("<version>1.0.0</version>")
    );
    assert_eq!(
        fixture.action(id, "revoke", &digest, "promoter").await.0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .request("GET", &format!("/r/maven/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::CONFLICT
    );
    let (status, ..) = fixture
        .request(
            "POST",
            "/api/v1/repositories/maven/staging",
            "writer",
            serde_json::to_vec(&json!({"name":NAME,"version":"1.0.0"})).unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn publish_permissions_immutability_paths_limits_and_pom_packaging_are_enforced(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool);
    let id = Uuid::new_v4();
    let payload = serde_json::to_vec(&json!({"id":id,"name":NAME,"version":"1.0.0"})).unwrap();
    for who in ["none", "admin", "legacy", "reader", "promoter", "other"] {
        let status = fixture
            .request(
                "POST",
                "/api/v1/repositories/maven/staging",
                who,
                payload.clone(),
            )
            .await
            .0;
        assert_eq!(
            status,
            if ["none", "admin", "legacy"].contains(&who) {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
    fixture.create(id).await;
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/api/v1/staging/{id}/{BASE}.pom"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture.upload(id, "pom", POM.to_vec()).await,
        StatusCode::CREATED
    );
    assert_eq!(
        fixture.upload(id, "pom", POM.to_vec()).await,
        StatusCode::CREATED
    );
    assert_eq!(
        fixture
            .upload(
                id,
                "pom",
                String::from_utf8(POM.to_vec())
                    .unwrap()
                    .replace("</project>", "<description>changed</description></project>")
                    .into_bytes()
            )
            .await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/v1/staging/{id}/seal"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::BAD_REQUEST,
        "missing default jar cannot seal"
    );
    for path in [
        format!("{BASE}.jar?overwrite=true"),
        "dev/private/library/1.0.0/%6cibrary-1.0.0.jar".into(),
        "dev/private/../outside-1.0.0.jar".into(),
        "dev/other/library/1.0.0/library-1.0.0.jar".into(),
    ] {
        assert_eq!(
            fixture
                .request(
                    "PUT",
                    &format!("/api/v1/staging/{id}/{path}"),
                    "writer",
                    jar()
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        fixture.upload(id, "jar", vec![0; 4097]).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        fixture.upload(id, "jar.sha256", vec![b'0'; 64]).await,
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.upload(id, "jar", jar()).await, StatusCode::CREATED);
    assert_eq!(
        fixture.upload(id, "jar.sha256", vec![b'0'; 64]).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture
            .upload(
                id,
                "jar.sha256",
                maven::checksum(&jar(), ChecksumAlgorithm::Sha256).into_bytes()
            )
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        fixture
            .request(
                "PUT",
                &format!("/api/v1/staging/{id}/dev/private/library/maven-metadata.xml"),
                "writer",
                b"untrusted upstream metadata".to_vec()
            )
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/v1/staging/{id}/seal"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(fixture.upload(id, "jar", jar()).await, StatusCode::CONFLICT);
    assert_eq!(
        fixture
            .request("GET", &format!("/r/maven/{BASE}.jar"), "writer", vec![])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .request("GET", "/api/v1/operations", "writer", vec![])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_evidence_for_one_release_member_holds_all_files_and_checksums(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool);
    let (id, digest) = fixture.stage_full().await;
    fixture.analyze().await;
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::OK
    );
    let files = hosted::stage_files(&fixture.store, id).await.unwrap();
    let pom = &files
        .iter()
        .find(|file| file.path.ends_with(".pom"))
        .unwrap()
        .artifact;
    fixture.store.invalidate(&pom.digest).await.unwrap();
    for suffix in ["jar", "jar.sha1", "pom"] {
        assert_eq!(
            fixture
                .request(
                    "GET",
                    &format!("/r/maven/{BASE}.{suffix}"),
                    "reader",
                    vec![]
                )
                .await
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let configuration = fixture.config.delivery_fingerprint(&pom.scope()).unwrap();
    let job = fixture
        .store
        .lease(&fixture.config.fingerprint(), 60)
        .await
        .unwrap()
        .unwrap();
    // Hard failure is bound to the POM's current context and cannot be hidden by the JAR's passes.
    if job.subject == pom.digest {
        fixture
            .store
            .complete(
                &job,
                &[Evidence {
                    subject: pom.digest.clone(),
                    check: "archive_safety".into(),
                    tool_version: "test".into(),
                    configuration,
                    created_at: Utc::now() - Duration::seconds(1),
                    expires_at: Utc::now() + Duration::hours(1),
                    outcome: Outcome::Fail,
                    details: json!({}),
                    references: vec![],
                }],
            )
            .await
            .unwrap();
    } else {
        panic!("POM job must be oldest pending job");
    }
    assert_eq!(
        fixture
            .request("GET", &format!("/r/maven/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert!(matches!(
        hosted::delivery(
            &fixture.store,
            "maven",
            &format!("{BASE}.jar"),
            &fixture.config
        )
        .await
        .unwrap()
        .unwrap()
        .decision,
        Decision::Denied(_)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn physical_blob_tampering_blocks_promotion_and_delivery(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool);
    let (id, digest) = fixture.stage_full().await;
    fixture.analyze().await;
    let subject = sha256(&jar());
    let blob =
        fixture
            ._directory
            .path()
            .join(format!("blobs/sha256/{}/{}", &subject[..2], subject));
    std::fs::write(&blob, b"substituted").unwrap();
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.blobs.put(jar()).await.unwrap();
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::OK
    );
    std::fs::write(&blob, b"substituted").unwrap();
    assert_eq!(
        fixture
            .request("GET", &format!("/r/maven/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::BAD_GATEWAY
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn policy_change_requeues_quarantined_members_without_reusing_previous_approval(
    pool: sqlx::PgPool,
) {
    let mut fixture = Fixture::new(pool);
    let (id, digest) = fixture.stage_full().await;
    fixture.analyze().await;
    let mut updated = fixture.config.as_ref().clone();
    updated.policy.revision = "updated-hosted-policy".into();
    fixture.reconfigure(updated);
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::CONFLICT
    );
    fixture.analyze().await;
    assert_eq!(
        fixture.action(id, "promote", &digest, "promoter").await.0,
        StatusCode::OK
    );
    let (status, receipt, ..) = fixture
        .request("GET", &format!("/api/v1/staging/{id}"), "promoter", vec![])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["promotion"]["manifest_digest"], digest);
    assert_eq!(
        fixture
            .request("GET", &format!("/r/maven/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nonretaining_proxy_cannot_delete_a_blob_referenced_by_an_open_hosted_stage(
    pool: sqlx::PgPool,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(axum::routing::get(|| async { jar() })),
        )
        .await
        .unwrap()
    });
    let fixture = Fixture::with_proxy(pool, Some(&upstream));
    let id = Uuid::new_v4();
    fixture.create(id).await;
    assert_eq!(fixture.upload(id, "jar", jar()).await, StatusCode::CREATED);
    let path = "/r/public/dev/public/library/1.0.0/library-1.0.0.jar";
    assert_eq!(
        fixture.request("GET", path, "reader", vec![]).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let job = fixture
        .store
        .lease(&fixture.config.fingerprint(), 60)
        .await
        .unwrap()
        .unwrap();
    scanner::analyze(&fixture.config, &fixture.store, &fixture.blobs, &job)
        .await
        .unwrap();
    assert_eq!(
        fixture.request("GET", path, "reader", vec![]).await.0,
        StatusCode::OK
    );
    assert_eq!(fixture.blobs.read(&sha256(&jar())).await.unwrap(), jar());
    assert_eq!(
        hosted::stage_files(&fixture.store, id).await.unwrap().len(),
        1
    );
    server.abort();
}

#[sqlx::test(migrations = "./migrations")]
async fn only_the_original_writer_can_abort_an_open_stage_and_retry_never_sealed_coordinates(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool);
    let old = Uuid::new_v4();
    fixture.create(old).await;
    assert_eq!(
        fixture.upload(old, "pom", POM.to_vec()).await,
        StatusCode::CREATED
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/v1/staging/{old}/abort"),
                "promoter",
                vec![]
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/v1/staging/{old}/abort"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture.upload(old, "jar", jar()).await,
        StatusCode::CONFLICT
    );
    let (new, digest) = fixture.stage_full().await;
    assert_ne!(new, old);
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/v1/staging/{new}/abort"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
    fixture.analyze().await;
    assert_eq!(
        fixture.action(new, "promote", &digest, "promoter").await.0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/v1/staging/{new}/abort"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn cached_ambiguous_proxy_origins_cannot_bypass_new_namespace_reservations(
    pool: sqlx::PgPool,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(axum::routing::get(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async { jar() }
            })),
        )
        .await
        .unwrap()
    });
    let mut fixture = Fixture::with_proxy(pool, Some(&upstream));
    let mut config = fixture.config.as_ref().clone();
    config.repositories.get_mut("public").unwrap().retain = true;
    fixture.reconfigure(config);
    let path = "dev/public/library/1.0.0/library-1.0.0.jar?source=dev.private";
    let bytes = jar();
    let digest = fixture.blobs.put(bytes.clone()).await.unwrap();
    let artifact = packweir::model::Artifact {
        repository: "public".into(),
        origin: format!("{upstream}{path}"),
        digest,
        size: bytes.len() as i64,
        filename: "library-1.0.0.jar".into(),
        content_type: "application/java-archive".into(),
        package: packweir::identity::from_coordinates(
            packweir::model::Ecosystem::Maven,
            "dev.public:library",
            "1.0.0",
        ),
    };
    fixture.store.register(&artifact).await.unwrap();
    fixture
        .store
        .enqueue_delivery(
            &artifact,
            &fixture
                .config
                .delivery_fingerprint(&artifact.scope())
                .unwrap(),
            &fixture.config.fingerprint(),
        )
        .await
        .unwrap();
    let job = fixture
        .store
        .lease(&fixture.config.fingerprint(), 60)
        .await
        .unwrap()
        .unwrap();
    scanner::analyze(&fixture.config, &fixture.store, &fixture.blobs, &job)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .request("GET", &format!("/r/public/{path}"), "reader", vec![])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                "/api/v1/prefetch",
                "admin",
                serde_json::to_vec(&json!({"repository":"public","path":path})).unwrap()
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.blobs.read(&artifact.digest).await.unwrap(), bytes);
    server.abort();
}
