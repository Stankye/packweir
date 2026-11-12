//! Cross-repository governance through HTTP, shared storage, and real worker invocations.
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use packweir::{
    access::{AccessControl, Action, Grant, MavenOwnership, ServicePrincipal},
    config::{
        CommandScanner, Config, PinnedResource, RepositoryKind, ScannerDriver, StorageConfig,
    },
    gateway::{self, AppState},
    hosted,
    model::{Decision, Outcome, sha256},
    policy::PolicyRequirements,
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
const SOURCE_NOTE: &str = "private-source-assessment-must-not-leak";
const POM:&[u8]=b"<project><modelVersion>4.0.0</modelVersion><groupId>dev.private</groupId><artifactId>library</artifactId><version>1.0.0</version></project>";
fn jar() -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive
        .start_file("library.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive
        .write_all(b"same original bytes in dev and production")
        .unwrap();
    archive.finish().unwrap().into_inner()
}
fn tokens() -> BTreeMap<String, String> {
    [
        "writer",
        "source-promoter",
        "source-reader",
        "copier",
        "other-copier",
        "target-writer",
        "target-promoter",
        "reader",
    ]
    .into_iter()
    .map(|id| (id.into(), format!("{id}-{}", "x".repeat(40))))
    .collect()
}
struct Fixture {
    app: Router,
    config: Arc<Config>,
    store: Store,
    blobs: BlobStore,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new(pool: sqlx::PgPool, review: Outcome) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
        let mut repository = config.repositories["maven"].clone();
        repository.kind = RepositoryKind::Hosted;
        repository.upstream = None;
        repository.download_origins.clear();
        repository.token_env = None;
        repository.retain = true;
        repository.cache_max_age_seconds = None;
        repository.cargo_download_template = None;
        config.repositories.clear();
        config.repositories.insert("dev".into(), repository.clone());
        repository.policy = Some(PolicyRequirements {
            revision: "production-reviewed-v1".into(),
            required: vec!["release_review".into()],
            deny_on_failure: vec!["release_review".into()],
            agent_escalation: None,
        });
        config.repositories.insert("prod".into(), repository);
        config.storage = StorageConfig::Fs {
            root: directory.path().to_string_lossy().into(),
        };
        config.access.legacy_read_enabled = false;
        config.access.maven_owners = vec![MavenOwnership {
            namespace: "dev.private".into(),
            repository: "dev".into(),
            additional_repositories: vec!["prod".into()],
        }];
        let grant = |repo: &str, action| Grant {
            repository: repo.into(),
            actions: vec![action],
            namespace: Some("dev.private".into()),
        };
        for (id, grants) in [
            ("writer", vec![grant("dev", Action::Write)]),
            ("source-promoter", vec![grant("dev", Action::Promote)]),
            ("source-reader", vec![grant("dev", Action::Read)]),
            (
                "copier",
                vec![grant("dev", Action::Read), grant("prod", Action::Write)],
            ),
            (
                "other-copier",
                vec![grant("dev", Action::Read), grant("prod", Action::Write)],
            ),
            ("target-writer", vec![grant("prod", Action::Write)]),
            ("target-promoter", vec![grant("prod", Action::Promote)]),
            ("reader", vec![grant("prod", Action::Read)]),
        ] {
            config.access.principals.insert(
                id.into(),
                ServicePrincipal {
                    token_env: format!("PACKWEIR_COPY_{}", id.replace('-', "_").to_uppercase()),
                    expires_at: None,
                    grants,
                },
            );
        }
        let report =
            serde_json::to_vec(&json!({"outcome":review,"details":{"source_note":SOURCE_NOTE}}))
                .unwrap();
        let report_path = directory.path().join("review.json");
        std::fs::write(&report_path, &report).unwrap();
        let binary = support::fixture_program();
        config.scanners.insert(
            "release_review".into(),
            CommandScanner {
                program: binary.to_string_lossy().into(),
                program_sha256: Some(sha256(&std::fs::read(binary).unwrap())),
                args: vec!["scope-report".into()],
                version: "explicit-test-fixture".into(),
                timeout_seconds: 10,
                environment: BTreeMap::new(),
                driver: ScannerDriver::Command,
                resources: BTreeMap::from([(
                    "report".into(),
                    PinnedResource {
                        path: report_path.to_string_lossy().into(),
                        sha256: sha256(&report),
                    },
                )]),
            },
        );
        config.validate().unwrap();
        let access =
            AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &tokens())
                .unwrap();
        let config = Arc::new(config);
        let store = Store { pool };
        let blobs = BlobStore::new(&config.storage).unwrap();
        let app = gateway::router(AppState::with_access(
            config.clone(),
            store.clone(),
            blobs.clone(),
            "a".repeat(32),
            "r".repeat(32),
            access,
        ));
        Self {
            app,
            config,
            store,
            blobs,
            _directory: directory,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        who: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Value, Vec<u8>) {
        let token = match who {
            "admin" => "a".repeat(32),
            "legacy" => "r".repeat(32),
            _ => tokens().get(who).cloned().unwrap_or_default(),
        };
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
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
        )
    }
    async fn analyze(&self) -> usize {
        let mut count = 0;
        while let Some(job) = self
            .store
            .lease(&self.config.fingerprint(), 60)
            .await
            .unwrap()
        {
            scanner::analyze(&self.config, &self.store, &self.blobs, &job)
                .await
                .unwrap();
            count += 1;
        }
        count
    }
    async fn source(&self) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let (status, body, ..) = self
            .request(
                "POST",
                "/api/v1/repositories/dev/staging",
                "writer",
                serde_json::to_vec(&json!({"id":id,"name":NAME,"version":"1.0.0"})).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        for (extension, bytes) in [("pom", POM.to_vec()), ("jar", jar())] {
            assert_eq!(
                self.request(
                    "PUT",
                    &format!("/api/v1/staging/{id}/{BASE}.{extension}"),
                    "writer",
                    bytes
                )
                .await
                .0,
                StatusCode::CREATED
            );
        }
        let (status, body, ..) = self
            .request(
                "POST",
                &format!("/api/v1/staging/{id}/seal"),
                "writer",
                vec![],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let manifest = body["manifest_digest"].as_str().unwrap().to_string();
        assert_eq!(self.analyze().await, 2);
        assert_eq!(
            self.action(id, "promote", &manifest, "source-promoter")
                .await
                .0,
            StatusCode::OK
        );
        (id, manifest)
    }
    async fn action(
        &self,
        id: Uuid,
        action: &str,
        manifest: &str,
        who: &str,
    ) -> (StatusCode, Value, Vec<u8>) {
        self.request(
            "POST",
            &format!("/api/v1/staging/{id}/{action}"),
            who,
            serde_json::to_vec(&json!({"manifest_digest":manifest})).unwrap(),
        )
        .await
    }
    async fn copy(
        &self,
        source: Uuid,
        id: Uuid,
        manifest: &str,
        who: &str,
    ) -> (StatusCode, Value, Vec<u8>) {
        self.request(
            "POST",
            &format!("/api/v1/staging/{source}/copy"),
            who,
            serde_json::to_vec(
                &json!({"id":id,"destination_repository":"prod","source_manifest_digest":manifest}),
            )
            .unwrap(),
        )
        .await
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn copy_preserves_bytes_requires_fresh_destination_review_and_keeps_revocations_independent(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, Outcome::Pass);
    let (source, source_manifest) = fixture.source().await;
    let target = Uuid::new_v4();
    let (status, copy, raw) = fixture
        .copy(source, target, &source_manifest, "copier")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{copy}");
    assert_eq!(copy["destination"]["stage"]["state"], "sealed");
    assert_eq!(copy["source_stage"], source.to_string());
    assert!(!String::from_utf8(raw).unwrap().contains(SOURCE_NOTE));
    for item in copy["source_files"].as_array().unwrap() {
        assert!(item.get("evidence").is_none());
        assert!(item.get("policy").is_none());
        assert!(!item["evidence_ids"].as_array().unwrap().is_empty());
    }
    let persisted = hosted::lineage(&fixture.store, target)
        .await
        .unwrap()
        .unwrap();
    assert!(
        serde_json::to_string(&persisted)
            .unwrap()
            .contains(SOURCE_NOTE),
        "redaction must not discard the audit evidence"
    );
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/api/v1/staging/{target}/copy-evidence"),
                "copier",
                vec![]
            )
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, audit) = fixture
        .request(
            "GET",
            &format!("/api/v1/staging/{target}/copy-evidence"),
            "admin",
            vec![],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(audit).unwrap().contains(SOURCE_NOTE));
    let manifest = copy["destination"]["manifest_digest"].as_str().unwrap();
    assert_ne!(manifest, source_manifest);
    let source_files = hosted::stage_files(&fixture.store, source).await.unwrap();
    let files = hosted::stage_files(&fixture.store, target).await.unwrap();
    assert_eq!(files.len(), source_files.len());
    for (from, to) in source_files.iter().zip(&files) {
        assert_eq!(from.path, to.path);
        assert_eq!(from.artifact.digest, to.artifact.digest);
        let config = fixture
            .config
            .delivery_fingerprint(&to.artifact.scope())
            .unwrap();
        assert_ne!(
            config,
            fixture
                .config
                .delivery_fingerprint(&from.artifact.scope())
                .unwrap()
        );
        assert!(
            fixture
                .store
                .evidence(&to.artifact.digest, &config)
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        fixture
            .request("GET", &format!("/r/prod/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .action(target, "promote", manifest, "target-promoter")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.analyze().await, 2);
    assert_eq!(
        fixture
            .action(target, "promote", manifest, "target-promoter")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .request("GET", &format!("/r/prod/{BASE}.jar"), "reader", vec![])
            .await
            .2,
        jar()
    );
    assert_eq!(
        fixture
            .action(source, "revoke", &source_manifest, "source-promoter")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .request("GET", &format!("/r/prod/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::OK
    );
    let (status, replay, ..) = fixture
        .copy(source, target, &source_manifest, "copier")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(replay["destination"]["stage"]["state"], "published");
    assert_eq!(
        fixture
            .copy(source, Uuid::new_v4(), &source_manifest, "copier")
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (_, inspection, body) = fixture
        .request(
            "GET",
            &format!("/api/v1/staging/{target}"),
            "copier",
            vec![],
        )
        .await;
    assert_eq!(
        inspection["copy"]["source_manifest_digest"],
        source_manifest
    );
    assert!(
        inspection["copy"]["source_files"][0]
            .get("evidence")
            .is_none()
    );
    // Destination's own promotion is visible to its writers; the source portion stays redacted.
    assert!(
        !serde_json::to_string(&inspection["copy"])
            .unwrap()
            .contains(SOURCE_NOTE)
    );
    assert!(!body.is_empty());
    assert_eq!(
        fixture
            .action(target, "revoke", manifest, "target-promoter")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .copy(source, target, &source_manifest, "copier")
            .await
            .1["destination"]["stage"]["state"],
        "revoked"
    );
    assert_eq!(
        fixture
            .request("GET", &format!("/r/prod/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn source_read_and_destination_write_are_both_required_and_copy_retries_cannot_change_the_request(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, Outcome::Pass);
    let (source, manifest) = fixture.source().await;
    let target = Uuid::new_v4();
    for who in [
        "writer",
        "source-promoter",
        "source-reader",
        "target-writer",
        "target-promoter",
        "reader",
    ] {
        assert_eq!(
            fixture.copy(source, target, &manifest, who).await.0,
            StatusCode::FORBIDDEN,
            "{who}"
        );
    }
    assert_eq!(
        fixture.copy(source, target, &manifest, "admin").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture.copy(source, target, &manifest, "legacy").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .copy(source, target, &"0".repeat(64), "copier")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert!(
        hosted::lineage(&fixture.store, target)
            .await
            .unwrap()
            .is_none()
    );
    let (status, receipt, ..) = fixture.copy(source, target, &manifest, "copier").await;
    assert_eq!(status, StatusCode::CREATED, "{receipt}");
    assert_eq!(
        fixture
            .copy(source, target, &manifest, "other-copier")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .copy(source, target, &"0".repeat(64), "copier")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .copy(source, Uuid::new_v4(), &manifest, "copier")
            .await
            .0,
        StatusCode::CONFLICT
    );
    let copies: i64 = sqlx::query_scalar("SELECT count(*) FROM hosted_lineage")
        .fetch_one(&fixture.store.pool)
        .await
        .unwrap();
    assert_eq!(copies, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn source_optional_review_cannot_override_a_failed_required_destination_review(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, Outcome::Fail);
    let (source, manifest) = fixture.source().await;
    let target = Uuid::new_v4();
    let (status, receipt, ..) = fixture.copy(source, target, &manifest, "copier").await;
    assert_eq!(status, StatusCode::CREATED, "{receipt}");
    assert_eq!(fixture.analyze().await, 2);
    let target_manifest = receipt["destination"]["manifest_digest"].as_str().unwrap();
    assert_eq!(
        fixture
            .action(target, "promote", target_manifest, "target-promoter")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .request("GET", &format!("/r/prod/{BASE}.jar"), "reader", vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        hosted::stage(&fixture.store, target).await.unwrap().state,
        hosted::StageState::Sealed
    );
    let source_file = hosted::stage_files(&fixture.store, source)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        hosted::delivery(&fixture.store, "dev", &source_file.path, &fixture.config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Approved
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn source_invalidation_requeues_current_assessment_and_missing_bytes_do_not_create_a_destination(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, Outcome::Pass);
    let (source, manifest) = fixture.source().await;
    let target = Uuid::new_v4();
    let files = hosted::stage_files(&fixture.store, source).await.unwrap();
    fixture
        .store
        .invalidate(&files[0].artifact.digest)
        .await
        .unwrap();
    assert_eq!(
        fixture.copy(source, target, &manifest, "copier").await.0,
        StatusCode::CONFLICT
    );
    assert!(
        hosted::lineage(&fixture.store, target)
            .await
            .unwrap()
            .is_none()
    );
    assert!(fixture.analyze().await >= 1);
    let blob = fixture._directory.path().join(format!(
        "blobs/sha256/{}/{}",
        &files[0].artifact.digest[..2],
        files[0].artifact.digest
    ));
    let original = std::fs::read(&blob).unwrap();
    std::fs::write(&blob, b"tampered").unwrap();
    assert_eq!(
        fixture.copy(source, target, &manifest, "copier").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        hosted::lineage(&fixture.store, target)
            .await
            .unwrap()
            .is_none()
    );
    std::fs::write(blob, original).unwrap();
    assert_eq!(
        fixture.copy(source, target, &manifest, "copier").await.0,
        StatusCode::CREATED
    );
}
