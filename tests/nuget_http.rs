//! Native NuGet transport uses the same immutable, current-policy hosted lifecycle.
mod support;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use packweir::{
    access::{AccessControl, Action, Grant, NugetOwnership, ServicePrincipal},
    config::{
        CommandScanner, Config, PinnedResource, RepositoryKind, ScannerDriver, StorageConfig,
    },
    gateway::{self, AppState},
    hosted,
    model::{Outcome, sha256},
    nuget,
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

const NAME: &str = "Packweir.Private.Library";
const ID: &str = "packweir.private.library";
const PACKAGE: &str =
    "flatcontainer/packweir.private.library/1.0.0/packweir.private.library.1.0.0.nupkg";
const NUSPEC: &str = "flatcontainer/packweir.private.library/1.0.0/packweir.private.library.nuspec";
const BOUNDARY: &str = "packweir-native-nuget-boundary";

fn nuspec(name: &str, version: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\"><metadata><id>{name}</id><version>{version}</version><authors>Fixture</authors><description>Original NuGet HTTP fixture</description><dependencies><group targetFramework=\"net10.0\"/></dependencies></metadata></package>").into_bytes()
}
fn package(name: &str, version: &str) -> Vec<u8> {
    package_with_payload(name, version, b"original library payload")
}
fn package_with_payload(name: &str, version: &str, payload: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in [
        (format!("{name}.nuspec"), nuspec(name, version)),
        ("lib/net10.0/fixture.txt".into(), payload.to_vec()),
        (
            ".signature.p7s".into(),
            b"opaque signature-shaped original content".to_vec(),
        ),
    ] {
        archive
            .start_file(
                path,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        archive.write_all(&bytes).unwrap();
    }
    archive.finish().unwrap().into_inner()
}
fn multipart(fields: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, bytes) in fields {
        body.extend_from_slice(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}
fn token(who: &str) -> String {
    match who {
        "admin" => "a".repeat(32),
        "legacy" => "r".repeat(32),
        _ => format!("{who}-{}", "x".repeat(40)),
    }
}
fn secrets() -> BTreeMap<String, String> {
    [
        "writer",
        "second-writer",
        "source-promoter",
        "source-reader",
        "copier",
        "target-promoter",
        "target-reader",
        "outsider",
        "outside-writer",
    ]
    .into_iter()
    .map(|who| (who.into(), token(who)))
    .collect()
}
type Reply = (StatusCode, Value, Vec<u8>, HeaderMap);
struct Fixture {
    app: Router,
    config: Arc<Config>,
    store: Store,
    blobs: BlobStore,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new(pool: sqlx::PgPool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
        let mut repo = config.repositories["nuget"].clone();
        repo.kind = RepositoryKind::Hosted;
        repo.upstream = None;
        repo.download_origins.clear();
        repo.token_env = None;
        repo.cache_max_age_seconds = None;
        repo.cargo_download_template = None;
        repo.retain = true;
        config.repositories.clear();
        config.repositories.insert("dev".into(), repo.clone());
        repo.policy = Some(PolicyRequirements {
            revision: "nuget-production-review-v1".into(),
            required: vec!["release_review".into()],
            deny_on_failure: vec!["release_review".into()],
        });
        config.repositories.insert("prod".into(), repo);
        config.storage = StorageConfig::Fs {
            root: directory.path().to_string_lossy().into(),
        };
        config.max_download_bytes = 64 * 1024;
        config.access.legacy_read_enabled = false;
        config.access.nuget_owners = vec![NugetOwnership {
            prefix: "packweir.private".into(),
            repository: "dev".into(),
            additional_repositories: vec!["prod".into()],
        }];
        let grant = |repository: &str, action| Grant {
            repository: repository.into(),
            actions: vec![action],
            namespace: Some("packweir.private".into()),
        };
        for (who, mut grants) in [
            ("writer", vec![grant("dev", Action::Write)]),
            ("second-writer", vec![grant("dev", Action::Write)]),
            ("source-promoter", vec![grant("dev", Action::Promote)]),
            ("source-reader", vec![grant("dev", Action::Read)]),
            (
                "copier",
                vec![grant("dev", Action::Read), grant("prod", Action::Write)],
            ),
            ("target-promoter", vec![grant("prod", Action::Promote)]),
            ("target-reader", vec![grant("prod", Action::Read)]),
            ("outsider", vec![grant("dev", Action::Read)]),
            ("outside-writer", vec![grant("dev", Action::Write)]),
        ] {
            if matches!(who, "outsider" | "outside-writer") {
                grants[0].namespace = Some("packweir.other".into());
            }
            config.access.principals.insert(
                who.into(),
                ServicePrincipal {
                    token_env: format!(
                        "PACKWEIR_NUGET_HTTP_{}",
                        who.replace('-', "_").to_uppercase()
                    ),
                    expires_at: None,
                    grants,
                },
            );
        }
        let report = serde_json::to_vec(&json!({"outcome":Outcome::Pass,"details":{"production_review":"fresh destination assessment"}})).unwrap();
        let report_path = directory.path().join("review.json");
        std::fs::write(&report_path, &report).unwrap();
        let binary = support::fixture_program();
        config.scanners.insert(
            "release_review".into(),
            CommandScanner {
                program: binary.to_string_lossy().into(),
                program_sha256: Some(sha256(&std::fs::read(binary).unwrap())),
                args: vec!["scope-report".into()],
                version: "nuget-http-review-fixture".into(),
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
        let config = Arc::new(config);
        let store = Store { pool };
        let blobs = BlobStore::new(&config.storage).unwrap();
        let app = Self::router(config.clone(), store.clone(), blobs.clone());
        Self {
            app,
            config,
            store,
            blobs,
            _directory: directory,
        }
    }
    fn router(config: Arc<Config>, store: Store, blobs: BlobStore) -> Router {
        let access =
            AccessControl::from_tokens(&config, &token("admin"), &token("legacy"), &secrets())
                .unwrap();
        gateway::router(AppState::with_access(
            config,
            store,
            blobs,
            token("admin"),
            token("legacy"),
            access,
        ))
    }
    fn reconfigure(&mut self, config: Config) {
        config.validate().unwrap();
        self.config = Arc::new(config);
        self.app = Self::router(self.config.clone(), self.store.clone(), self.blobs.clone());
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, value);
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
    async fn request(&self, method: &str, path: &str, who: &str, body: Vec<u8>) -> Reply {
        let mut headers = vec![("content-type", "application/json".into())];
        if who != "none" {
            headers.push(("authorization", format!("Bearer {}", token(who))));
        }
        self.send(method, path, &headers, body).await
    }
    async fn create(&self, id: Uuid, name: &str, version: &str, who: &str) -> Reply {
        self.request(
            "POST",
            "/api/v1/repositories/dev/staging",
            who,
            serde_json::to_vec(&json!({"id":id,"name":name,"version":version})).unwrap(),
        )
        .await
    }
    async fn push_fields(&self, id: Uuid, who: &str, fields: &[(&str, &str, &[u8])]) -> Reply {
        let mut headers = vec![(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )];
        if who != "none" {
            headers.push(("x-nuget-apikey", token(who)));
        }
        self.send(
            "PUT",
            &format!("/api/v1/staging/{id}/nuget/push"),
            &headers,
            multipart(fields),
        )
        .await
    }
    async fn push(&self, id: Uuid, who: &str, bytes: &[u8]) -> Reply {
        self.push_fields(
            id,
            who,
            &[("untrusted-field", "../../different-file.zip", bytes)],
        )
        .await
    }
    async fn action(&self, id: Uuid, action: &str, manifest: &str, who: &str) -> Reply {
        self.request(
            "POST",
            &format!("/api/v1/staging/{id}/{action}"),
            who,
            serde_json::to_vec(&json!({"manifest_digest":manifest})).unwrap(),
        )
        .await
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
    async fn sealed(&self) -> (Uuid, String, Vec<u8>) {
        let id = Uuid::new_v4();
        let bytes = package(NAME, "01.0.0.0+original.build");
        let created = self.create(id, NAME, "1", "writer").await;
        assert_eq!(created.0, StatusCode::CREATED, "{}", created.1);
        let pushed = self.push(id, "writer", &bytes).await;
        assert_eq!(pushed.0, StatusCode::CREATED, "{}", pushed.1);
        let sealed = self
            .request(
                "POST",
                &format!("/api/v1/staging/{id}/seal"),
                "writer",
                vec![],
            )
            .await;
        assert_eq!(sealed.0, StatusCode::OK, "{}", sealed.1);
        (
            id,
            sealed.1["manifest_digest"].as_str().unwrap().into(),
            bytes,
        )
    }
    async fn copy(&self, source: Uuid, id: Uuid, manifest: &str, who: &str) -> Reply {
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
async fn nuget_native_discovery_upload_authentication_and_coordinates_are_stage_bound(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool);
    let id = Uuid::new_v4();
    for discovered in [id, Uuid::new_v4()] {
        let (status, body, bytes, headers) = fixture
            .request(
                "GET",
                &format!("/api/v1/staging/{discovered}/nuget/index.json"),
                "none",
                vec![],
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(body["resources"].as_array().unwrap().len(), 1);
        assert_eq!(body["resources"][0]["@type"], "PackagePublish/2.0.0");
        assert!(
            body["resources"][0]["@id"]
                .as_str()
                .unwrap()
                .ends_with(&format!("/api/v1/staging/{discovered}/nuget/push"))
        );
        assert!(!String::from_utf8(bytes).unwrap().contains(ID));
    }
    assert_eq!(
        fixture
            .create(id, NAME, "01.0.0.0+build.1", "writer")
            .await
            .0,
        StatusCode::CREATED
    );
    for version in ["1", "1.0", "1.0.0", "1.0.0.0", "0001.0000.0000+other"] {
        let same = fixture
            .create(id, &NAME.to_uppercase(), version, "writer")
            .await;
        assert_eq!(same.0, StatusCode::CREATED);
        assert_eq!(same.1["stage"]["package"]["version"], "1.0.0");
        assert!(same.1["stage"]["package"]["namespace"].is_null());
        assert_eq!(
            fixture
                .create(Uuid::new_v4(), NAME, version, "writer")
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        fixture
            .create(
                Uuid::new_v4(),
                "Packweir.Privateevil.Library",
                "1",
                "writer"
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    for who in ["none", "admin", "legacy"] {
        assert_eq!(
            fixture.push(id, who, &package(NAME, "1")).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for who in [
        "source-reader",
        "source-promoter",
        "second-writer",
        "outside-writer",
    ] {
        assert_eq!(
            fixture.push(id, who, &package(NAME, "1")).await.0,
            StatusCode::FORBIDDEN,
            "{who}"
        );
    }
    let push_path = format!("/api/v1/staging/{id}/nuget/push");
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let bytes = package(NAME, "1");
    for auth in [
        vec![
            ("x-nuget-apikey", token("writer")),
            ("authorization", format!("Bearer {}", token("writer"))),
        ],
        vec![
            ("x-nuget-apikey", token("writer")),
            ("x-nuget-apikey", token("writer")),
        ],
    ] {
        let mut headers = vec![("content-type", content_type.clone())];
        headers.extend(auth);
        assert_eq!(
            fixture
                .send(
                    "PUT",
                    &push_path,
                    &headers,
                    multipart(&[("file", "a.nupkg", &bytes)])
                )
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        fixture
            .request("GET", "/api/v1/capabilities", "admin", vec![])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .send(
                "GET",
                "/api/v1/capabilities",
                &[
                    ("authorization", format!("Bearer {}", token("admin"))),
                    ("x-nuget-apikey", token("writer"))
                ],
                vec![]
            )
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .send(
                "PUT",
                &format!("{push_path}?override=other"),
                &[
                    ("content-type", content_type.clone()),
                    ("x-nuget-apikey", token("writer"))
                ],
                multipart(&[("file", "a.nupkg", &bytes)])
            )
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture.push(id, "writer", b"not a ZIP").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture
            .push(id, "writer", &package("Packweir.Private.Other", "1"))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture.push(id, "writer", &package(NAME, "2")).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture
            .push_fields(
                id,
                "writer",
                &[
                    ("first", "bad.nupkg", b"not a ZIP"),
                    ("second", "valid.nupkg", &bytes)
                ]
            )
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        hosted::stage_files(&fixture.store, id)
            .await
            .unwrap()
            .is_empty()
    );
    let pushed = fixture
        .push_fields(
            id,
            "writer",
            &[
                ("first", "../../not-the-id.zip", &bytes),
                ("ignored", "invalid.nupkg", b"ignored later field"),
            ],
        )
        .await;
    assert_eq!(pushed.0, StatusCode::CREATED, "{}", pushed.1);
    assert_eq!(pushed.1["path"], PACKAGE);
    let files = hosted::stage_files(&fixture.store, id).await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(
        fixture.blobs.read(&files[0].artifact.digest).await.unwrap(),
        bytes
    );
    assert_eq!(
        fixture.push(id, "writer", &bytes).await.0,
        StatusCode::CREATED
    );
    // Native NuGet clients append a slash to the advertised PackagePublish URL.
    for (who, expected) in [
        ("writer", StatusCode::CREATED),
        ("source-reader", StatusCode::FORBIDDEN),
        ("second-writer", StatusCode::FORBIDDEN),
        ("unconfigured", StatusCode::UNAUTHORIZED),
        ("none", StatusCode::UNAUTHORIZED),
    ] {
        let mut headers = vec![("content-type", content_type.clone())];
        if who != "none" {
            headers.push(("x-nuget-apikey", token(who)));
        }
        let response = fixture
            .send(
                "PUT",
                &format!("{push_path}/"),
                &headers,
                multipart(&[("file", "ignored-name.nupkg", &bytes)]),
            )
            .await;
        assert_eq!(response.0, expected, "slash push as {who}: {}", response.1);
    }
    let changed = package(NAME, "1.0+different-original-nuspec");
    assert_eq!(
        fixture.push(id, "writer", &changed).await.0,
        StatusCode::CONFLICT
    );
    for path in [format!("/api/v1/staging/{id}"), "/r/dev/index.json".into()] {
        assert_eq!(
            fixture
                .send("GET", &path, &[("x-nuget-apikey", token("writer"))], vec![])
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn nuget_native_reads_hide_staging_and_recheck_current_archive_policy(pool: sqlx::PgPool) {
    let mut fixture = Fixture::new(pool);
    let (id, manifest, original) = fixture.sealed().await;
    for suffix in [
        format!("flatcontainer/{ID}/index.json"),
        PACKAGE.into(),
        NUSPEC.into(),
        format!("{PACKAGE}.sha512"),
    ] {
        for method in ["GET", "HEAD"] {
            let response = fixture
                .request(method, &format!("/r/dev/{suffix}"), "source-reader", vec![])
                .await;
            assert_eq!(
                response.0,
                StatusCode::NOT_FOUND,
                "{method} {suffix}: {}",
                response.1
            );
            assert!(!response.3.contains_key("x-packweir-sha256"));
            if method == "HEAD" {
                assert!(response.2.is_empty());
            }
        }
    }
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/api/v1/staging/{id}/{PACKAGE}"),
                "writer",
                vec![]
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture.action(id, "promote", &manifest, "writer").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .action(id, "promote", &manifest, "source-promoter")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.analyze().await, 1);
    assert_eq!(
        fixture
            .action(id, "promote", &"0".repeat(64), "source-promoter")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .action(id, "promote", &manifest, "source-promoter")
            .await
            .0,
        StatusCode::OK
    );
    let index = fixture
        .request("GET", "/r/dev/index.json", "source-reader", vec![])
        .await;
    assert_eq!(index.0, StatusCode::OK);
    assert_eq!(index.1["resources"][0]["@type"], "PackageBaseAddress/3.0.0");
    assert!(
        !String::from_utf8(index.2)
            .unwrap()
            .contains("PackagePublish")
    );
    let versions = fixture
        .request(
            "GET",
            &format!("/r/dev/flatcontainer/{ID}/index.json"),
            "source-reader",
            vec![],
        )
        .await;
    assert_eq!(versions.0, StatusCode::OK);
    assert_eq!(versions.1["versions"], json!(["1.0.0"]));
    for (suffix, expected) in [
        (PACKAGE.into(), original.clone()),
        (NUSPEC.into(), nuspec(NAME, "01.0.0.0+original.build")),
        (
            format!("{PACKAGE}.sha512"),
            nuget::checksum(&original).into_bytes(),
        ),
    ] {
        let response = fixture
            .request("GET", &format!("/r/dev/{suffix}"), "source-reader", vec![])
            .await;
        assert_eq!(response.0, StatusCode::OK, "{suffix}: {}", response.1);
        assert_eq!(response.2, expected);
        let head = fixture
            .request("HEAD", &format!("/r/dev/{suffix}"), "source-reader", vec![])
            .await;
        assert_eq!(head.0, StatusCode::OK);
        assert!(head.2.is_empty());
        assert_eq!(
            fixture
                .request("GET", &format!("/r/dev/{suffix}"), "outsider", vec![])
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let artifact = hosted::stage_files(&fixture.store, id)
        .await
        .unwrap()
        .remove(0)
        .artifact;
    fixture.store.invalidate(&artifact.digest).await.unwrap();
    for suffix in [
        PACKAGE.to_owned(),
        NUSPEC.to_owned(),
        format!("{PACKAGE}.sha512"),
    ] {
        assert_eq!(
            fixture
                .request("GET", &format!("/r/dev/{suffix}"), "source-reader", vec![])
                .await
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/r/dev/flatcontainer/{ID}/index.json"),
                "source-reader",
                vec![]
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(fixture.analyze().await, 1);
    assert_eq!(
        fixture
            .request("GET", &format!("/r/dev/{PACKAGE}"), "source-reader", vec![])
            .await
            .2,
        original
    );
    let mut changed = (*fixture.config).clone();
    changed.policy.revision = "fresh-policy-revision".into();
    fixture.reconfigure(changed);
    assert_eq!(
        fixture
            .request("GET", &format!("/r/dev/{NUSPEC}"), "source-reader", vec![])
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.analyze().await, 1);
    assert_eq!(
        fixture
            .request("GET", &format!("/r/dev/{PACKAGE}"), "source-reader", vec![])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .action(id, "revoke", &manifest, "source-promoter")
            .await
            .0,
        StatusCode::OK
    );
    for suffix in [
        PACKAGE.to_owned(),
        NUSPEC.to_owned(),
        format!("{PACKAGE}.sha512"),
        format!("flatcontainer/{ID}/index.json"),
    ] {
        assert_eq!(
            fixture
                .request("GET", &format!("/r/dev/{suffix}"), "source-reader", vec![])
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        fixture
            .create(Uuid::new_v4(), NAME, "1.0.0.0+replacement", "writer")
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nuget_http_copy_adds_destination_quarantine_and_keeps_revocations_independent(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool);
    let (source, manifest, original) = fixture.sealed().await;
    assert_eq!(fixture.analyze().await, 1);
    assert_eq!(
        fixture
            .action(source, "promote", &manifest, "source-promoter")
            .await
            .0,
        StatusCode::OK
    );
    let destination = Uuid::new_v4();
    for who in [
        "writer",
        "source-promoter",
        "target-promoter",
        "source-reader",
    ] {
        assert_eq!(
            fixture.copy(source, destination, &manifest, who).await.0,
            StatusCode::FORBIDDEN,
            "{who}"
        );
    }
    let evidence_before: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence")
        .fetch_one(&fixture.store.pool)
        .await
        .unwrap();
    let copied = fixture.copy(source, destination, &manifest, "copier").await;
    assert_eq!(copied.0, StatusCode::CREATED, "{}", copied.1);
    assert_eq!(copied.1["destination"]["stage"]["state"], "sealed");
    let target_manifest = copied.1["destination"]["manifest_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let files = hosted::stage_files(&fixture.store, destination)
        .await
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].artifact.digest, sha256(&original));
    assert!(
        files[0]
            .artifact
            .origin
            .ends_with(&format!("/r/prod/{PACKAGE}"))
    );
    assert!(
        fixture
            .store
            .evidence(
                &files[0].artifact.digest,
                &fixture
                    .config
                    .delivery_fingerprint(&files[0].artifact.scope())
                    .unwrap()
            )
            .await
            .unwrap()
            .is_empty()
    );
    let evidence_after: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence")
        .fetch_one(&fixture.store.pool)
        .await
        .unwrap();
    assert_eq!(evidence_before, evidence_after);
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/r/prod/{PACKAGE}"),
                "target-reader",
                vec![]
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .action(destination, "promote", &target_manifest, "copier")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .action(destination, "promote", &target_manifest, "target-promoter")
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.analyze().await, 1);
    let promoted = fixture
        .action(destination, "promote", &target_manifest, "target-promoter")
        .await;
    assert_eq!(promoted.0, StatusCode::OK, "{}", promoted.1);
    assert!(
        promoted.1["files"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["document"]["check"] == "release_review")
    );
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/r/prod/{PACKAGE}"),
                "target-reader",
                vec![]
            )
            .await
            .2,
        original
    );
    assert_eq!(
        fixture
            .action(source, "revoke", &manifest, "source-promoter")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .request("GET", &format!("/r/dev/{PACKAGE}"), "source-reader", vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/r/prod/{PACKAGE}"),
                "target-reader",
                vec![]
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .action(destination, "revoke", &target_manifest, "target-promoter")
            .await
            .0,
        StatusCode::OK
    );
    let replay = fixture.copy(source, destination, &manifest, "copier").await;
    assert_eq!(replay.0, StatusCode::CREATED);
    assert_eq!(replay.1["destination"]["stage"]["state"], "revoked");
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/r/prod/{PACKAGE}"),
                "target-reader",
                vec![]
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nuget_multipart_uses_configured_package_and_whole_request_budgets(pool: sqlx::PgPool) {
    let mut fixture = Fixture::new(pool);
    let mut config = (*fixture.config).clone();
    config.max_download_bytes = 4 * 1024 * 1024;
    fixture.reconfigure(config);
    let large = package_with_payload(NAME, "1", &vec![0x41; 2 * 1024 * 1024 + 64 * 1024]);
    assert!(
        large.len() > 2 * 1024 * 1024,
        "qualify the override of Axum's default 2 MiB multipart limit"
    );
    let id = Uuid::new_v4();
    assert_eq!(
        fixture.create(id, NAME, "1", "writer").await.0,
        StatusCode::CREATED
    );
    let accepted = fixture.push(id, "writer", &large).await;
    assert_eq!(accepted.0, StatusCode::CREATED, "{}", accepted.1);
    let mut config = (*fixture.config).clone();
    config.max_download_bytes = large.len() - 1;
    fixture.reconfigure(config);
    let limited = Uuid::new_v4();
    let limited_name = "Packweir.Private.Limited";
    assert_eq!(
        fixture.create(limited, limited_name, "1", "writer").await.0,
        StatusCode::CREATED
    );
    let too_large = package_with_payload(limited_name, "1", &vec![0x42; large.len()]);
    assert_eq!(
        fixture.push(limited, "writer", &too_large).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(
        hosted::stage_files(&fixture.store, limited)
            .await
            .unwrap()
            .is_empty()
    );
    let aggregate = Uuid::new_v4();
    let aggregate_name = "Packweir.Private.Aggregate";
    assert_eq!(
        fixture
            .create(aggregate, aggregate_name, "1", "writer")
            .await
            .0,
        StatusCode::CREATED
    );
    let valid = package(aggregate_name, "1");
    let ignored = vec![0x43; fixture.config.max_download_bytes + 64 * 1024];
    let response = fixture
        .push_fields(
            aggregate,
            "writer",
            &[
                ("first", "valid.nupkg", &valid),
                ("ignored", "padding.bin", &ignored),
            ],
        )
        .await;
    assert_eq!(
        response.0,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the entire multipart body is bounded, including ignored later fields"
    );
    assert!(
        hosted::stage_files(&fixture.store, aggregate)
            .await
            .unwrap()
            .is_empty()
    );
}
