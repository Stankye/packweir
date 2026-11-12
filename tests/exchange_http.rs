//! OCI evidence imports archive hostile source claims without changing local gates.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    access::{AccessControl, Action, Grant, ServicePrincipal},
    config::{Config, RepositoryKind, StorageConfig},
    exchange,
    gateway::{self, AppState},
    model::{Artifact, Evidence, Outcome, sha256},
    oci::{self, Transfer},
    storage::BlobStore,
    store::Store,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

struct Fixture {
    app: Router,
    state: AppState,
    artifact: Artifact,
    directory: tempfile::TempDir,
}

impl Fixture {
    async fn new(pool: sqlx::PgPool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        config.repositories.retain(|name, _| name == "maven");
        let repository = config.repositories.get_mut("maven").unwrap();
        repository.kind = RepositoryKind::Hosted;
        repository.upstream = None;
        repository.download_origins.clear();
        repository.token_env = None;
        repository.cargo_download_template = None;
        repository.cache_max_age_seconds = None;
        config.storage = StorageConfig::Fs {
            root: directory.path().to_string_lossy().into(),
        };
        let mut tokens = BTreeMap::new();
        for (id, action) in [
            ("reader", Action::Read),
            ("writer", Action::Write),
            ("promoter", Action::Promote),
        ] {
            config.access.principals.insert(
                id.into(),
                ServicePrincipal {
                    token_env: format!("TEST_{id}"),
                    expires_at: None,
                    grants: vec![Grant {
                        repository: "maven".into(),
                        actions: vec![action],
                        namespace: None,
                    }],
                },
            );
            tokens.insert(id.into(), id.repeat(12));
        }
        let access =
            AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &tokens).unwrap();
        let blobs = BlobStore::new(&config.storage).unwrap();
        let store = Store { pool };
        let artifact = Artifact {
            repository: "maven".into(),
            origin: "https://source.test/library.jar".into(),
            digest: sha256(b"original package bytes must not appear in an evidence layout"),
            size: 61,
            filename: "library.jar".into(),
            content_type: "application/java-archive".into(),
            package: None,
        };
        store.register(&artifact).await.unwrap();
        let configuration = config.delivery_fingerprint(&artifact.scope()).unwrap();
        store
            .enqueue_delivery(&artifact, &configuration, &config.fingerprint())
            .await
            .unwrap();
        let state = AppState::with_access(
            Arc::new(config),
            store,
            blobs,
            "a".repeat(32),
            "r".repeat(32),
            access,
        );
        let app = gateway::router(state.clone());
        Self {
            app,
            state,
            artifact,
            directory,
        }
    }
    fn endpoint(&self, suffix: &str) -> String {
        format!("/api/v1/artifacts/{}/{suffix}", self.artifact.digest)
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        who: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if who != "none" {
            let token = match who {
                "admin" => "a".repeat(32),
                "legacy" => "r".repeat(32),
                other => other.repeat(12),
            };
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn local_state(&self) -> Value {
        sqlx::query_scalar("SELECT jsonb_build_object(\
            'contexts',(SELECT jsonb_agg(to_jsonb(t) ORDER BY subject) FROM contexts t),\
            'evidence',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM evidence t),\
            'decisions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM decisions t),\
            'documents',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM documents t),\
            'jobs',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM jobs t),\
            'claims',(SELECT jsonb_agg(to_jsonb(t) ORDER BY repository,origin,coordinate) FROM package_claims t),\
            'artifacts',(SELECT jsonb_agg(to_jsonb(t) ORDER BY repository,origin) FROM artifacts t))")
            .fetch_one(&self.state.store.pool).await.unwrap()
    }
    async fn import_bundle(&self, bundle: &oci::ValidatedBundle) -> (StatusCode, Value) {
        self.request(
            "POST",
            &self.endpoint("evidence-import"),
            "admin",
            serde_json::to_vec(&bundle.transfer()).unwrap(),
        )
        .await
    }
}

fn forged(fixture: &Fixture, sequence: u8) -> oci::ValidatedBundle {
    oci::build_bundle(&fixture.artifact.digest,json!({
        "public_url":fixture.state.config.public_url,"context_revision":0,
        "engine_configuration":fixture.state.config.fingerprint(),"sequence":sequence,
        "verified":true,"trust_status":"trusted"
    }),json!({"decision":{"state":"approved"},"evidence":[{"outcome":"pass","check":"archive_safety"}],
        "documents":[{"kind":"sbom","origin":"artifact_observed","claimed_local_origin":true}]}),
        vec![b"{\n  \"foreign\": true, \"claimed_origin\": \"artifact_observed\"\n}\n".to_vec()]).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn every_exchange_operation_requires_admin_credentials(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool).await;
    let id = Uuid::new_v4();
    for who in ["none", "legacy", "reader", "writer", "promoter"] {
        for (method, suffix) in [
            ("GET", "evidence-export".to_string()),
            ("POST", "evidence-import".into()),
            ("GET", "evidence-imports".into()),
            ("GET", format!("evidence-imports/{id}")),
            ("GET", format!("evidence-imports/{id}/export")),
        ] {
            assert_eq!(
                fixture
                    .request(method, &fixture.endpoint(&suffix), who, vec![])
                    .await
                    .0,
                StatusCode::UNAUTHORIZED,
                "{who}: {suffix}"
            );
        }
    }
    let request = Request::builder()
        .uri(fixture.endpoint("evidence-export"))
        .header(header::AUTHORIZATION, format!("Bearer {}", "a".repeat(32)))
        .header("x-nuget-apikey", "a".repeat(32))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        fixture.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn forged_pass_approval_and_current_source_context_never_change_local_policy_state(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    for denied in [false, true] {
        if denied {
            let now = Utc::now();
            let evidence = Evidence {
                subject: fixture.artifact.digest.clone(),
                check: "archive_safety".into(),
                configuration: fixture
                    .state
                    .config
                    .delivery_fingerprint(&fixture.artifact.scope())
                    .unwrap(),
                tool_version: "local fixture".into(),
                outcome: Outcome::Fail,
                created_at: now,
                expires_at: now + Duration::hours(1),
                details: json!({"local":"failure"}),
                references: vec![],
            };
            sqlx::query("INSERT INTO evidence(id,subject,check_name,configuration,created_at,expires_at,document,context_revision) VALUES($1,$2,$3,$4,$5,$6,$7,0)")
                .bind(Uuid::new_v4()).bind(&evidence.subject).bind(&evidence.check).bind(&evidence.configuration)
                .bind(evidence.created_at).bind(evidence.expires_at).bind(serde_json::to_value(&evidence).unwrap())
                .execute(&fixture.state.store.pool).await.unwrap();
        }
        let path = format!("/api/v1/artifacts/{}", fixture.artifact.digest);
        let before = fixture.request("GET", &path, "admin", vec![]).await.1;
        assert_eq!(
            before["decision"]["state"],
            if denied { "denied" } else { "pending" }
        );
        let local = fixture.local_state().await;
        let (status, receipt) = fixture.import_bundle(&forged(&fixture, denied as u8)).await;
        assert_eq!(status, StatusCode::CREATED, "{receipt}");
        assert_eq!(receipt["verified"], false);
        assert_eq!(receipt["trust_status"], "unverified");
        assert_eq!(receipt["approval_effect"], "none");
        assert_eq!(receipt["source_context_status"], "historical_foreign_claim");
        assert_eq!(
            fixture.local_state().await,
            local,
            "import may alter only its separate archive and audit"
        );
        let after = fixture.request("GET", &path, "admin", vec![]).await.1;
        assert_eq!(before["decision"], after["decision"]);
        assert_eq!(before["documents"], after["documents"]);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn import_is_deduplicated_and_exactly_readable_with_corruption_fail_closed(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let bundle = forged(&fixture, 0);
    let expected = serde_json::to_value(bundle.transfer()).unwrap();
    let (status, first) = fixture.import_bundle(&bundle).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, second) = fixture.import_bundle(&bundle).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, second);
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='external_evidence_imported'")
            .fetch_one(&fixture.state.store.pool)
            .await
            .unwrap();
    assert_eq!(events, 1);
    let id = first["id"].as_str().unwrap();
    fixture
        .state
        .blobs
        .read_bounded(
            bundle.envelope().documents[0]
                .digest
                .strip_prefix("sha256:")
                .unwrap(),
            8 * 1024 * 1024,
        )
        .await
        .unwrap();
    let (status, receipt) = fixture
        .request(
            "GET",
            &fixture.endpoint(&format!("evidence-imports/{id}")),
            "admin",
            vec![],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt, first);
    let (status, list) = fixture
        .request(
            "GET",
            &fixture.endpoint("evidence-imports"),
            "admin",
            vec![],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["imports"].as_array().unwrap().len(), 1);
    let readback = fixture.endpoint(&format!("evidence-imports/{id}/export"));
    assert_eq!(
        fixture.request("GET", &readback, "admin", vec![]).await,
        (StatusCode::OK, expected)
    );
    let document_digest = bundle.envelope().documents[0]
        .digest
        .strip_prefix("sha256:")
        .unwrap();
    let blob_path = fixture
        .directory
        .path()
        .join("blobs/sha256")
        .join(&document_digest[..2])
        .join(document_digest);
    std::fs::write(&blob_path, b"corrupt archive bytes").unwrap();
    assert_eq!(
        fixture.request("GET", &readback, "admin", vec![]).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::remove_file(blob_path).unwrap();
    assert_eq!(
        fixture.request("GET", &readback, "admin", vec![]).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_mutated_missing_or_wrong_subject_transfers_have_no_partial_import(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let bundle = forged(&fixture, 0);
    let baseline = fixture.local_state().await;
    let mut mutations = Vec::new();
    let mut transfer = bundle.transfer();
    transfer.manifest.0 = STANDARD.encode(b"{}");
    mutations.push(serde_json::to_vec(&transfer).unwrap());
    let mut transfer = bundle.transfer();
    transfer.blobs.pop_first();
    mutations.push(serde_json::to_vec(&transfer).unwrap());
    let mut transfer = bundle.transfer();
    transfer.blobs.values_mut().next().unwrap().0 = STANDARD.encode(b"mutated");
    mutations.push(serde_json::to_vec(&transfer).unwrap());
    let wrong = oci::build_bundle(&"f".repeat(64), json!({}), json!({}), vec![]).unwrap();
    mutations.push(serde_json::to_vec(&wrong.transfer()).unwrap());
    mutations.push(b"not JSON".to_vec());
    for mutation in mutations {
        assert_eq!(
            fixture
                .request(
                    "POST",
                    &fixture.endpoint("evidence-import"),
                    "admin",
                    mutation
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let unknown = format!("/api/v1/artifacts/{}/evidence-import", "e".repeat(64));
    assert_eq!(
        fixture
            .request(
                "POST",
                &unknown,
                "admin",
                serde_json::to_vec(&bundle.transfer()).unwrap()
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let imports: i64 = sqlx::query_scalar("SELECT count(*) FROM external_imports")
        .fetch_one(&fixture.state.store.pool)
        .await
        .unwrap();
    let refs: i64 = sqlx::query_scalar("SELECT count(*) FROM external_import_blobs")
        .fetch_one(&fixture.state.store.pool)
        .await
        .unwrap();
    assert_eq!((imports, refs), (0, 0));
    assert_eq!(fixture.local_state().await, baseline);
}

#[sqlx::test(migrations = "./migrations")]
async fn exported_snapshot_preserves_raw_documents_and_records_source_context_and_omissions(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let raw = b"{  \"z\": [1,2],\n \"a\": true }\n".to_vec();
    let digest = fixture.state.blobs.put(raw.clone()).await.unwrap();
    fixture
        .state
        .store
        .document(&fixture.artifact.digest, "sbom", "client_resolved", &digest)
        .await
        .unwrap();
    fixture
        .state
        .store
        .document(
            &fixture.artifact.digest,
            "attestation",
            "artifact_observed",
            &digest,
        )
        .await
        .unwrap();
    let mut removed = fixture.artifact.clone();
    removed.repository = "removed-source-repository".into();
    removed.origin = "https://retired.test/library.jar".into();
    fixture.state.store.register(&removed).await.unwrap();
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM contexts WHERE subject=$1")
        .bind(&fixture.artifact.digest)
        .fetch_one(&fixture.state.store.pool)
        .await
        .unwrap();
    exchange::snapshot_bundle(&fixture.state, &fixture.artifact.digest)
        .await
        .unwrap();
    let (status, value) = fixture
        .request("GET", &fixture.endpoint("evidence-export"), "admin", vec![])
        .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let transfer: Transfer = serde_json::from_value(value).unwrap();
    let bundle = oci::validate_transfer(transfer).unwrap();
    assert_eq!(bundle.envelope().subject, fixture.artifact.digest);
    assert_eq!(bundle.document_bytes(0), Some(raw.as_slice()));
    assert_eq!(
        bundle.envelope().documents.len(),
        1,
        "same raw blob is exported once"
    );
    assert_eq!(
        bundle.envelope().snapshot["documents"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "all document kind/origin references survive dedup"
    );
    assert_eq!(bundle.envelope().source["context_revision"], revision);
    assert_eq!(bundle.envelope().snapshot["context_revision"], revision);
    assert_eq!(
        bundle.envelope().source["snapshot_time"],
        bundle.envelope().snapshot["database_snapshot"]["time"]
    );
    let scopes = bundle.envelope().snapshot["artifact_scopes"]
        .as_array()
        .unwrap();
    assert_eq!(scopes.len(), 2);
    assert_eq!(
        scopes
            .iter()
            .filter(|s| s["configured_repository"] == true)
            .count(),
        1
    );
    assert!(
        scopes
            .iter()
            .any(|s| s["configured_repository"] == false
                && s["omission"]["reason"].as_str().is_some())
    );
    assert!(
        !bundle
            .blobs()
            .contains_key(&format!("sha256:{}", fixture.artifact.digest)),
        "original package bytes are omitted"
    );
    let blob_path = fixture
        .directory
        .path()
        .join("blobs/sha256")
        .join(&digest[..2])
        .join(&digest);
    std::fs::write(blob_path, b"bad stored document").unwrap();
    assert_eq!(
        fixture
            .request("GET", &fixture.endpoint("evidence-export"), "admin", vec![])
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nonretained_delivery_preserves_actual_import_blobs_but_not_the_claimed_subject(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let shared = b"{\"actual_import_document_and_package\":true}".to_vec();
    let subject_only = b"{\"package_subject_without_import_blob_reference\":true}".to_vec();
    let upstream = Router::new()
        .route(
            "/shared.jar",
            axum::routing::get({
                let bytes = shared.clone();
                move || async move { bytes.clone() }
            }),
        )
        .route(
            "/subject-only.jar",
            axum::routing::get({
                let bytes = subject_only.clone();
                move || async move { bytes.clone() }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });
    let mut config = (*fixture.state.config).clone();
    config.access.principals.clear();
    config.policy.required.clear();
    config.policy.deny_on_failure.clear();
    config.allow_private_upstreams = true;
    let repo = config.repositories.get_mut("maven").unwrap();
    repo.kind = RepositoryKind::Proxy;
    repo.upstream = Some(upstream_url.parse().unwrap());
    repo.retain = false;
    let state = AppState::new(
        Arc::new(config),
        fixture.state.store.clone(),
        fixture.state.blobs.clone(),
        "a".repeat(32),
        "r".repeat(32),
    );
    let app = gateway::router(state.clone());
    let shared_digest = sha256(&shared);
    state.blobs.put(shared.clone()).await.unwrap();
    let bundle = oci::build_bundle(
        &fixture.artifact.digest,
        json!({}),
        json!({}),
        vec![shared.clone()],
    )
    .unwrap();
    // Reproduce a deleting delivery holding the same digest lock while import
    // waits. The import must rewrite the deleted bytes before committing refs.
    let mut deleting = state.store.pool.begin().await.unwrap();
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('packweir.cas.retention:' || $1,0))",
    )
    .bind(&shared_digest)
    .execute(&mut *deleting)
    .await
    .unwrap();
    let importing = tokio::spawn({
        let state = state.clone();
        let subject = fixture.artifact.digest.clone();
        let bundle = bundle.clone();
        async move {
            exchange::register_bundle(&state, &subject, &bundle)
                .await
                .unwrap()
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let blocked:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%packweir.cas.retention:%')")
                .fetch_one(&state.store.pool).await.unwrap();
            if blocked {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("import waits for the deleting delivery's CAS digest lock");
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM external_imports")
        .fetch_one(&state.store.pool)
        .await
        .unwrap();
    assert_eq!(visible, 0);
    state.blobs.delete(&shared_digest).await.unwrap();
    deleting.commit().await.unwrap();
    importing.await.unwrap();
    assert_eq!(state.blobs.read(&shared_digest).await.unwrap(), shared);
    let deliver = |path: &str| {
        Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", "r".repeat(32)))
            .body(Body::empty())
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(deliver("/r/maven/shared.jar"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        shared.as_slice()
    );
    assert_eq!(
        state.blobs.read(&shared_digest).await.unwrap(),
        shared,
        "actual archive blob references retain CAS bytes"
    );
    let subject_digest = sha256(&subject_only);
    state
        .store
        .register(&Artifact {
            repository: "maven".into(),
            origin: format!("{upstream_url}subject-only.jar"),
            digest: subject_digest.clone(),
            size: subject_only.len() as i64,
            filename: "subject-only.jar".into(),
            content_type: "application/octet-stream".into(),
            package: None,
        })
        .await
        .unwrap();
    let subject_bundle = oci::build_bundle(&subject_digest, json!({}), json!({}), vec![]).unwrap();
    exchange::register_bundle(&state, &subject_digest, &subject_bundle)
        .await
        .unwrap();
    let response = app
        .oneshot(deliver("/r/maven/subject-only.jar"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        state.blobs.read(&subject_digest).await.is_err(),
        "a foreign package subject is not a blob retention reference"
    );
    server.abort();
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_context_documents_and_policy_remain_one_database_snapshot_during_a_change(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let new_document = fixture
        .state
        .blobs
        .put(b"{\"new_context_document\":true}".to_vec())
        .await
        .unwrap();
    let configuration = fixture
        .state
        .config
        .delivery_fingerprint(&fixture.artifact.scope())
        .unwrap();
    let mut change = fixture.state.store.pool.begin().await.unwrap();
    // Export reads context, artifacts, evidence, and documents before reaching
    // decisions. Hold it there, then atomically change that source context.
    sqlx::query("LOCK TABLE decisions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *change)
        .await
        .unwrap();
    let exporting = tokio::spawn({
        let state = fixture.state.clone();
        let subject = fixture.artifact.digest.clone();
        async move { exchange::snapshot_bundle(&state, &subject).await.unwrap() }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async{
        loop {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM decisions%')")
                .fetch_one(&fixture.state.store.pool).await.unwrap();
            if blocked {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("export must reach its decisions read in the original snapshot");
    sqlx::query("UPDATE contexts SET revision=revision+1 WHERE subject=$1")
        .bind(&fixture.artifact.digest)
        .execute(&mut *change)
        .await
        .unwrap();
    sqlx::query("INSERT INTO documents(id,subject,kind,origin,blob_digest) VALUES($1,$2,'sbom','client_resolved',$3)")
        .bind(Uuid::new_v4()).bind(&fixture.artifact.digest).bind(&new_document).execute(&mut *change).await.unwrap();
    let now = Utc::now();
    let evidence = Evidence {
        subject: fixture.artifact.digest.clone(),
        configuration,
        check: "archive_safety".into(),
        tool_version: "concurrent-source".into(),
        outcome: Outcome::Fail,
        created_at: now,
        expires_at: now + Duration::hours(1),
        details: json!({}),
        references: vec![],
    };
    sqlx::query("INSERT INTO evidence(id,subject,check_name,configuration,context_revision,created_at,expires_at,document) VALUES($1,$2,$3,$4,1,$5,$6,$7)")
        .bind(Uuid::new_v4()).bind(&evidence.subject).bind(&evidence.check).bind(&evidence.configuration)
        .bind(evidence.created_at).bind(evidence.expires_at).bind(serde_json::to_value(&evidence).unwrap())
        .execute(&mut *change).await.unwrap();
    change.commit().await.unwrap();
    let old = exporting.await.unwrap();
    assert_eq!(old.envelope().snapshot["context_revision"], 0);
    assert_eq!(old.envelope().source["context_revision"], 0);
    assert!(
        old.envelope().snapshot["documents"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        old.envelope().snapshot["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        old.envelope().snapshot["artifact_scopes"][0]["explanation"]["decision"]["state"],
        "pending"
    );
    let new = exchange::snapshot_bundle(&fixture.state, &fixture.artifact.digest)
        .await
        .unwrap();
    assert_eq!(new.envelope().snapshot["context_revision"], 1);
    assert_eq!(
        new.envelope().snapshot["documents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        new.envelope().snapshot["evidence"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        new.envelope().snapshot["artifact_scopes"][0]["explanation"]["decision"]["state"],
        "denied"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_atomic_audit_registration_leaves_no_visible_import_or_blob_references(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    sqlx::query("CREATE FUNCTION reject_external_import_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''test audit failure''; END;'")
        .execute(&fixture.state.store.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER reject_external_import_audit BEFORE INSERT ON audit FOR EACH ROW WHEN (NEW.action='external_evidence_imported') EXECUTE FUNCTION reject_external_import_audit()")
        .execute(&fixture.state.store.pool).await.unwrap();
    let before = fixture.local_state().await;
    assert_eq!(
        fixture.import_bundle(&forged(&fixture, 0)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let imports: i64 = sqlx::query_scalar("SELECT count(*) FROM external_imports")
        .fetch_one(&fixture.state.store.pool)
        .await
        .unwrap();
    let references: i64 = sqlx::query_scalar("SELECT count(*) FROM external_import_blobs")
        .fetch_one(&fixture.state.store.pool)
        .await
        .unwrap();
    assert_eq!((imports, references), (0, 0));
    assert_eq!(fixture.local_state().await, before);
}
