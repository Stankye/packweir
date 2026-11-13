//! Controlled storage/API fixtures, not actual Ghidra execution or qualification.
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    access::{AccessControl, Action, Grant, ServicePrincipal},
    analysis_outputs::OutputDraft,
    binary_analysis::{BinaryAnalysisPolicy, producer_identity_sha256, validate_manifest},
    config::{Config, RepositoryKind, StorageConfig},
    gateway::{self, AppState},
    model::{Artifact, Decision, Evidence, Outcome, sha256},
    storage::BlobStore,
    store::{Job, Store},
};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration as Wait};
use tower::ServiceExt;
use uuid::Uuid;

const CHECK: &str = "controlled_binary_observation";
const CONFIGURATION: &str = "controlled-storage-configuration";
const OUTPUT: &[u8] = b"/* controlled storage fixture; no tool was executed */\n";

struct Fixture {
    state: AppState,
    app: Router,
    artifact: Artifact,
    manifest: Value,
    directory: tempfile::TempDir,
}

impl Fixture {
    async fn new(pool: sqlx::PgPool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        config.repositories.retain(|name, _| name == "maven");
        let repo = config.repositories.get_mut("maven").unwrap();
        repo.kind = RepositoryKind::Hosted;
        repo.upstream = None;
        repo.download_origins.clear();
        repo.token_env = None;
        repo.cargo_download_template = None;
        repo.cache_max_age_seconds = None;
        config.storage = StorageConfig::Fs {
            root: directory.path().to_string_lossy().into(),
        };
        config.access.principals.clear();
        let mut tokens = BTreeMap::new();
        for (id, action) in [("reader", Action::Read), ("writer", Action::Write)] {
            config.access.principals.insert(
                id.into(),
                ServicePrincipal {
                    token_env: format!("TEST_OUTPUT_{id}"),
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
        let package = b"controlled parent package, distinct from its binary child";
        let artifact = Artifact {
            repository: "maven".into(),
            origin: "https://source.test/controlled.jar".into(),
            digest: sha256(package),
            size: package.len() as i64,
            filename: "controlled.jar".into(),
            content_type: "application/java-archive".into(),
            package: None,
        };
        store.register(&artifact).await.unwrap();
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
            state,
            app,
            artifact,
            manifest: controlled_manifest(),
            directory,
        }
    }

    async fn job(&self) -> Job {
        self.state
            .store
            .enqueue(
                &self.artifact.digest,
                CONFIGURATION,
                &self.artifact.filename,
            )
            .await
            .unwrap();
        self.state
            .store
            .lease(CONFIGURATION, 60)
            .await
            .unwrap()
            .unwrap()
    }

    fn drafts(&self) -> Vec<OutputDraft> {
        OutputDraft::from_manifest(CHECK, &self.manifest, &["bin/controlled.elf".into()]).unwrap()
    }

    fn evidence(&self) -> Evidence {
        let now = Utc::now();
        Evidence {
            subject: self.artifact.digest.clone(),
            check: CHECK.into(),
            tool_version: "controlled-storage-fixture-only".into(),
            configuration: CONFIGURATION.into(),
            outcome: Outcome::Pass,
            created_at: now,
            expires_at: now + Duration::hours(1),
            details: json!({"binary_analysis":{"manifests":[{
                "manifest_sha256":sha256(&serde_json::to_vec(&self.manifest).unwrap()),
                "manifest":self.manifest}]}}),
            references: vec![],
        }
    }

    async fn commit(&self) -> (Job, Uuid) {
        let job = self.job().await;
        self.state
            .store
            .complete_with_outputs(&job, &[self.evidence()], &self.drafts(), &self.state.blobs)
            .await
            .unwrap();
        let id = sqlx::query_scalar("SELECT id FROM analysis_outputs WHERE job_id=$1")
            .bind(job.id)
            .fetch_one(&self.state.store.pool)
            .await
            .unwrap();
        (job, id)
    }

    fn endpoint(&self) -> String {
        format!(
            "/api/v1/artifacts/{}/analysis-outputs",
            self.artifact.digest
        )
    }

    async fn request(&self, path: &str, who: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
        request(&self.app, path, who).await
    }

    async fn assert_no_receipts(&self, job: &Job) {
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM evidence),(SELECT count(*) FROM analysis_outputs)",
        )
        .fetch_one(&self.state.store.pool)
        .await
        .unwrap();
        assert_eq!(
            counts,
            (0, 0),
            "evidence and derived-output references must roll back together"
        );
        assert_eq!(
            self.state
                .store
                .job_status(&job.subject, &job.configuration)
                .await
                .unwrap()
                .map(|s| s.state),
            if job.context_revision
                == sqlx::query_scalar::<_, i64>("SELECT revision FROM contexts WHERE subject=$1")
                    .bind(&job.subject)
                    .fetch_one(&self.state.store.pool)
                    .await
                    .unwrap()
            {
                Some("running".into())
            } else {
                None
            }
        );
    }
}

// Produce a valid bounded contract, but identify every input and engine as a
// controlled fixture. Storage tests do not claim the engine ran on these bytes.
fn controlled_manifest() -> Value {
    let input = b"\x7fELFcontrolled storage input";
    let input_sha = sha256(input);
    let mut producer = json!({"engine":"ControlledStorageFixture","engine_version":"1",
        "engine_archive_sha256":sha256(b"fixture-engine"),"jdk_version":"fixture-only",
        "jdk_archive_sha256":sha256(b"fixture-jdk"),"decompiler_sha256":sha256(b"fixture-decompiler"),
        "scripts_sha256":sha256(b"fixture-scripts"),"profile_sha256":sha256(b"fixture-profile"),
        "driver_sha256":sha256(b"fixture-driver")});
    let identity = producer_identity_sha256(&producer).unwrap();
    producer["identity_sha256"] = json!(identity);
    let now = Utc::now();
    let manifest = json!({"schema_version":"packweir.binary-analysis.v1",
        "input":{"sha256":input_sha,"size":input.len(),"kind":"elf"},"producer":producer,
        "analysis":{"started_at":(now-Duration::seconds(2)).to_rfc3339(),
            "completed_at":(now-Duration::seconds(1)).to_rfc3339(),"status":"complete","timed_out":false,
            "errors":[],"warnings":[],"language_id":"fixture:LE:64:default","compiler_spec_id":"fixture",
            "requested_capabilities":["decompile"],"capabilities":{"decompile":"complete","pcode":"not_requested","decode_xor":"not_requested"},
            "functions_total":1,"functions_decompiled":1,"functions_failed":0,"export_truncated":false,"log_sha256":sha256(b"fixture-log")},
        "observations":[{"kind":"note","name":"scope","value":"Controlled storage fixture, not an actual tool execution"}],
        "outputs":[{"kind":"decompiled_c","media_type":"text/x-c","sha256":sha256(OUTPUT),"size":OUTPUT.len(),
            "data_base64":STANDARD.encode(OUTPUT),"derivation":{"operation":"ghidra.decompile","version":"1",
                "input_sha256":input_sha,"parameters":{"function_entry":"fixture-entry"},
                "source_spans":[{"offset":0,"length":input.len(),"sha256":input_sha}]}}]});
    let policy = BinaryAnalysisPolicy {
        service: "ControlledFixtureService".into(),
        identity_sha256: identity,
        required_capabilities: vec!["decompile".into()],
        informational_warnings: vec![],
        candidate_kinds: vec!["elf".into()],
    };
    let validated = validate_manifest(
        &policy,
        &input_sha,
        input.len() as u64,
        "elf",
        Some(input),
        &manifest,
        now,
    )
    .unwrap();
    assert!(validated.complete);
    validated.details["manifest"].clone()
}

async fn request(app: &Router, path: &str, who: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().uri(path);
    if who != "none" {
        let token = match who {
            "admin" => "a".repeat(32),
            "legacy" => "r".repeat(32),
            other => other.repeat(12),
        };
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
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
    (status, headers, bytes)
}

async fn wait_for_lock(pool: &sqlx::PgPool, fragment: &str) {
    tokio::time::timeout(Wait::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND strpos(query,$1)>0)")
                .bind(fragment).fetch_one(pool).await.unwrap();
            if blocked { break; }
            tokio::time::sleep(Wait::from_millis(10)).await;
        }
    }).await.expect("transaction must actually wait at the intended database lock");
}

#[sqlx::test(migrations = "./migrations")]
async fn output_and_evidence_commit_in_one_context_without_documents_or_inherited_approval(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let (job, _) = fixture.commit().await;
    let row = sqlx::query("SELECT o.*,e.document,e.context_revision AS evidence_context FROM analysis_outputs o JOIN evidence e ON e.id=o.evidence_id")
        .fetch_one(&fixture.state.store.pool).await.unwrap();
    assert_eq!(row.get::<Uuid, _>("job_id"), job.id);
    assert_eq!(row.get::<String, _>("subject"), fixture.artifact.digest);
    assert_eq!(row.get::<String, _>("configuration"), CONFIGURATION);
    assert_eq!(row.get::<i64, _>("context_revision"), 0);
    assert_eq!(row.get::<i64, _>("evidence_context"), 0);
    assert_eq!(
        row.get::<String, _>("manifest_sha256"),
        sha256(&serde_json::to_vec(&fixture.manifest).unwrap())
    );
    assert_eq!(
        row.get::<Value, _>("document")["details"]["binary_analysis"]["manifests"][0]["manifest"],
        fixture.manifest
    );
    assert_eq!(
        row.get::<Value, _>("metadata")["logical_paths"],
        json!(["bin/controlled.elf"])
    );
    assert_eq!(row.get::<String, _>("approval_effect"), "none");
    let metadata = row.get::<Value, _>("metadata");
    assert_eq!(metadata["validation"]["source_spans_verified"], Value::Null);
    assert_eq!(metadata["validation"]["xor_recomputed"], Value::Null);
    assert_eq!(
        metadata["validation"]["semantic_equivalence_verified"],
        false
    );
    assert_eq!(
        metadata["validation"]["basis"],
        "no_engine_validation_supplied"
    );
    assert_eq!(
        fixture.state.blobs.read(&sha256(OUTPUT)).await.unwrap(),
        OUTPUT
    );
    assert_eq!(
        fixture
            .state
            .store
            .job_status(&job.subject, CONFIGURATION)
            .await
            .unwrap()
            .unwrap()
            .state,
        "complete"
    );
    let counts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM documents),(SELECT count(*) FROM artifacts WHERE digest=$1),(SELECT count(*) FROM evidence WHERE subject=$1)")
        .bind(sha256(OUTPUT)).fetch_one(&fixture.state.store.pool).await.unwrap();
    assert_eq!(
        counts,
        (0, 0, 0),
        "derived bytes are not a package or document and have no inherited finding"
    );
    let parent_evidence = fixture
        .state
        .store
        .evidence(&job.subject, CONFIGURATION)
        .await
        .unwrap();
    assert!(matches!(
        fixture.state.config.policy.evaluate(
            &sha256(OUTPUT),
            CONFIGURATION,
            &parent_evidence,
            Utc::now()
        ),
        Decision::Pending(_)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM decisions")
            .fetch_one(&fixture.state.store.pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stored_receipts_preserve_computed_source_and_xor_checks_without_claiming_semantic_equivalence(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let decoded = OUTPUT;
    let mut input = b"\x7fELF".to_vec();
    input.extend(decoded.iter().map(|byte| byte ^ 0x5a));
    input.extend(decoded.iter().map(|byte| byte ^ 0x5a));
    let input_sha = sha256(&input);
    let mut manifest = fixture.manifest.clone();
    manifest["input"]["sha256"] = json!(input_sha);
    manifest["input"]["size"] = json!(input.len());
    manifest["outputs"][0]["derivation"]["input_sha256"] = json!(input_sha);
    manifest["outputs"][0]["derivation"]["source_spans"] =
        json!([{"offset":0,"length":input.len(),"sha256":input_sha}]);
    manifest["analysis"]["requested_capabilities"] = json!(["decompile", "decode_xor"]);
    manifest["analysis"]["capabilities"]["decode_xor"] = json!("complete");
    manifest["outputs"].as_array_mut().unwrap().push(json!({"kind":"decoded_bytes","media_type":"application/octet-stream",
        "sha256":sha256(decoded),"size":decoded.len(),"data_base64":STANDARD.encode(decoded),
        "derivation":{"operation":"xor.decode","version":"1","input_sha256":input_sha,"parameters":{"key_hex":"5a"},
            "source_spans":[{"offset":4,"length":decoded.len(),"sha256":sha256(&input[4..4+decoded.len()])}]}}));
    let mut second = manifest["outputs"][1].clone();
    second["derivation"]["source_spans"][0]["offset"] = json!(4 + decoded.len());
    manifest["outputs"].as_array_mut().unwrap().push(second);
    let policy = BinaryAnalysisPolicy {
        service: "ControlledFixtureService".into(),
        identity_sha256: manifest["producer"]["identity_sha256"]
            .as_str()
            .unwrap()
            .into(),
        required_capabilities: vec!["decompile".into(), "decode_xor".into()],
        informational_warnings: vec![],
        candidate_kinds: vec!["elf".into()],
    };
    let validated = validate_manifest(
        &policy,
        &input_sha,
        input.len() as u64,
        "elf",
        Some(&input),
        &manifest,
        Utc::now(),
    )
    .unwrap();
    assert!(validated.complete);
    let drafts = OutputDraft::from_manifest(
        CHECK,
        &validated.details["manifest"],
        &["bin/controlled.elf".into()],
    )
    .unwrap();
    let mut evidence = fixture.evidence();
    evidence.details["binary_analysis"]["manifests"] = json!([validated.details]);
    let job = fixture.job().await;
    fixture
        .state
        .store
        .complete_with_outputs(&job, &[evidence], &drafts, &fixture.state.blobs)
        .await
        .unwrap();
    let rows = sqlx::query("SELECT id,kind,output_sha256,derivation_sha256,metadata FROM analysis_outputs ORDER BY kind")
        .fetch_all(&fixture.state.store.pool)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        3,
        "one C descriptor and two independently verified XOR spans retain separate receipts"
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.get::<Uuid, _>("id"))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.get::<String, _>("output_sha256"))
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([sha256(OUTPUT)])
    );
    let decoded_rows: Vec<_> = rows
        .iter()
        .filter(|row| row.get::<String, _>("kind") == "decoded_bytes")
        .collect();
    assert_eq!(decoded_rows.len(), 2);
    assert_eq!(
        decoded_rows
            .iter()
            .map(|row| row.get::<String, _>("derivation_sha256"))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    assert_eq!(
        fixture.state.blobs.read(&sha256(OUTPUT)).await.unwrap(),
        OUTPUT
    );
    let cas_objects = std::fs::read_dir(fixture.directory.path().join("blobs/sha256"))
        .unwrap()
        .map(|prefix| std::fs::read_dir(prefix.unwrap().path()).unwrap().count())
        .sum::<usize>();
    assert_eq!(
        cas_objects, 1,
        "kind and derivation identity must not duplicate the physical CAS bytes"
    );
    for row in rows {
        let kind = row.get::<String, _>("kind");
        let metadata = row.get::<Value, _>("metadata");
        assert_eq!(metadata["validation"]["source_spans_verified"], true);
        assert_eq!(
            metadata["validation"]["xor_recomputed"],
            kind == "decoded_bytes"
        );
        assert_eq!(
            metadata["validation"]["semantic_equivalence_verified"],
            false
        );
        assert_eq!(metadata["manifest_validation"]["complete"], true);
        assert_eq!(
            metadata["manifest_validation"]["input_bytes_verified"],
            true
        );
        assert_eq!(metadata["manifest_validation"]["reasons"], json!([]));
        assert!(metadata["validation"].get("derivation_verified").is_none());
        assert!(metadata["validation"].get("data_base64").is_none());
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn context_changes_hide_old_evidence_but_preserve_labeled_historical_outputs(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    fixture.commit().await;
    fixture
        .state
        .store
        .invalidate(&fixture.artifact.digest)
        .await
        .unwrap();
    assert!(
        fixture
            .state
            .store
            .evidence(&fixture.artifact.digest, CONFIGURATION)
            .await
            .unwrap()
            .is_empty()
    );
    let new_job = fixture.job().await;
    assert_eq!(new_job.context_revision, 1);
    fixture
        .state
        .store
        .complete_with_outputs(
            &new_job,
            &[fixture.evidence()],
            &fixture.drafts(),
            &fixture.state.blobs,
        )
        .await
        .unwrap();
    let (status, _, body) = fixture.request(&fixture.endpoint(), "admin").await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&body).unwrap();
    let outputs = body["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 2);
    let mut revisions: Vec<_> = outputs
        .iter()
        .map(|o| o["context_revision"].as_i64().unwrap())
        .collect();
    revisions.sort();
    assert_eq!(revisions, [0, 1]);
    assert!(outputs.iter().all(|o| o["approval_effect"] == "none"));
    assert_eq!(
        fixture
            .state
            .store
            .evidence(&fixture.artifact.digest, CONFIGURATION)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn retrieval_is_admin_only_and_downloads_exact_hash_checked_cas_bytes(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool).await;
    let (_, id) = fixture.commit().await;
    let download = format!("{}/{id}", fixture.endpoint());
    for who in ["none", "legacy", "reader", "writer"] {
        for path in [&fixture.endpoint(), &download] {
            assert_eq!(
                fixture.request(path, who).await.0,
                StatusCode::UNAUTHORIZED,
                "{who}: {path}"
            );
        }
    }
    let (status, headers, body) = fixture.request(&fixture.endpoint(), "admin").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["subject"], fixture.artifact.digest);
    assert_eq!(body["approval_effect"], "none");
    assert_eq!(body["outputs"][0]["output_sha256"], sha256(OUTPUT));
    assert!(
        body["outputs"][0]["metadata"]["output"]
            .get("data_base64")
            .is_none()
    );
    let (status, headers, bytes) = fixture.request(&download, "admin").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, OUTPUT);
    assert_eq!(headers["x-packweir-sha256"], sha256(&bytes));
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_subject_unknown_id_and_missing_or_corrupt_cas_fail_closed(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool).await;
    let (_, id) = fixture.commit().await;
    let wrong = format!(
        "/api/v1/artifacts/{}/analysis-outputs/{id}",
        sha256(b"another parent")
    );
    assert_eq!(
        fixture.request(&wrong, "admin").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .request(
                &format!("{}/{}", fixture.endpoint(), Uuid::new_v4()),
                "admin"
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .request("/api/v1/artifacts/not-a-full-sha/analysis-outputs", "admin")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let download = format!("{}/{id}", fixture.endpoint());
    fixture.state.blobs.delete(&sha256(OUTPUT)).await.unwrap();
    assert_eq!(
        fixture.request(&download, "admin").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.state.blobs.put(OUTPUT.to_vec()).await.unwrap();
    let digest = sha256(OUTPUT);
    let path = fixture
        .directory
        .path()
        .join("blobs/sha256")
        .join(&digest[..2])
        .join(&digest);
    std::fs::write(path, vec![b'!'; OUTPUT.len()]).unwrap();
    let (status, _, body) = fixture.request(&download, "admin").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"],
        "analysis_output_unavailable"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unbound_substituted_and_ambiguous_producing_evidence_roll_back_all_receipts(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let job = fixture.job().await;
    for case in [
        "missing_check",
        "omitted_manifests",
        "wrong_manifest_hash",
        "substituted_manifest",
        "wrong_subject",
        "wrong_configuration",
        "duplicate_check",
    ] {
        let mut evidence = fixture.evidence();
        match case {
            "missing_check" => evidence.check = "another-check".into(),
            "omitted_manifests" => evidence.details = json!({}),
            "wrong_manifest_hash" => {
                evidence.details["binary_analysis"]["manifests"][0]["manifest_sha256"] =
                    json!(sha256(b"substituted manifest"))
            }
            "substituted_manifest" => {
                evidence.details["binary_analysis"]["manifests"][0]["manifest"]["observations"][0]
                    ["value"] = json!("different manifest under the original digest")
            }
            "wrong_subject" => evidence.subject = sha256(b"another subject"),
            "wrong_configuration" => evidence.configuration = "another-configuration".into(),
            "duplicate_check" => {}
            _ => unreachable!(),
        }
        let evidence = if case == "duplicate_check" {
            vec![evidence.clone(), evidence]
        } else {
            vec![evidence]
        };
        assert!(
            fixture
                .state
                .store
                .complete_with_outputs(&job, &evidence, &fixture.drafts(), &fixture.state.blobs)
                .await
                .is_err(),
            "{case}"
        );
        fixture.assert_no_receipts(&job).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_lease_and_changed_context_cannot_commit_derived_receipts(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool).await;
    let job = fixture.job().await;
    sqlx::query("UPDATE jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(job.id)
        .execute(&fixture.state.store.pool)
        .await
        .unwrap();
    assert!(
        fixture
            .state
            .store
            .complete_with_outputs(
                &job,
                &[fixture.evidence()],
                &fixture.drafts(),
                &fixture.state.blobs
            )
            .await
            .is_err()
    );
    fixture.assert_no_receipts(&job).await;
    let fresh_job = fixture
        .state
        .store
        .lease(CONFIGURATION, 60)
        .await
        .unwrap()
        .unwrap();
    fixture
        .state
        .store
        .invalidate(&fresh_job.subject)
        .await
        .unwrap();
    assert!(
        fixture
            .state
            .store
            .complete_with_outputs(
                &fresh_job,
                &[fixture.evidence()],
                &fixture.drafts(),
                &fixture.state.blobs
            )
            .await
            .is_err()
    );
    fixture.assert_no_receipts(&fresh_job).await;
    assert!(fixture.state.blobs.read(&sha256(OUTPUT)).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn context_generation_change_while_waiting_on_row_lock_prevents_receipts(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool).await;
    let job = fixture.job().await;
    let subject = job.subject.clone();
    let mut blocker = fixture.state.store.pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
        .bind(&subject)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let store = fixture.state.store.clone();
    let blobs = fixture.state.blobs.clone();
    let drafts = fixture.drafts();
    let evidence = fixture.evidence();
    let task = tokio::spawn(async move {
        store
            .complete_with_outputs(&job, &[evidence], &drafts, &blobs)
            .await
    });
    wait_for_lock(&fixture.state.store.pool, "SELECT revision FROM contexts").await;
    sqlx::query("UPDATE contexts SET revision=revision+1 WHERE subject=$1")
        .bind(&subject)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("context changed")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM evidence")
            .fetch_one(&fixture.state.store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analysis_outputs")
            .fetch_one(&fixture.state.store.pool)
            .await
            .unwrap(),
        0
    );
    assert!(fixture.state.blobs.read(&sha256(OUTPUT)).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_lock_wait_past_lease_expiry_rolls_back_evidence_and_output_references(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    let job = fixture.job().await;
    let job_id = job.id;
    let mut blocker = fixture.state.store.pool.begin().await.unwrap();
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('packweir.cas.retention:' || $1,0))",
    )
    .bind(sha256(OUTPUT))
    .execute(&mut *blocker)
    .await
    .unwrap();
    sqlx::query("UPDATE jobs SET lease_until=clock_timestamp()+interval '2 seconds' WHERE id=$1")
        .bind(job_id)
        .execute(&fixture.state.store.pool)
        .await
        .unwrap();
    let store = fixture.state.store.clone();
    let blobs = fixture.state.blobs.clone();
    let drafts = fixture.drafts();
    let evidence = fixture.evidence();
    let task = tokio::spawn(async move {
        store
            .complete_with_outputs(&job, &[evidence], &drafts, &blobs)
            .await
    });
    wait_for_lock(&fixture.state.store.pool, "packweir.cas.retention:").await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM evidence")
            .fetch_one(&fixture.state.store.pool)
            .await
            .unwrap(),
        0,
        "uncommitted evidence is not externally visible"
    );
    tokio::time::timeout(Wait::from_secs(5), async {
        loop {
            let expired: bool =
                sqlx::query_scalar("SELECT lease_until<=clock_timestamp() FROM jobs WHERE id=$1")
                    .bind(job_id)
                    .fetch_one(&fixture.state.store.pool)
                    .await
                    .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Wait::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("expired while storing derived outputs")
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evidence),(SELECT count(*) FROM analysis_outputs)",
    )
    .fetch_one(&fixture.state.store.pool)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0));
    assert_eq!(
        fixture.state.blobs.read(&sha256(OUTPUT)).await.unwrap(),
        OUTPUT,
        "an unreferenced CAS orphan is allowed after transaction rollback"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM jobs WHERE id=$1")
            .bind(job_id)
            .fetch_one(&fixture.state.store.pool)
            .await
            .unwrap(),
        "running"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nonretaining_package_delivery_preserves_cas_referenced_only_by_a_derived_output(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool).await;
    fixture.commit().await;
    let ordinary = b"ordinary unreferenced nonretained package".to_vec();
    let upstream = Router::new()
        .route(
            "/derived.jar",
            axum::routing::get(|| async { OUTPUT.to_vec() }),
        )
        .route(
            "/ordinary.jar",
            axum::routing::get({
                let bytes = ordinary.clone();
                move || {
                    let bytes = bytes.clone();
                    async move { bytes }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
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
    for (path, expected) in [
        ("/r/maven/derived.jar", OUTPUT),
        ("/r/maven/ordinary.jar", ordinary.as_slice()),
    ] {
        let (status, _, bytes) = request(&app, path, "legacy").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, expected);
    }
    assert_eq!(
        state.blobs.read(&sha256(OUTPUT)).await.unwrap(),
        OUTPUT,
        "the derived-output reference retains its exact CAS object"
    );
    assert!(
        state.blobs.read(&sha256(&ordinary)).await.is_err(),
        "control delivery proves nonretaining deletion actually ran"
    );
    let non_output_refs:(i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM jobs WHERE subject=$1),(SELECT count(*) FROM hosted_files WHERE digest=$1),(SELECT count(*) FROM external_import_blobs WHERE digest=$1),(SELECT count(*) FROM documents WHERE blob_digest=$1)")
        .bind(sha256(OUTPUT)).fetch_one(&state.store.pool).await.unwrap();
    assert_eq!(non_output_refs, (0, 0, 0, 0));
    server.abort();
}
