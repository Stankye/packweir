//! SQL-backed delivery and publication must see the same complete freshness input.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    access::MavenOwnership,
    config::{CommandScanner, Config, RepositoryKind, ScannerDriver, StorageConfig},
    gateway::{self, AppState},
    hosted::{self, CopyRequest, HostedError},
    identity,
    maven::Coordinate,
    model::{Artifact, Decision, Evidence, Outcome, evidence_fingerprint},
    policy::{AgentEscalation, OutcomeCondition},
    storage::BlobStore,
    store::Store,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

const PATH: &str = "dev/fresh/fixture/1.0.0/fixture-1.0.0.jar";

struct Fixture {
    app: Router,
    config: Arc<Config>,
    store: Store,
    blobs: BlobStore,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(pool: sqlx::PgPool, hosted: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        config.repositories.retain(|name, _| name == "maven");
        config.storage = StorageConfig::Fs {
            root: directory.path().join("storage").to_string_lossy().into(),
        };
        config.policy.trust_agent = true;
        config.policy.agent_escalation = Some(AgentEscalation {
            when_any: vec![OutcomeCondition {
                check: "heuristic".into(),
                outcomes: vec![Outcome::Inconclusive],
            }],
        });
        // No subprocess is invoked by these tests: evidence is committed through
        // Store::complete to exercise two same-context analysis generations.
        for name in ["heuristic", "agent"] {
            config.scanners.insert(
                name.into(),
                CommandScanner {
                    program: std::env::current_exe().unwrap().to_string_lossy().into(),
                    args: vec![],
                    version: "trusted-store-fixture".into(),
                    timeout_seconds: 10,
                    environment: BTreeMap::new(),
                    program_sha256: None,
                    resources: BTreeMap::new(),
                    driver: ScannerDriver::Command,
                },
            );
        }
        if hosted {
            let mut repo = config.repositories.remove("maven").unwrap();
            repo.kind = RepositoryKind::Hosted;
            repo.upstream = None;
            repo.download_origins.clear();
            repo.token_env = None;
            repo.cargo_download_template = None;
            repo.cache_max_age_seconds = None;
            repo.retain = true;
            config.repositories.insert("dev".into(), repo.clone());
            config.repositories.insert("prod".into(), repo);
            config.access.maven_owners = vec![MavenOwnership {
                namespace: "dev.fresh".into(),
                repository: "dev".into(),
                additional_repositories: vec!["prod".into()],
            }];
        }
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
            app,
            config,
            store,
            blobs,
            _directory: directory,
        }
    }

    async fn proxy(&self) -> Artifact {
        let bytes = b"plain artifact fixture";
        let repo = &self.config.repositories["maven"];
        let origin = repo.proxy_upstream().unwrap().join(PATH).unwrap();
        let digest = self.blobs.put(bytes.to_vec()).await.unwrap();
        self.store
            .register(&Artifact {
                repository: "maven".into(),
                origin: origin.to_string(),
                digest,
                size: bytes.len() as i64,
                filename: "fixture-1.0.0.jar".into(),
                content_type: "application/java-archive".into(),
                package: identity::observe(repo, &origin, PATH),
            })
            .await
            .unwrap()
    }

    async fn request(&self, uri: &str, admin: bool) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", if admin { "a" } else { "r" }.repeat(32)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn commit(&self, artifact: &Artifact, mut findings: Vec<Evidence>) {
        let configuration = self.config.delivery_fingerprint(&artifact.scope()).unwrap();
        self.store
            .enqueue_delivery(artifact, &configuration, &self.config.fingerprint())
            .await
            .unwrap();
        let job = self
            .store
            .lease(&self.config.fingerprint(), 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.subject, artifact.digest);
        let existing = self
            .store
            .policy_evidence(&artifact.digest, &configuration)
            .await
            .unwrap();
        let mut dependencies = BTreeMap::new();
        for finding in existing
            .iter()
            .chain(&findings)
            .filter(|finding| finding.check != "agent")
        {
            let candidate = (finding.created_at, evidence_fingerprint(finding));
            if dependencies
                .get(&finding.check)
                .is_none_or(|(at, _)| *at <= candidate.0)
            {
                dependencies.insert(finding.check.clone(), candidate);
            }
        }
        let dependencies: BTreeMap<_, _> = dependencies
            .into_iter()
            .map(|(check, (_, digest))| (check, digest))
            .collect();
        for agent in findings
            .iter_mut()
            .filter(|finding| finding.check == "agent")
        {
            agent.details["packweir_inputs"] = json!({"version":1,"findings":dependencies});
        }
        self.store.complete(&job, &findings).await.unwrap();
    }

    fn evidence(
        &self,
        artifact: &Artifact,
        check: &str,
        outcome: Outcome,
        at: DateTime<Utc>,
        expiry: DateTime<Utc>,
    ) -> Evidence {
        Evidence {
            subject: artifact.digest.clone(),
            configuration: self.config.delivery_fingerprint(&artifact.scope()).unwrap(),
            check: check.into(),
            tool_version: "trusted-store-fixture".into(),
            outcome,
            created_at: at,
            expires_at: expiry,
            details: if check == "agent" {
                json!({"model":"store-test","prompt_digest":"prompt","toolset_digest":"tools","evidence_digest":"bundle","trace_digest":"trace"})
            } else {
                json!({})
            },
            references: vec![],
        }
    }

    async fn generations(&self, artifact: &Artifact) {
        let now = Utc::now();
        self.commit(
            artifact,
            vec![
                self.evidence(
                    artifact,
                    "inventory",
                    Outcome::Pass,
                    now - Duration::minutes(10),
                    now + Duration::hours(1),
                ),
                self.evidence(
                    artifact,
                    "archive_safety",
                    Outcome::Pass,
                    now - Duration::minutes(10),
                    now + Duration::hours(1),
                ),
                self.evidence(
                    artifact,
                    "heuristic",
                    Outcome::Pass,
                    now - Duration::minutes(10),
                    now + Duration::hours(1),
                ),
            ],
        )
        .await;
        self.commit(
            artifact,
            vec![
                self.evidence(
                    artifact,
                    "heuristic",
                    Outcome::Inconclusive,
                    now - Duration::minutes(5),
                    now + Duration::minutes(10),
                ),
                self.evidence(
                    artifact,
                    "agent",
                    Outcome::Pass,
                    now - Duration::minutes(4),
                    now + Duration::minutes(10),
                ),
            ],
        )
        .await;
    }

    async fn expire_trigger(&self, artifact: &Artifact) {
        let expiry = Utc::now() - Duration::seconds(1);
        // The indexed column is authoritative even if the JSON document still
        // advertises its original future expiry.
        sqlx::query("UPDATE evidence SET expires_at=$1 WHERE subject=$2 AND check_name='heuristic' AND document->>'outcome'='inconclusive'")
            .bind(expiry).bind(&artifact.digest).execute(&self.store.pool).await.unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_new_trigger_cannot_resurrect_older_pass_through_http(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    fixture.generations(&artifact).await;
    assert_eq!(
        fixture.request(&format!("/r/maven/{PATH}"), false).await.0,
        StatusCode::OK
    );
    fixture.expire_trigger(&artifact).await;
    let document_expiry: DateTime<Utc> = sqlx::query_scalar("SELECT (document->>'expires_at')::timestamptz FROM evidence WHERE subject=$1 AND check_name='heuristic' AND document->>'outcome'='inconclusive'")
        .bind(&artifact.digest).fetch_one(&fixture.store.pool).await.unwrap();
    assert!(
        document_expiry > Utc::now(),
        "fixture JSON still advertises a current result"
    );
    let projected = fixture
        .store
        .policy_evidence(
            &artifact.digest,
            &fixture
                .config
                .delivery_fingerprint(&artifact.scope())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(projected.iter().find(|finding| finding.check == "heuristic" && finding.outcome == Outcome::Inconclusive).unwrap().expires_at < Utc::now());
    let current = fixture
        .store
        .evidence(
            &artifact.digest,
            &fixture
                .config
                .delivery_fingerprint(&artifact.scope())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        !current
            .iter()
            .any(|e| e.check == "heuristic" && e.outcome == Outcome::Inconclusive),
        "current-only evidence deliberately retains its old semantics"
    );
    let (status, body) = fixture.request(&format!("/r/maven/{PATH}"), false).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["decision"]["state"], "pending");
    let (status, explanation) = fixture
        .request(&format!("/api/v1/artifacts/{}", artifact.digest), true)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(explanation["decision"], body["decision"]);
    assert_eq!(
        explanation["scopes"][0]["agent_escalation"]["state"],
        "unresolved"
    );
    assert_eq!(
        fixture
            .store
            .job_status(
                &artifact.digest,
                &fixture
                    .config
                    .delivery_fingerprint(&artifact.scope())
                    .unwrap()
            )
            .await
            .unwrap()
            .unwrap()
            .state,
        "queued"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn future_and_skipped_latest_inputs_stay_unresolved_in_database_delivery(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    fixture.generations(&artifact).await;
    for outcome in [Outcome::Skipped, Outcome::Inconclusive] {
        let now = Utc::now();
        let created = if outcome == Outcome::Skipped {
            now
        } else {
            now + Duration::hours(1)
        };
        fixture
            .commit(
                &artifact,
                vec![fixture.evidence(
                    &artifact,
                    "heuristic",
                    outcome,
                    created,
                    created + Duration::hours(1),
                )],
            )
            .await;
        let (status, body) = fixture.request(&format!("/r/maven/{PATH}"), false).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (_, explanation) = fixture
            .request(&format!("/api/v1/artifacts/{}", artifact.digest), true)
            .await;
        assert_eq!(explanation["decision"], body["decision"]);
        assert_eq!(
            explanation["scopes"][0]["agent_escalation"]["state"],
            "unresolved"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn newer_source_generation_cannot_reuse_older_bound_agent_pass(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    fixture.generations(&artifact).await;
    assert_eq!(
        fixture.request(&format!("/r/maven/{PATH}"), false).await.0,
        StatusCode::OK
    );
    let now = Utc::now();
    fixture
        .commit(
            &artifact,
            vec![fixture.evidence(
                &artifact,
                "heuristic",
                Outcome::Inconclusive,
                now,
                now + Duration::hours(1),
            )],
        )
        .await;
    let (status, body) = fixture.request(&format!("/r/maven/{PATH}"), false).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["decision"]["reasons"], json!(["agent"]));
    let (_, explanation) = fixture
        .request(&format!("/api/v1/artifacts/{}", artifact.digest), true)
        .await;
    assert_eq!(explanation["decision"], body["decision"]);
}

async fn hosted_stage(fixture: &Fixture, version: &str) -> (Uuid, Vec<Artifact>) {
    let coordinate = Coordinate::new("dev.fresh:fixture", version).unwrap();
    let id = Uuid::new_v4();
    hosted::create_stage(&fixture.store, id, "dev", coordinate.package(), "publisher")
        .await
        .unwrap();
    let mut artifacts = vec![];
    for extension in ["pom", "jar"] {
        let path = format!("{}.{extension}", coordinate.artifact_prefix());
        let bytes = format!("immutable {version} {extension} fixture");
        let digest = fixture.blobs.put(bytes.as_bytes().to_vec()).await.unwrap();
        let artifact = Artifact {
            repository: "dev".into(),
            origin: fixture
                .config
                .public_url
                .join(&format!("r/dev/{path}"))
                .unwrap()
                .into(),
            digest,
            size: bytes.len() as i64,
            filename: path.rsplit('/').next().unwrap().into(),
            content_type: "application/octet-stream".into(),
            package: Some(coordinate.package()),
        };
        hosted::add_file(&fixture.store, id, artifact.clone(), &path, "publisher")
            .await
            .unwrap();
        artifacts.push(artifact);
    }
    hosted::seal(&fixture.store, id, &fixture.config, "publisher")
        .await
        .unwrap();
    // Seal queued both members. Commit their first generations in lease order.
    while let Some(job) = fixture
        .store
        .lease(&fixture.config.fingerprint(), 60)
        .await
        .unwrap()
    {
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.digest == job.subject)
            .unwrap();
        let now = Utc::now();
        let findings = ["inventory", "archive_safety", "heuristic"]
            .into_iter()
            .map(|check| {
                fixture.evidence(
                    artifact,
                    check,
                    Outcome::Pass,
                    now - Duration::minutes(10),
                    now + Duration::hours(1),
                )
            })
            .collect::<Vec<_>>();
        fixture.store.complete(&job, &findings).await.unwrap();
    }
    for artifact in &artifacts {
        let now = Utc::now();
        fixture
            .commit(
                artifact,
                vec![
                    fixture.evidence(
                        artifact,
                        "heuristic",
                        Outcome::Inconclusive,
                        now - Duration::minutes(5),
                        now + Duration::minutes(10),
                    ),
                    fixture.evidence(
                        artifact,
                        "agent",
                        Outcome::Pass,
                        now - Duration::minutes(4),
                        now + Duration::minutes(10),
                    ),
                ],
            )
            .await;
    }
    (id, artifacts)
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_latest_trigger_blocks_hosted_promotion_delivery_and_immutable_copy(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, true);
    let (source, source_artifacts) = hosted_stage(&fixture, "1.0.0").await;
    let receipt = hosted::promote(&fixture.store, source, &fixture.config, "promoter")
        .await
        .unwrap();
    let (pending, pending_artifacts) = hosted_stage(&fixture, "2.0.0").await;
    for artifact in source_artifacts.iter().chain(&pending_artifacts) {
        fixture.expire_trigger(artifact).await;
    }
    assert!(matches!(
        hosted::promote(&fixture.store, pending, &fixture.config, "promoter").await,
        Err(HostedError::NotApproved(_))
    ));
    let path = format!(
        "{}.jar",
        Coordinate::new("dev.fresh:fixture", "1.0.0")
            .unwrap()
            .artifact_prefix()
    );
    assert!(matches!(
        hosted::delivery(&fixture.store, "dev", &path, &fixture.config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Pending(_)
    ));
    let request = CopyRequest {
        id: Uuid::new_v4(),
        destination_repository: "prod".into(),
        source_manifest_digest: receipt.manifest_digest,
    };
    assert!(matches!(
        hosted::copy_release(&fixture.store, source, &fixture.config, &request, "copier").await,
        Err(HostedError::NotApproved(_))
    ));
    assert!(matches!(
        hosted::stage(&fixture.store, request.id).await,
        Err(HostedError::NotFound)
    ));
    assert_eq!(
        fixture.request(&format!("/r/dev/{path}"), false).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn bound_and_unbound_pass_ties_survive_store_and_explanation(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    let now = Utc::now();
    let mut unbound = fixture.evidence(
        &artifact,
        "agent",
        Outcome::Pass,
        now - Duration::seconds(1),
        now + Duration::hours(1),
    );
    unbound.details = json!({});
    fixture
        .commit(
            &artifact,
            vec![
                fixture.evidence(
                    &artifact,
                    "inventory",
                    Outcome::Pass,
                    now - Duration::seconds(3),
                    now + Duration::hours(1),
                ),
                fixture.evidence(
                    &artifact,
                    "archive_safety",
                    Outcome::Pass,
                    now - Duration::seconds(3),
                    now + Duration::hours(1),
                ),
                fixture.evidence(
                    &artifact,
                    "heuristic",
                    Outcome::Inconclusive,
                    now - Duration::seconds(2),
                    now + Duration::hours(1),
                ),
                fixture.evidence(
                    &artifact,
                    "agent",
                    Outcome::Pass,
                    now - Duration::seconds(1),
                    now + Duration::hours(1),
                ),
                unbound,
            ],
        )
        .await;
    let configuration = fixture
        .config
        .delivery_fingerprint(&artifact.scope())
        .unwrap();
    for evidence in [
        fixture
            .store
            .policy_evidence(&artifact.digest, &configuration)
            .await
            .unwrap(),
        fixture
            .store
            .evidence_history(&artifact.digest, &configuration)
            .await
            .unwrap(),
    ] {
        assert_eq!(evidence.iter().filter(|e| e.check == "agent").count(), 2);
        assert_eq!(
            fixture
                .config
                .policy
                .evaluate(&artifact.digest, &configuration, &evidence, Utc::now()),
            Decision::Pending(vec!["agent".into()])
        );
    }
    let (status, body) = fixture.request(&format!("/r/maven/{PATH}"), false).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (_, explanation) = fixture
        .request(&format!("/api/v1/artifacts/{}", artifact.digest), true)
        .await;
    assert_eq!(body["decision"], explanation["decision"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn policy_evidence_bounds_fail_closed_without_dropping_conflicting_rows(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    let now = Utc::now();
    fixture
        .commit(
            &artifact,
            vec![
                fixture.evidence(
                    &artifact,
                    "inventory",
                    Outcome::Pass,
                    now,
                    now + Duration::hours(1)
                );
                1025
            ],
        )
        .await;
    let configuration = fixture
        .config
        .delivery_fingerprint(&artifact.scope())
        .unwrap();
    assert!(
        fixture
            .store
            .policy_evidence(&artifact.digest, &configuration)
            .await
            .is_err()
    );
    assert!(
        fixture
            .store
            .evidence_history(&artifact.digest, &configuration)
            .await
            .is_err()
    );
    assert_ne!(
        fixture.request(&format!("/r/maven/{PATH}"), false).await.0,
        StatusCode::OK
    );
    sqlx::query("DELETE FROM evidence WHERE subject=$1")
        .bind(&artifact.digest)
        .execute(&fixture.store.pool)
        .await
        .unwrap();
    let mut large = fixture.evidence(
        &artifact,
        "inventory",
        Outcome::Pass,
        now,
        now + Duration::hours(1),
    );
    large.details = json!({"padding":"x".repeat(1024 * 1024)});
    fixture.commit(&artifact, vec![large; 33]).await;
    assert!(
        fixture
            .store
            .policy_evidence(&artifact.digest, &configuration)
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nanosecond_fingerprints_survive_authoritative_database_projection(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    let now = Utc::now();
    let created = DateTime::from_timestamp(now.timestamp() - 60, 123_456_789).unwrap();
    let expiry = DateTime::from_timestamp(now.timestamp() + 3600, 987_654_321).unwrap();
    let original = fixture.evidence(&artifact, "inventory", Outcome::Pass, created, expiry);
    let fingerprint = evidence_fingerprint(&original);
    fixture.commit(&artifact, vec![original]).await;
    let configuration = fixture
        .config
        .delivery_fingerprint(&artifact.scope())
        .unwrap();
    let projected = fixture
        .store
        .policy_evidence(&artifact.digest, &configuration)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(projected.created_at.timestamp_subsec_nanos(), 123_456_000);
    assert_eq!(projected.expires_at.timestamp_subsec_nanos(), 987_654_000);
    assert_eq!(evidence_fingerprint(&projected), fingerprint);
    sqlx::query("UPDATE evidence SET expires_at=expires_at-interval '1 second' WHERE subject=$1")
        .bind(&artifact.digest)
        .execute(&fixture.store.pool)
        .await
        .unwrap();
    let changed = fixture
        .store
        .policy_evidence(&artifact.digest, &configuration)
        .await
        .unwrap()
        .remove(0);
    assert_ne!(
        evidence_fingerprint(&changed),
        fingerprint,
        "real column validity changes must invalidate the generation binding"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stored_document_bindings_cannot_disagree_with_authoritative_columns(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, false);
    let artifact = fixture.proxy().await;
    fixture.generations(&artifact).await;
    assert_eq!(
        fixture.request(&format!("/r/maven/{PATH}"), false).await.0,
        StatusCode::OK
    );
    let original: Value = sqlx::query_scalar(
        "SELECT document FROM evidence WHERE subject=$1 AND check_name='inventory'",
    )
    .bind(&artifact.digest)
    .fetch_one(&fixture.store.pool)
    .await
    .unwrap();
    let configuration = fixture
        .config
        .delivery_fingerprint(&artifact.scope())
        .unwrap();
    for field in ["subject", "check", "configuration"] {
        let mut altered = original.clone();
        altered[field] = json!("forged-binding");
        sqlx::query("UPDATE evidence SET document=$1 WHERE subject=$2 AND check_name='inventory'")
            .bind(altered)
            .bind(&artifact.digest)
            .execute(&fixture.store.pool)
            .await
            .unwrap();
        assert!(
            fixture
                .store
                .policy_evidence(&artifact.digest, &configuration)
                .await
                .is_err(),
            "{field}"
        );
        assert!(
            fixture
                .store
                .evidence_history(&artifact.digest, &configuration)
                .await
                .is_err(),
            "{field}"
        );
        assert_ne!(
            fixture.request(&format!("/r/maven/{PATH}"), false).await.0,
            StatusCode::OK,
            "{field}"
        );
    }
}
