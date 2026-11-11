//! Publication state is independent of mutable security approval.
use chrono::{Duration, Utc};
use packweir::{
    config::{Config, RepositoryKind},
    hosted::{self, HostedError, StageState},
    identity,
    model::{Artifact, Decision, Ecosystem, Evidence, Outcome, sha256},
    store::Store,
};
use serde_json::json;
use sqlx::Row;
use std::{path::Path, sync::Arc};
use uuid::Uuid;

fn config() -> Config {
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    let mut repository = config.repositories["maven"].clone();
    repository.kind = RepositoryKind::Hosted;
    repository.upstream = None;
    repository.download_origins.clear();
    repository.token_env = None;
    repository.cargo_download_template = None;
    repository.cache_max_age_seconds = None;
    repository.retain = true;
    config.repositories.insert("releases".into(), repository);
    config
}
fn package() -> identity::PackageIdentity {
    let mut package =
        identity::from_coordinates(Ecosystem::Maven, "dev.packweir:fixture", "1.0.0").unwrap();
    package.basis = "hosted_coordinates_declared".into();
    package
}
fn file(config: &Config, extension: &str, bytes: &[u8]) -> (String, Artifact) {
    let path = format!("dev/packweir/fixture/1.0.0/fixture-1.0.0.{extension}");
    let filename = path.rsplit('/').next().unwrap().into();
    (
        path.clone(),
        Artifact {
            repository: "releases".into(),
            origin: config
                .public_url
                .join(&format!("r/releases/{path}"))
                .unwrap()
                .into(),
            digest: sha256(bytes),
            size: bytes.len() as i64,
            filename,
            content_type: "application/octet-stream".into(),
            package: Some(package()),
        },
    )
}
async fn populated(store: &Store, config: &Config) -> (Uuid, Vec<(String, Artifact)>) {
    let id = Uuid::new_v4();
    hosted::create_stage(store, id, "releases", package(), "publisher")
        .await
        .unwrap();
    let files = vec![
        file(config, "pom", b"POM fixture"),
        file(config, "jar", b"archive fixture"),
    ];
    for (path, artifact) in &files {
        hosted::add_file(store, id, artifact.clone(), path, "publisher")
            .await
            .unwrap();
    }
    (id, files)
}
async fn approve_jobs(store: &Store, config: &Config, ttl: Duration) {
    while let Some(job) = store.lease(&config.fingerprint(), 60).await.unwrap() {
        let scope = store.job_scope(job.id).await.unwrap().unwrap();
        let policy = config.effective_policy(&scope).unwrap();
        let now = Utc::now();
        let evidence: Vec<_> = policy
            .policy
            .required
            .iter()
            .map(|check| Evidence {
                subject: job.subject.clone(),
                configuration: job.configuration.clone(),
                check: check.clone(),
                tool_version: "fixture".into(),
                outcome: Outcome::Pass,
                created_at: now,
                expires_at: now + ttl,
                details: json!({"fixture":true}),
                references: vec![],
            })
            .collect();
        store.complete(&job, &evidence).await.unwrap();
    }
}
async fn wait_for_context_waiter(store: &Store) {
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE%')").fetch_one(&store.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("promotion should wait for context lock");
}

#[sqlx::test(migrations = "./migrations")]
async fn reservations_idempotency_and_revocation_never_allow_coordinate_replacement(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let id = Uuid::new_v4();
    let first = hosted::create_stage(&store, id, "releases", package(), "publisher")
        .await
        .unwrap();
    assert_eq!(
        hosted::create_stage(&store, id, "releases", package(), "publisher")
            .await
            .unwrap()
            .id,
        first.id
    );
    assert!(matches!(
        hosted::create_stage(&store, id, "releases", package(), "other").await,
        Err(HostedError::Conflict(_))
    ));
    let mut changed = package();
    changed.version = "2.0.0".into();
    changed =
        identity::from_coordinates(Ecosystem::Maven, &changed.name, &changed.version).unwrap();
    changed.basis = "hosted_coordinates_declared".into();
    assert!(matches!(
        hosted::create_stage(&store, id, "releases", changed, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    hosted::revoke(&store, id, "promoter").await.unwrap();
    assert!(matches!(
        hosted::create_stage(&store, Uuid::new_v4(), "releases", package(), "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='hosted_stage_created'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(events, 1);
    // Two independent connections cannot both reserve one coordinate, even with different IDs.
    let mut other = package();
    other = identity::from_coordinates(Ecosystem::Maven, &other.name, "3.0.0").unwrap();
    other.basis = "hosted_coordinates_declared".into();
    let (a, b) = tokio::join!(
        hosted::create_stage(
            &store,
            Uuid::new_v4(),
            "releases",
            other.clone(),
            "publisher"
        ),
        hosted::create_stage(&store, Uuid::new_v4(), "releases", other, "publisher")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn uploads_are_owner_bound_immutable_and_atomically_sealed_with_final_scope_jobs(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let id = Uuid::new_v4();
    hosted::create_stage(&store, id, "releases", package(), "publisher")
        .await
        .unwrap();
    assert!(matches!(
        hosted::seal(&store, id, &config, "promoter").await,
        Err(HostedError::Invalid(_))
    ));
    let (path, artifact) = file(&config, "jar", b"archive");
    assert!(matches!(
        hosted::add_file(&store, id, artifact.clone(), &path, "other").await,
        Err(HostedError::Conflict(_))
    ));
    hosted::add_file(&store, id, artifact.clone(), &path, "publisher")
        .await
        .unwrap();
    hosted::add_file(&store, id, artifact.clone(), &path, "publisher")
        .await
        .unwrap();
    let mut replaced = artifact.clone();
    replaced.digest = sha256(b"substitution");
    assert!(matches!(
        hosted::add_file(&store, id, replaced, &path, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    assert!(
        hosted::add_file(
            &store,
            id,
            artifact.clone(),
            "dev/packweir/fixture/1.0.0/../escape.jar",
            "publisher"
        )
        .await
        .is_err()
    );
    assert!(
        hosted::published_file(&store, "releases", &path)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        hosted::seal(&store, id, &config, "promoter").await,
        Err(HostedError::Invalid(_))
    ));
    let (pom, pom_artifact) = file(&config, "pom", b"POM");
    hosted::add_file(&store, id, pom_artifact, &pom, "publisher")
        .await
        .unwrap();
    let sealed = hosted::seal(&store, id, &config, "promoter").await.unwrap();
    assert_eq!(sealed.stage.state, StageState::Sealed);
    assert_eq!(sealed.manifest.files.len(), 2);
    assert_eq!(
        sha256(&serde_json::to_vec(&sealed.manifest).unwrap()),
        sealed.manifest_digest
    );
    assert_eq!(
        hosted::seal(&store, id, &config, "promoter")
            .await
            .unwrap()
            .manifest_digest,
        sealed.manifest_digest
    );
    assert!(matches!(
        hosted::add_file(&store, id, artifact.clone(), &path, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    assert_eq!(
        store
            .artifact("releases", &artifact.origin)
            .await
            .unwrap()
            .unwrap()
            .digest,
        artifact.digest
    );
    let jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE scope->>'repository'='releases'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(jobs, 2);
    let row = sqlx::query("SELECT configuration,scope FROM jobs WHERE subject=$1")
        .bind(&artifact.digest)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        row.get::<String, _>("configuration"),
        config.delivery_fingerprint(&artifact.scope()).unwrap()
    );
    assert_eq!(
        row.get::<serde_json::Value, _>("scope"),
        serde_json::to_value(artifact.scope()).unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn promotion_binds_all_current_evidence_and_reads_recheck_the_whole_release(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (id, files) = populated(&store, &config).await;
    hosted::seal(&store, id, &config, "promoter").await.unwrap();
    assert!(matches!(
        hosted::promote(&store, id, &config, "promoter").await,
        Err(HostedError::NotApproved(_))
    ));
    assert!(
        hosted::delivery(&store, "releases", &files[0].0, &config)
            .await
            .unwrap()
            .is_none()
    );
    approve_jobs(&store, &config, Duration::hours(1)).await;
    let receipt = hosted::promote(&store, id, &config, "promoter")
        .await
        .unwrap();
    assert_eq!(receipt.stage.state, StageState::Published);
    assert_eq!(receipt.files.len(), 2);
    assert_eq!(receipt.actor, "promoter");
    assert!(matches!(
        hosted::abort(&store, id, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    for file in &receipt.files {
        assert!(!file.evidence.is_empty());
        assert_eq!(
            sha256(&serde_json::to_vec(&file.evidence).unwrap()),
            file.evidence_digest
        );
        assert!(
            file.evidence
                .iter()
                .all(|e| e["id"].is_string() && e["document"]["subject"] == file.subject)
        );
    }
    assert!(matches!(
        hosted::promote(&store, id, &config, "promoter").await,
        Err(HostedError::Conflict(_))
    ));
    assert_eq!(
        hosted::published_versions(&store, "releases", &package().name)
            .await
            .unwrap(),
        vec!["1.0.0"]
    );
    assert_eq!(
        hosted::delivery(&store, "releases", &files[0].0, &config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Approved
    );
    // Invalidating JAR observations blocks the POM too: a published release is one sealed set.
    store.invalidate(&files[1].1.digest).await.unwrap();
    assert!(matches!(
        hosted::delivery(&store, "releases", &files[0].0, &config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Pending(_)
    ));
    let mut changed = config.clone();
    changed.policy.revision = "changed-policy".into();
    assert!(matches!(
        hosted::delivery(&store, "releases", &files[0].0, &changed)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Pending(_)
    ));
    hosted::revoke(&store, id, "promoter").await.unwrap();
    assert!(matches!(
        hosted::abort(&store, id, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    assert!(
        hosted::published_file(&store, "releases", &files[0].0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        hosted::delivery(&store, "releases", &files[0].0, &config)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        hosted::published_versions(&store, "releases", &package().name)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        hosted::promote(&store, id, &config, "promoter").await,
        Err(HostedError::Conflict(_))
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_seal_rolls_back_bindings_jobs_and_audit_and_rejects_forged_origins(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (id, files) = populated(&store, &config).await;
    store.register(&files[1].1).await.unwrap();
    assert!(matches!(
        hosted::seal(&store, id, &config, "promoter").await,
        Err(HostedError::Conflict(_))
    ));
    assert_eq!(
        hosted::stage(&store, id).await.unwrap().state,
        StageState::Open
    );
    assert!(
        store
            .artifact("releases", &files[0].1.origin)
            .await
            .unwrap()
            .is_none()
    );
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(jobs, 0);
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='hosted_stage_sealed'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(events, 0);
    // A forged final delivery URL cannot be made authoritative by sealing it.
    let other = Uuid::new_v4();
    hosted::create_stage(&store, other, "other", package(), "publisher")
        .await
        .unwrap();
    let mut artifact = files[0].1.clone();
    artifact.repository = "other".into();
    artifact.origin = "https://attacker.invalid/substituted.pom".into();
    hosted::add_file(&store, other, artifact, &files[0].0, "publisher")
        .await
        .unwrap();
    let mut other_config = config.clone();
    other_config.repositories.insert(
        "other".into(),
        other_config.repositories["releases"].clone(),
    );
    assert!(matches!(
        hosted::seal(&store, other, &other_config, "promoter").await,
        Err(HostedError::Invalid(_))
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_context_and_expiry_while_waiting_for_locks_cannot_promote(pool: sqlx::PgPool) {
    let store = Store { pool };
    let config = Arc::new(config());
    let (id, files) = populated(&store, &config).await;
    hosted::seal(&store, id, &config, "promoter").await.unwrap();
    approve_jobs(&store, &config, Duration::hours(1)).await;
    let mut tx = store.pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
        .bind(&files[0].1.digest)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let attempt = {
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move { hosted::promote(&store, id, &config, "promoter").await })
    };
    wait_for_context_waiter(&store).await;
    sqlx::query("UPDATE contexts SET revision=revision+1 WHERE subject=$1")
        .bind(&files[0].1.digest)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        attempt.await.unwrap(),
        Err(HostedError::NotApproved(_))
    ));
    // Give every current context new evidence, but let it expire while promotion waits.
    for (_, artifact) in &files {
        store
            .enqueue_delivery(
                artifact,
                &config.delivery_fingerprint(&artifact.scope()).unwrap(),
                &config.fingerprint(),
            )
            .await
            .unwrap();
    }
    approve_jobs(&store, &config, Duration::seconds(2)).await;
    let mut tx = store.pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
        .bind(&files[0].1.digest)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let attempt = {
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move { hosted::promote(&store, id, &config, "promoter").await })
    };
    wait_for_context_waiter(&store).await;
    tokio::time::sleep(std::time::Duration::from_millis(2250)).await;
    tx.commit().await.unwrap();
    assert!(matches!(
        attempt.await.unwrap(),
        Err(HostedError::NotApproved(_))
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_promotions_publish_once_and_same_digest_members_keep_separate_scopes(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let id = Uuid::new_v4();
    hosted::create_stage(&store, id, "releases", package(), "publisher")
        .await
        .unwrap();
    for extension in ["pom", "jar"] {
        let (path, artifact) = file(&config, extension, b"shared content");
        hosted::add_file(&store, id, artifact, &path, "publisher")
            .await
            .unwrap();
    }
    hosted::seal(&store, id, &config, "promoter").await.unwrap();
    approve_jobs(&store, &config, Duration::hours(1)).await;
    let (a, b) = tokio::join!(
        hosted::promote(&store, id, &config, "first-promoter"),
        hosted::promote(&store, id, &config, "second-promoter")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let receipt = a.or(b).unwrap();
    assert_eq!(receipt.files[0].subject, receipt.files[1].subject);
    assert_ne!(
        receipt.files[0].configuration,
        receipt.files[1].configuration
    );
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='hosted_stage_published'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(events, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn release_size_limits_are_checked_before_binding_more_files(pool: sqlx::PgPool) {
    let store = Store { pool };
    let config = config();
    let id = Uuid::new_v4();
    hosted::create_stage(&store, id, "releases", package(), "publisher")
        .await
        .unwrap();
    for extension in ["pom", "jar", "zip", "war"] {
        let (path, mut artifact) = file(&config, extension, b"fixture");
        artifact.size = 128 * 1024 * 1024;
        hosted::add_file(&store, id, artifact, &path, "publisher")
            .await
            .unwrap();
    }
    let (path, mut artifact) = file(&config, "ear", b"fixture");
    artifact.size = 1;
    assert!(matches!(
        hosted::add_file(&store, id, artifact, &path, "publisher").await,
        Err(HostedError::Invalid(_))
    ));
    assert_eq!(hosted::stage_files(&store, id).await.unwrap().len(), 4);
}

#[sqlx::test(migrations = "./migrations")]
async fn store_uses_the_protocol_grammar_and_cannot_seal_sidecars_or_coordinate_claim_aliases(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    for version in ["LATEST", "RELEASE", "1.0-SNAPSHOT"] {
        let mut invalid =
            identity::from_coordinates(Ecosystem::Maven, &package().name, version).unwrap();
        invalid.basis = "hosted_coordinates_declared".into();
        assert!(matches!(
            hosted::create_stage(&store, Uuid::new_v4(), "releases", invalid, "publisher").await,
            Err(HostedError::Invalid(_))
        ));
    }
    let mut claimed = package();
    claimed.basis = "registry_metadata_observed".into();
    assert!(matches!(
        hosted::create_stage(&store, Uuid::new_v4(), "releases", claimed, "publisher").await,
        Err(HostedError::Invalid(_))
    ));
    let id = Uuid::new_v4();
    hosted::create_stage(&store, id, "releases", package(), "publisher")
        .await
        .unwrap();
    let (_, template) = file(&config, "pom", b"fixture");
    for path in [
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.pom.sha256",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0.jar..extra",
        "dev/packweir/fixture/1.0.0/fixture-1.0.0-_sources.jar",
        "dev/packweir/fixture/maven-metadata.xml",
        "dev.packweir/fixture/1.0.0/fixture-1.0.0.pom",
    ] {
        let mut artifact = template.clone();
        artifact.filename = path.rsplit('/').next().unwrap().into();
        artifact.origin = config
            .public_url
            .join(&format!("r/releases/{path}"))
            .unwrap()
            .into();
        assert!(
            matches!(
                hosted::add_file(&store, id, artifact, path, "publisher").await,
                Err(HostedError::Invalid(_))
            ),
            "unexpectedly bound {path}"
        );
    }
    assert!(hosted::stage_files(&store, id).await.unwrap().is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn abort_preserves_stage_history_but_allows_new_uuid_coordinate_reservation(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (id, files) = populated(&store, &config).await;
    assert!(matches!(
        hosted::abort(&store, id, "other-writer").await,
        Err(HostedError::Conflict(_))
    ));
    assert_eq!(
        hosted::stage(&store, id).await.unwrap().state,
        StageState::Open
    );
    let aborted = hosted::abort(&store, id, "publisher").await.unwrap();
    assert_eq!(aborted.state, StageState::Aborted);
    assert!(aborted.aborted_at.is_some());
    assert_eq!(
        hosted::abort(&store, id, "publisher")
            .await
            .unwrap()
            .aborted_at,
        aborted.aborted_at
    );
    assert_eq!(hosted::stage_files(&store, id).await.unwrap().len(), 2);
    for operation in [
        hosted::seal(&store, id, &config, "promoter")
            .await
            .map(|_| ()),
        hosted::promote(&store, id, &config, "promoter")
            .await
            .map(|_| ()),
        hosted::revoke(&store, id, "promoter").await.map(|_| ()),
    ] {
        assert!(matches!(operation, Err(HostedError::Conflict(_))));
    }
    assert!(matches!(
        hosted::add_file(&store, id, files[0].1.clone(), &files[0].0, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    let replacement_id = Uuid::new_v4();
    let replacement =
        hosted::create_stage(&store, replacement_id, "releases", package(), "publisher")
            .await
            .unwrap();
    assert_eq!(replacement.state, StageState::Open);
    assert_ne!(replacement.id, id);
    assert_eq!(
        hosted::create_stage(&store, id, "releases", package(), "publisher")
            .await
            .unwrap()
            .state,
        StageState::Aborted
    );
    assert!(matches!(
        hosted::create_stage(&store, id, "releases", package(), "different-owner").await,
        Err(HostedError::Conflict(_))
    ));
    let abort_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action='hosted_stage_aborted' AND subject=$1",
    )
    .bind(id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(abort_events, 1);
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM hosted_files WHERE stage_id=$1")
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(retained, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn abort_and_seal_race_has_one_terminal_result_and_no_partial_registration(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (id, _) = populated(&store, &config).await;
    let (aborted, sealed) = tokio::join!(
        hosted::abort(&store, id, "publisher"),
        hosted::seal(&store, id, &config, "promoter")
    );
    assert_eq!(
        usize::from(aborted.is_ok()) + usize::from(sealed.is_ok()),
        1
    );
    let final_stage = hosted::stage(&store, id).await.unwrap();
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let artifacts: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM audit WHERE subject=$1 AND action IN ('hosted_stage_aborted','hosted_stage_sealed')").bind(id.to_string()).fetch_one(&store.pool).await.unwrap();
    assert_eq!(events, 1);
    match final_stage.state {
        StageState::Aborted => {
            assert!(final_stage.manifest_digest.is_none());
            assert_eq!(jobs, 0);
            assert_eq!(artifacts, 0);
            hosted::create_stage(&store, Uuid::new_v4(), "releases", package(), "publisher")
                .await
                .unwrap();
        }
        StageState::Sealed => {
            assert!(final_stage.manifest_digest.is_some());
            assert_eq!(jobs, 2);
            assert_eq!(artifacts, 2);
            assert!(matches!(
                hosted::create_stage(&store, Uuid::new_v4(), "releases", package(), "publisher")
                    .await,
                Err(HostedError::Conflict(_))
            ));
            assert!(matches!(
                hosted::abort(&store, id, "publisher").await,
                Err(HostedError::Conflict(_))
            ));
        }
        state => panic!("invalid race outcome: {state:?}"),
    }
}
