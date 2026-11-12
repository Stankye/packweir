//! Cross-repository copies create new quarantine scopes, never transferred approvals.
use chrono::{Duration, Utc};
use packweir::{
    access::MavenOwnership,
    config::{Config, RepositoryKind},
    hosted::{self, CopyRequest, HostedError, StageState},
    maven::Coordinate,
    model::{Artifact, Decision, Evidence, Outcome, sha256},
    policy::PolicyRequirements,
    store::Store,
};
use serde_json::json;
use std::{path::Path, sync::Arc, time::Duration as Wait};
use uuid::Uuid;

const NAME: &str = "dev.copy:fixture";

fn config() -> Config {
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    let mut repository = config.repositories["maven"].clone();
    repository.kind = RepositoryKind::Hosted;
    repository.upstream = None;
    repository.download_origins.clear();
    repository.token_env = None;
    repository.cache_max_age_seconds = None;
    repository.cargo_download_template = None;
    repository.retain = true;
    config.repositories.clear();
    for name in ["dev", "other"] {
        config.repositories.insert(name.into(), repository.clone());
    }
    repository.policy = Some(PolicyRequirements {
        revision: "production-review-v1".into(),
        required: vec!["release_review".into()],
        deny_on_failure: vec!["release_review".into()],
        agent_escalation: None,
    });
    config.repositories.insert("prod".into(), repository);
    config.access.maven_owners = vec![MavenOwnership {
        namespace: "dev.copy".into(),
        repository: "dev".into(),
        additional_repositories: vec!["prod".into(), "other".into()],
    }];
    config
}
fn artifact(config: &Config, repository: &str, extension: &str) -> (String, Artifact) {
    let coordinate = Coordinate::new(NAME, "1.0.0").unwrap();
    let path = format!("{}.{extension}", coordinate.artifact_prefix());
    let bytes = format!("immutable {extension} fixture");
    (
        path.clone(),
        Artifact {
            repository: repository.into(),
            origin: config
                .public_url
                .join(&format!("r/{repository}/{path}"))
                .unwrap()
                .into(),
            digest: sha256(bytes.as_bytes()),
            size: bytes.len() as i64,
            filename: path.rsplit('/').next().unwrap().into(),
            content_type: "application/octet-stream".into(),
            package: Some(coordinate.package()),
        },
    )
}
async fn complete_jobs(store: &Store, config: &Config, ttl: Duration, review: Outcome) {
    while let Some(job) = store.lease(&config.fingerprint(), 60).await.unwrap() {
        let scope = store.job_scope(job.id).await.unwrap().unwrap();
        let now = Utc::now();
        let findings: Vec<_> = config.effective_policy(&scope).unwrap().policy.required.iter().map(|check| Evidence {
            subject:job.subject.clone(),configuration:job.configuration.clone(),check:check.clone(),tool_version:"trusted-store-fixture".into(),
            created_at:now,expires_at:now+ttl,outcome:if check=="release_review" { review } else { Outcome::Pass },
            details:json!({"fixture_repository":scope.repository,"private_assessment":"preserved for administrators"}),references:vec![],
        }).collect();
        store.complete(&job, &findings).await.unwrap();
    }
}
async fn published(
    store: &Store,
    config: &Config,
    repository: &str,
    ttl: Duration,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    hosted::create_stage(
        store,
        id,
        repository,
        Coordinate::new(NAME, "1.0.0").unwrap().package(),
        "publisher",
    )
    .await
    .unwrap();
    for extension in ["pom", "jar"] {
        let (path, artifact) = artifact(config, repository, extension);
        hosted::add_file(store, id, artifact, &path, "publisher")
            .await
            .unwrap();
    }
    let sealed = hosted::seal(store, id, config, "publisher").await.unwrap();
    complete_jobs(store, config, ttl, Outcome::Pass).await;
    hosted::promote(store, id, config, "promoter")
        .await
        .unwrap();
    (id, sealed.manifest_digest)
}
fn copy_request(manifest: &str) -> CopyRequest {
    CopyRequest {
        id: Uuid::new_v4(),
        destination_repository: "prod".into(),
        source_manifest_digest: manifest.into(),
    }
}
async fn evidence_count(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM evidence")
        .fetch_one(&store.pool)
        .await
        .unwrap()
}
async fn assert_no_copy(store: &Store, id: Uuid) {
    assert!(matches!(
        hosted::stage(store, id).await,
        Err(HostedError::NotFound)
    ));
    assert!(hosted::lineage(store, id).await.unwrap().is_none());
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM hosted_files WHERE stage_id=$1")
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE subject=$1")
        .bind(id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let target_jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE scope->>'repository'='prod'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!((files, events, target_jobs), (0, 0, 0));
}
async fn wait_for_lock(store: &Store, query: &str) {
    tokio::time::timeout(Wait::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                .bind(query).fetch_one(&store.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Wait::from_millis(10)).await;
        }
    }).await.expect("copy must reach the held database lock");
}

#[sqlx::test(migrations = "./migrations")]
async fn copy_preserves_every_member_but_requires_new_destination_evidence(pool: sqlx::PgPool) {
    let store = Store { pool };
    let config = config();
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let before = evidence_count(&store).await;
    let request = copy_request(&manifest);
    let copied = hosted::copy_release(&store, source, &config, &request, "copier")
        .await
        .unwrap();
    assert_eq!(copied.destination.stage.state, StageState::Sealed);
    assert_eq!(copied.source_stage, source);
    assert_eq!(copied.actor, "copier");
    assert_ne!(copied.destination.manifest_digest, manifest);
    assert_eq!(
        before,
        evidence_count(&store).await,
        "copy must insert zero evidence rows"
    );
    let original = hosted::stage_files(&store, source).await.unwrap();
    let target = hosted::stage_files(&store, request.id).await.unwrap();
    assert_eq!(original.len(), target.len());
    for (old, new) in original.iter().zip(&target) {
        assert_eq!(old.path, new.path);
        let mut expected = serde_json::to_value(&old.artifact).unwrap();
        expected["repository"] = json!("prod");
        expected["origin"] = json!(
            config
                .public_url
                .join(&format!("r/prod/{}", old.path))
                .unwrap()
                .as_str()
        );
        assert_eq!(expected, serde_json::to_value(&new.artifact).unwrap());
        let fingerprint = config.delivery_fingerprint(&new.artifact.scope()).unwrap();
        assert_ne!(
            fingerprint,
            config.delivery_fingerprint(&old.artifact.scope()).unwrap()
        );
        assert!(
            store
                .evidence(&new.artifact.digest, &fingerprint)
                .await
                .unwrap()
                .is_empty()
        );
    }
    for proof in &copied.source_files {
        assert_eq!(
            proof.evidence_digest,
            sha256(&serde_json::to_vec(&proof.evidence).unwrap())
        );
        assert!(
            proof
                .evidence
                .iter()
                .all(|e| e["document"]["details"]["fixture_repository"] == "dev")
        );
    }
    assert!(matches!(
        hosted::promote(&store, request.id, &config, "promoter").await,
        Err(HostedError::NotApproved(_))
    ));
    complete_jobs(&store, &config, Duration::hours(1), Outcome::Fail).await;
    assert!(matches!(
        hosted::promote(&store, request.id, &config, "promoter").await,
        Err(HostedError::NotApproved(_))
    ));
    for member in &target {
        store
            .enqueue_delivery(
                &member.artifact,
                &config
                    .delivery_fingerprint(&member.artifact.scope())
                    .unwrap(),
                &config.fingerprint(),
            )
            .await
            .unwrap();
    }
    complete_jobs(&store, &config, Duration::hours(1), Outcome::Pass).await;
    let promoted = hosted::promote(&store, request.id, &config, "promoter")
        .await
        .unwrap();
    assert!(promoted.files.iter().all(|proof| {
        proof
            .evidence
            .iter()
            .all(|e| e["document"]["details"]["fixture_repository"] == "prod")
    }));
    assert_eq!(
        hosted::delivery(&store, "prod", &target[0].path, &config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Approved
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn source_policy_manifest_and_corrupt_identity_cannot_leave_partial_target_state(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let count = evidence_count(&store).await;
    let mut changed = config.clone();
    changed.policy.revision = "new-security-policy".into();
    let attempt = copy_request(&manifest);
    assert!(matches!(
        hosted::copy_release(&store, source, &changed, &attempt, "copier").await,
        Err(HostedError::NotApproved(_))
    ));
    assert_no_copy(&store, attempt.id).await;
    let wrong = copy_request(&"0".repeat(64));
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &wrong, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    assert_no_copy(&store, wrong.id).await;
    let files = hosted::stage_files(&store, source).await.unwrap();
    let mut malformed = files[0].artifact.clone();
    malformed.package.as_mut().unwrap().purl = "pkg:maven/attacker/substitution@1.0.0".into();
    sqlx::query("UPDATE hosted_files SET artifact=$3 WHERE stage_id=$1 AND path=$2")
        .bind(source)
        .bind(&files[0].path)
        .bind(serde_json::to_value(malformed).unwrap())
        .execute(&store.pool)
        .await
        .unwrap();
    let corrupt = copy_request(&manifest);
    assert!(
        hosted::copy_release(&store, source, &config, &corrupt, "copier")
            .await
            .is_err()
    );
    assert_no_copy(&store, corrupt.id).await;
    assert_eq!(count, evidence_count(&store).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn destination_id_coordinate_and_url_conflicts_never_overwrite_or_partially_register(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let occupied = Uuid::new_v4();
    hosted::create_stage(
        &store,
        occupied,
        "prod",
        Coordinate::new(NAME, "1.0.0").unwrap().package(),
        "copier",
    )
    .await
    .unwrap();
    let mut same_id = copy_request(&manifest);
    same_id.id = occupied;
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &same_id, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    let collision = copy_request(&manifest);
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &collision, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    assert_no_copy(&store, collision.id).await;
    hosted::abort(&store, occupied, "copier").await.unwrap();
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &same_id, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    let (_, mut existing) = artifact(&config, "prod", "pom");
    existing.digest = sha256(b"preexisting binding");
    store.register(&existing).await.unwrap();
    let partial = copy_request(&manifest);
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &partial, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    assert_no_copy(&store, partial.id).await;
    assert_eq!(
        store
            .artifact("prod", &existing.origin)
            .await
            .unwrap()
            .unwrap()
            .digest,
        existing.digest
    );
    let artifacts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository='prod'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(artifacts, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_is_request_bound_historical_and_cannot_revive_a_revoked_destination(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let request = copy_request(&manifest);
    let first = hosted::copy_release(&store, source, &config, &request, "copier")
        .await
        .unwrap();
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &request, "different-actor").await,
        Err(HostedError::Conflict(_))
    ));
    let mut changed = request.clone();
    changed.source_manifest_digest = "0".repeat(64);
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &changed, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    changed = request.clone();
    changed.destination_repository = "other".into();
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &changed, "copier").await,
        Err(HostedError::Conflict(_))
    ));
    hosted::revoke(&store, source, "promoter").await.unwrap();
    let replay = hosted::copy_release(&store, source, &config, &request, "copier")
        .await
        .unwrap();
    assert_eq!(replay.created_at, first.created_at);
    assert_eq!(replay.source_evaluated_at, first.source_evaluated_at);
    assert_eq!(replay.destination.stage.state, StageState::Sealed);
    complete_jobs(&store, &config, Duration::hours(1), Outcome::Pass).await;
    hosted::promote(&store, request.id, &config, "promoter")
        .await
        .unwrap();
    assert_eq!(
        hosted::copy_release(&store, source, &config, &request, "copier")
            .await
            .unwrap()
            .destination
            .stage
            .state,
        StageState::Published
    );
    hosted::revoke(&store, request.id, "promoter")
        .await
        .unwrap();
    assert_eq!(
        hosted::copy_release(&store, source, &config, &request, "copier")
            .await
            .unwrap()
            .destination
            .stage
            .state,
        StageState::Revoked
    );
    assert_eq!(
        hosted::stage(&store, request.id).await.unwrap().state,
        StageState::Revoked
    );
    let copies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action='hosted_release_copied' AND subject=$1",
    )
    .bind(request.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(copies, 1);
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE state='queued'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(queued, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn source_evidence_expiring_during_destination_origin_lock_wait_rolls_back_everything(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = Arc::new(config());
    let (source, manifest) = published(&store, &config, "dev", Duration::seconds(3)).await;
    let request = copy_request(&manifest);
    let target_id = request.id;
    let (path, _) = artifact(&config, "prod", "jar");
    let origin = config
        .public_url
        .join(&format!("r/prod/{path}"))
        .unwrap()
        .to_string();
    let mut tx = store.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(serde_json::to_string(&("prod", origin)).unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();
    let task = {
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move {
            hosted::copy_release(&store, source, &config, &request, "copier").await
        })
    };
    wait_for_lock(
        &store,
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))%",
    )
    .await;
    tokio::time::sleep(Wait::from_millis(3250)).await;
    tx.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(HostedError::NotApproved(_))
    ));
    assert_no_copy(&store, target_id).await;
    assert_eq!(
        hosted::stage(&store, source).await.unwrap().state,
        StageState::Published
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn committed_source_revoke_and_context_invalidation_win_before_copy_grants(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = Arc::new(config());
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let request = copy_request(&manifest);
    let target_id = request.id;
    let mut tx = store.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM hosted_stages WHERE id=$1 FOR UPDATE")
        .bind(source)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let task = {
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move {
            hosted::copy_release(&store, source, &config, &request, "copier").await
        })
    };
    wait_for_lock(&store, "SELECT * FROM hosted_stages WHERE id=ANY($1)%").await;
    sqlx::query(
        "UPDATE hosted_stages SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1",
    )
    .bind(source)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(HostedError::Conflict(_))));
    assert_no_copy(&store, target_id).await;
    let (second, manifest) = published(&store, &config, "other", Duration::hours(1)).await;
    let request = copy_request(&manifest);
    let target_id = request.id;
    let files = hosted::stage_files(&store, second).await.unwrap();
    let mut tx = store.pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
        .bind(&files[0].artifact.digest)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let task = {
        let store = store.clone();
        let config = config.clone();
        tokio::spawn(async move {
            hosted::copy_release(&store, second, &config, &request, "copier").await
        })
    };
    wait_for_lock(&store, "%contexts%").await;
    sqlx::query("UPDATE contexts SET revision=revision+1 WHERE subject=$1")
        .bind(&files[0].artifact.digest)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(HostedError::NotApproved(_))
    ));
    assert_no_copy(&store, target_id).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_duplicate_and_opposite_uuid_operations_complete_without_rescanning(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let request = copy_request(&manifest);
    let (a, b) = tokio::time::timeout(Wait::from_secs(10), async {
        tokio::join!(
            hosted::copy_release(&store, source, &config, &request, "copier"),
            hosted::copy_release(&store, source, &config, &request, "copier")
        )
    })
    .await
    .expect("duplicate copies must serialize");
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.created_at, b.created_at);
    assert_eq!(a.destination.manifest_digest, b.destination.manifest_digest);
    let copies: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='hosted_release_copied'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(copies, 1);
    let jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE scope->>'repository'='prod'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(jobs, 2);
    let attempts: Vec<i32> =
        sqlx::query_scalar("SELECT attempts FROM jobs WHERE scope->>'repository'='prod'")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    assert!(attempts.iter().all(|a| *a == 0));
    let ((), revoked) = tokio::time::timeout(Wait::from_secs(10), async {
        tokio::join!(
            async {
                for _ in 0..12 {
                    let copy = hosted::lineage(&store, request.id).await.unwrap().unwrap();
                    assert!(matches!(
                        copy.destination.stage.state,
                        StageState::Sealed | StageState::Revoked
                    ));
                }
            },
            hosted::revoke(&store, request.id, "promoter")
        )
    })
    .await
    .expect("lineage readers and revocation cannot deadlock");
    revoked.unwrap();
    let (other, other_manifest) = published(&store, &config, "other", Duration::hours(1)).await;
    let left = CopyRequest {
        id: other,
        destination_repository: "other".into(),
        source_manifest_digest: manifest,
    };
    let right = CopyRequest {
        id: source,
        destination_repository: "dev".into(),
        source_manifest_digest: other_manifest,
    };
    let (a, b) = tokio::time::timeout(Wait::from_secs(10), async {
        tokio::join!(
            hosted::copy_release(&store, source, &config, &left, "copier"),
            hosted::copy_release(&store, other, &config, &right, "copier")
        )
    })
    .await
    .expect("opposite UUID requests must take the same row order");
    assert!(matches!(a, Err(HostedError::Conflict(_))));
    assert!(matches!(b, Err(HostedError::Conflict(_))));
}

#[sqlx::test(migrations = "./migrations")]
async fn lineage_rejects_mismatched_persistent_bindings_and_manifest_tampering(pool: sqlx::PgPool) {
    let store = Store { pool };
    let config = config();
    let (source, manifest) = published(&store, &config, "dev", Duration::hours(1)).await;
    let request = copy_request(&manifest);
    let receipt = hosted::copy_release(&store, source, &config, &request, "copier")
        .await
        .unwrap();
    sqlx::query("UPDATE hosted_lineage SET actor='substituted' WHERE destination_stage_id=$1")
        .bind(request.id)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(matches!(
        hosted::lineage(&store, request.id).await,
        Err(HostedError::Internal(_))
    ));
    assert!(matches!(
        hosted::copy_release(&store, source, &config, &request, "copier").await,
        Err(HostedError::Internal(_))
    ));
    sqlx::query("UPDATE hosted_lineage SET actor='copier' WHERE destination_stage_id=$1")
        .bind(request.id)
        .execute(&store.pool)
        .await
        .unwrap();
    let original = serde_json::to_value(&receipt).unwrap();
    sqlx::query("UPDATE hosted_lineage SET created_at=created_at+interval '1 second' WHERE destination_stage_id=$1").bind(request.id).execute(&store.pool).await.unwrap();
    assert!(matches!(
        hosted::lineage(&store, request.id).await,
        Err(HostedError::Internal(_))
    ));
    sqlx::query("UPDATE hosted_lineage SET created_at=$2 WHERE destination_stage_id=$1")
        .bind(request.id)
        .bind(receipt.created_at)
        .execute(&store.pool)
        .await
        .unwrap();
    let mut changed_evidence = original.clone();
    changed_evidence["source_files"][0]["evidence"][0]["document"]["details"]["private_assessment"] =
        json!("substituted evidence content");
    sqlx::query("UPDATE hosted_lineage SET receipt=$2 WHERE destination_stage_id=$1")
        .bind(request.id)
        .bind(changed_evidence)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(matches!(
        hosted::lineage(&store, request.id).await,
        Err(HostedError::Internal(_))
    ));
    let mut corrupt = original.clone();
    corrupt["destination"]["manifest"]["files"][0]["artifact"]["digest"] = json!("0".repeat(64));
    sqlx::query("UPDATE hosted_lineage SET receipt=$2 WHERE destination_stage_id=$1")
        .bind(request.id)
        .bind(corrupt)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(matches!(
        hosted::lineage(&store, request.id).await,
        Err(HostedError::Internal(_))
    ));
    sqlx::query("UPDATE hosted_lineage SET receipt=$2,source_manifest_digest=$3 WHERE destination_stage_id=$1").bind(request.id).bind(original).bind("0".repeat(64)).execute(&store.pool).await.unwrap();
    assert!(matches!(
        hosted::lineage(&store, request.id).await,
        Err(HostedError::Internal(_))
    ));
}
