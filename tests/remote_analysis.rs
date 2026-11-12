use chrono::{Duration, Utc};
use packweir::{
    model::{Outcome, sha256},
    remote_analysis::{self as remote, Binding, State},
    scanner::ScannerOutput,
    store::{Job, Store},
};
use serde_json::json;
use sqlx::Row;

const CONFIGURATION: &str = "remote-analysis-fixture";

fn binding() -> Binding {
    Binding {
        check_name: "assemblyline".into(),
        service_fingerprint: sha256(b"endpoint and exact service/configuration pins"),
        request_digest: sha256(b"canonical submission request"),
        evidence_digest: sha256(b"canonical evidence bundle"),
    }
}

async fn job(store: &Store) -> Job {
    store
        .enqueue(
            &sha256(b"remote analysis artifact"),
            CONFIGURATION,
            "fixture.bin",
        )
        .await
        .unwrap();
    store.lease(CONFIGURATION, 60).await.unwrap().unwrap()
}

fn output() -> ScannerOutput {
    ScannerOutput {
        outcome: Outcome::Pass,
        details: json!({"complete":true,"services":[{"name":"fixture","version":"1"}]}),
        references: vec!["https://assemblyline.example/submission/fixture-sid".into()],
        valid_until: Some(Utc::now() + Duration::minutes(5)),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_workers_get_one_correlation_and_only_one_submission_permit(pool: sqlx::PgPool) {
    let store = Store { pool };
    let job = job(&store).await;
    let binding = binding();
    let (left, right) = tokio::join!(
        remote::prepare(&store, &job, &binding, 600),
        remote::prepare(&store, &job, &binding, 600)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.id, right.id);
    let (left, right) = tokio::join!(
        remote::begin_submit(&store, &job, &left),
        remote::begin_submit(&store, &job, &right)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn sid_and_absolute_result_validity_survive_worker_retry(pool: sqlx::PgPool) {
    let store = Store { pool };
    let first = job(&store).await;
    let prepared = remote::prepare(&store, &first, &binding(), 600)
        .await
        .unwrap();
    let permit = remote::begin_submit(&store, &first, &prepared)
        .await
        .unwrap();
    assert_eq!(permit.correlation_id, prepared.id);
    assert!(
        remote::begin_submit(&store, &first, &prepared)
            .await
            .is_err()
    );
    let submitted = remote::submitted(&store, &first, &prepared, &permit, "fixture-sid")
        .await
        .unwrap();
    let pending = remote::pending(&store, &first, &submitted, 1, Some("temporary GET failure"))
        .await
        .unwrap();
    assert_eq!(pending.poll_attempts, 1);
    assert_eq!(pending.poll_failures, 1);
    assert_eq!(pending.remote_id.as_deref(), Some("fixture-sid"));
    store.fail(&first).await.unwrap();
    let resumed_job = store.lease(CONFIGURATION, 60).await.unwrap().unwrap();
    let resumed = remote::prepare(&store, &resumed_job, &binding(), 600)
        .await
        .unwrap();
    assert_eq!(resumed.id, prepared.id);
    assert_eq!(resumed.created_at, prepared.created_at);
    assert_eq!(resumed.deadline_at, prepared.deadline_at);
    assert_eq!(resumed.state, State::Submitted);
    assert_eq!(resumed.remote_id.as_deref(), Some("fixture-sid"));
    assert!(
        remote::begin_submit(&store, &resumed_job, &resumed)
            .await
            .is_err()
    );
    let healthy = remote::pending(&store, &resumed_job, &resumed, 1, None)
        .await
        .unwrap();
    assert_eq!(healthy.poll_attempts, 2);
    assert_eq!(healthy.poll_failures, 0);
    let result = output();
    let completed = remote::complete(&store, &resumed_job, &healthy, &result)
        .await
        .unwrap();
    let replayed = remote::prepare(&store, &resumed_job, &binding(), 600)
        .await
        .unwrap();
    assert_eq!(replayed.state, State::Complete);
    assert_eq!(replayed.completed_at, completed.completed_at);
    assert_eq!(replayed.output.unwrap().valid_until, result.valid_until);
    assert!(
        remote::complete(&store, &resumed_job, &completed, &output())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn interrupted_post_is_ambiguous_until_current_request_is_reconciled(pool: sqlx::PgPool) {
    let store = Store { pool };
    let first = job(&store).await;
    let prepared = remote::prepare(&store, &first, &binding(), 600)
        .await
        .unwrap();
    remote::begin_submit(&store, &first, &prepared)
        .await
        .unwrap();
    // The process could have died after the remote accepted the POST. Local
    // recovery has no evidence that issuing another POST would be safe.
    store.fail(&first).await.unwrap();
    let resumed_job = store.lease(CONFIGURATION, 60).await.unwrap().unwrap();
    let resumed = remote::prepare(&store, &resumed_job, &binding(), 600)
        .await
        .unwrap();
    assert_eq!(resumed.state, State::Submitting);
    assert!(
        remote::begin_submit(&store, &resumed_job, &resumed)
            .await
            .is_err()
    );
    let ambiguous = remote::ambiguous(
        &store,
        &resumed_job,
        &resumed,
        "submission response was lost",
    )
    .await
    .unwrap();
    assert_eq!(ambiguous.state, State::Ambiguous);
    assert!(
        remote::reconcile(&store, ambiguous.id, &resumed_job.subject, "recovered-sid")
            .await
            .is_err()
    );
    store.complete(&resumed_job, &[]).await.unwrap();
    let reconciled = remote::reconcile(&store, ambiguous.id, &resumed_job.subject, "recovered-sid")
        .await
        .unwrap();
    assert_eq!(reconciled.state, State::Submitted);
    assert_eq!(reconciled.remote_id.as_deref(), Some("recovered-sid"));
    assert!(reconciled.completed_at.is_none());
    let next = store.lease(CONFIGURATION, 60).await.unwrap().unwrap();
    assert_eq!(next.id, resumed_job.id);
    let again = remote::prepare(&store, &next, &binding(), 600)
        .await
        .unwrap();
    assert_eq!(again.id, prepared.id);
    assert!(
        remote::reconcile(&store, again.id, &next.subject, "different-sid")
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='remote_analysis_reconciled'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn obsolete_context_cannot_attach_or_reconcile_remote_results(pool: sqlx::PgPool) {
    let store = Store { pool };
    let first = job(&store).await;
    let prepared = remote::prepare(&store, &first, &binding(), 600)
        .await
        .unwrap();
    let permit = remote::begin_submit(&store, &first, &prepared)
        .await
        .unwrap();
    store.invalidate(&first.subject).await.unwrap();
    assert!(
        remote::submitted(&store, &first, &prepared, &permit, "late-sid")
            .await
            .is_err()
    );
    assert!(
        remote::prepare(&store, &first, &binding(), 600)
            .await
            .is_err()
    );
    assert!(
        remote::save_checkpoint(&store, &first, &json!({"stale":true}))
            .await
            .is_err()
    );
    assert!(remote::defer(&store, &first, Utc::now()).await.is_err());
    store
        .enqueue(&first.subject, CONFIGURATION, "fixture.bin")
        .await
        .unwrap();
    let fresh_job = store.lease(CONFIGURATION, 60).await.unwrap().unwrap();
    assert_eq!(fresh_job.context_revision, first.context_revision + 1);
    let fresh = remote::prepare(&store, &fresh_job, &binding(), 600)
        .await
        .unwrap();
    assert_ne!(fresh.id, prepared.id);
    assert_eq!(fresh.state, State::Prepared);
    // Even an operator cannot bind an old intent to the replacement context.
    sqlx::query(
        "UPDATE remote_analysis SET state='ambiguous',completed_at=clock_timestamp() WHERE id=$1",
    )
    .bind(prepared.id)
    .execute(&store.pool)
    .await
    .unwrap();
    store.complete(&fresh_job, &[]).await.unwrap();
    assert!(
        remote::reconcile(&store, prepared.id, &first.subject, "late-sid")
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn lease_replacement_fences_submit_response_even_with_the_original_permit(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let first = job(&store).await;
    let prepared = remote::prepare(&store, &first, &binding(), 600)
        .await
        .unwrap();
    let permit = remote::begin_submit(&store, &first, &prepared)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(first.id)
        .execute(&store.pool)
        .await
        .unwrap();
    let replacement = store.lease(CONFIGURATION, 60).await.unwrap().unwrap();
    assert_ne!(replacement.lease, first.lease);
    assert!(
        remote::submitted(&store, &first, &prepared, &permit, "late-sid")
            .await
            .is_err()
    );
    let resumed = remote::prepare(&store, &replacement, &binding(), 600)
        .await
        .unwrap();
    assert!(
        remote::submitted(&store, &replacement, &resumed, &permit, "late-sid")
            .await
            .is_err()
    );
    assert_eq!(
        remote::ambiguous(&store, &replacement, &resumed, "previous lease interrupted")
            .await
            .unwrap()
            .state,
        State::Ambiguous
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn immutable_request_service_and_bundle_pins_cannot_be_rebound(pool: sqlx::PgPool) {
    let store = Store { pool };
    let job = job(&store).await;
    remote::prepare(&store, &job, &binding(), 600)
        .await
        .unwrap();
    for changed in [
        Binding {
            service_fingerprint: sha256(b"new service version"),
            ..binding()
        },
        Binding {
            request_digest: sha256(b"new submission params"),
            ..binding()
        },
        Binding {
            evidence_digest: sha256(b"different evidence bundle"),
            ..binding()
        },
    ] {
        assert!(remote::prepare(&store, &job, &changed, 600).await.is_err());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_analysis")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mut invalid = binding();
    invalid.request_digest = "not-a-digest".into();
    assert!(remote::prepare(&store, &job, &invalid, 600).await.is_err());
    assert!(remote::prepare(&store, &job, &binding(), 0).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn deferred_poll_keeps_checkpoint_without_consuming_failure_budget(pool: sqlx::PgPool) {
    let store = Store { pool };
    let first = job(&store).await;
    let saved = json!({"subject":first.subject,"configuration":first.configuration,"findings":[],"bundle":{"documents":[]}});
    assert!(remote::checkpoint(&store, &first).await.unwrap().is_none());
    remote::save_checkpoint(&store, &first, &saved)
        .await
        .unwrap();
    assert_eq!(
        remote::checkpoint(&store, &first).await.unwrap(),
        Some(saved.clone())
    );
    remote::defer(&store, &first, Utc::now() + Duration::seconds(20))
        .await
        .unwrap();
    assert!(store.lease(CONFIGURATION, 60).await.unwrap().is_none());
    let row = sqlx::query("SELECT state,attempts,lease_token,lease_until FROM jobs WHERE id=$1")
        .bind(first.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "queued");
    assert_eq!(row.get::<i32, _>("attempts"), 0);
    assert!(row.get::<Option<uuid::Uuid>, _>("lease_token").is_none());
    assert!(
        row.get::<Option<chrono::DateTime<Utc>>, _>("lease_until")
            .is_none()
    );
    assert!(remote::checkpoint(&store, &first).await.is_err());
    sqlx::query("UPDATE jobs SET not_before=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(first.id)
        .execute(&store.pool)
        .await
        .unwrap();
    let resumed = store.lease(CONFIGURATION, 60).await.unwrap().unwrap();
    assert_eq!(
        remote::checkpoint(&store, &resumed).await.unwrap(),
        Some(saved)
    );
    assert_eq!(
        store
            .job_status(&resumed.subject, CONFIGURATION)
            .await
            .unwrap()
            .unwrap()
            .attempts,
        1
    );
    assert!(
        remote::defer(&store, &resumed, Utc::now() + Duration::minutes(6))
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn terminal_failure_preserves_sid_and_completed_outputs_require_expiry(pool: sqlx::PgPool) {
    let store = Store { pool };
    let job = job(&store).await;
    let prepared = remote::prepare(&store, &job, &binding(), 600)
        .await
        .unwrap();
    let permit = remote::begin_submit(&store, &job, &prepared).await.unwrap();
    let submitted = remote::submitted(&store, &job, &prepared, &permit, "fixture-sid")
        .await
        .unwrap();
    let mut unbounded = output();
    unbounded.valid_until = None;
    assert!(
        remote::complete(&store, &job, &submitted, &unbounded)
            .await
            .is_err()
    );
    let failed = remote::fail(&store, &job, &submitted, "remote service failed")
        .await
        .unwrap();
    assert_eq!(failed.state, State::Failed);
    assert_eq!(failed.remote_id.as_deref(), Some("fixture-sid"));
    assert!(failed.completed_at.is_some());
    assert!(remote::begin_submit(&store, &job, &failed).await.is_err());
    assert!(
        remote::pending(&store, &job, &failed, 1, None)
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_completed_receipt_gets_a_new_generation_without_replaying_old_intent(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let job = job(&store).await;
    let prepared = remote::prepare(&store, &job, &binding(), 600)
        .await
        .unwrap();
    let permit = remote::begin_submit(&store, &job, &prepared).await.unwrap();
    let submitted = remote::submitted(&store, &job, &prepared, &permit, "old-sid")
        .await
        .unwrap();
    let mut expired = output();
    expired.valid_until = Some(Utc::now() - Duration::seconds(1));
    remote::complete(&store, &job, &submitted, &expired)
        .await
        .unwrap();
    let fresh = remote::prepare(&store, &job, &binding(), 600)
        .await
        .unwrap();
    assert_ne!(fresh.id, prepared.id);
    assert_eq!(fresh.generation, 1);
    assert_eq!(fresh.state, State::Prepared);
    assert!(fresh.remote_id.is_none());
    let preserved =
        sqlx::query("SELECT state,remote_id,generation FROM remote_analysis WHERE id=$1")
            .bind(prepared.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(preserved.get::<String, _>("state"), "complete");
    assert_eq!(preserved.get::<String, _>("remote_id"), "old-sid");
    assert_eq!(preserved.get::<i32, _>("generation"), 0);
    let second_prepare = remote::prepare(&store, &job, &binding(), 600)
        .await
        .unwrap();
    assert_eq!(second_prepare.id, fresh.id);
    assert_eq!(second_prepare.generation, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_analysis")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_inconclusive_receipt_never_causes_automatic_resubmission(pool: sqlx::PgPool) {
    let store = Store { pool };
    let job = job(&store).await;
    let prepared = remote::prepare(&store, &job, &binding(), 600)
        .await
        .unwrap();
    let permit = remote::begin_submit(&store, &job, &prepared).await.unwrap();
    let submitted = remote::submitted(&store, &job, &prepared, &permit, "stale-sid")
        .await
        .unwrap();
    let mut expired = output();
    expired.outcome = Outcome::Inconclusive;
    expired.valid_until = Some(Utc::now() - Duration::seconds(1));
    remote::complete(&store, &job, &submitted, &expired)
        .await
        .unwrap();
    for _ in 0..3 {
        let reused = remote::prepare(&store, &job, &binding(), 600)
            .await
            .unwrap();
        assert_eq!(reused.id, prepared.id);
        assert_eq!(reused.generation, 0);
        assert_eq!(reused.state, State::Complete);
        assert_eq!(reused.remote_id.as_deref(), Some("stale-sid"));
        assert!(remote::begin_submit(&store, &job, &reused).await.is_err());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_analysis")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn document_reference_bound_returns_the_complete_set_or_rejects_it(pool: sqlx::PgPool) {
    let store = Store { pool };
    let job = job(&store).await;
    sqlx::query("INSERT INTO documents(id,subject,kind,origin,blob_digest) SELECT md5(i::text)::uuid,$1,'inventory','artifact_observed',lpad(i::text,64,'0') FROM generate_series(1,256) i")
        .bind(&job.subject)
        .execute(&store.pool)
        .await
        .unwrap();
    let complete = store.documents(&job.subject).await.unwrap();
    assert_eq!(complete.len(), 256);
    let distinct: std::collections::BTreeSet<_> = complete
        .iter()
        .map(|document| document["blob_digest"].as_str().unwrap())
        .collect();
    assert_eq!(distinct.len(), 256);
    store
        .document(
            &job.subject,
            "inventory",
            "artifact_observed",
            &sha256(b"257th document"),
        )
        .await
        .unwrap();
    assert!(store.documents(&job.subject).await.is_err());
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM documents WHERE subject=$1")
        .bind(&job.subject)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(stored, 257);
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_lease_after_waiting_for_context_lock_cannot_write_checkpoint(pool: sqlx::PgPool) {
    let store = Store { pool };
    let job = job(&store).await;
    sqlx::query(
        "UPDATE jobs SET lease_until=clock_timestamp()+interval '150 milliseconds' WHERE id=$1",
    )
    .bind(job.id)
    .execute(&store.pool)
    .await
    .unwrap();
    let mut blocker = store.pool.begin().await.unwrap();
    sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
        .bind(&job.subject)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let task_store = store.clone();
    let task = tokio::spawn(async move {
        remote::save_checkpoint(&task_store, &job, &json!({"late":true})).await
    });
    // Hold the authoritative context lock beyond the lease, proving that the
    // eventual guarded write evaluates the clock after its lock wait.
    sqlx::query("SELECT pg_sleep(0.25)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(task.await.unwrap().is_err());
    let saved: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT analysis_checkpoint FROM jobs LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(saved.is_none());
}
