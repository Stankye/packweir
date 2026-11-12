use chrono::{Duration, Utc};
use packweir::{
    model::{Evidence, Outcome},
    store::Store,
};

#[sqlx::test(migrations = "./migrations")]
async fn a_context_lock_wait_cannot_extend_a_worker_lease_past_its_deadline(pool: sqlx::PgPool) {
    complete_after_expiry(pool, true).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn a_job_row_lock_wait_cannot_extend_a_worker_lease_past_its_deadline(pool: sqlx::PgPool) {
    complete_after_expiry(pool, false).await;
}

async fn complete_after_expiry(pool: sqlx::PgPool, context_lock: bool) {
    let store = Store { pool };
    let subject = "a".repeat(64);
    let configuration = "c".repeat(64);
    store
        .enqueue(&subject, &configuration, "fixture")
        .await
        .unwrap();
    let job = store.lease(&configuration, 2).await.unwrap().unwrap();
    let mut blocker = store.pool.begin().await.unwrap();
    if context_lock {
        sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
            .bind(&subject)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
    } else {
        sqlx::query("SELECT lease_until FROM jobs WHERE id=$1 FOR UPDATE")
            .bind(job.id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
    }
    let evidence = Evidence {
        subject: subject.clone(),
        check: "inventory".into(),
        tool_version: "fixture".into(),
        configuration: configuration.clone(),
        outcome: Outcome::Pass,
        created_at: Utc::now() - Duration::seconds(1),
        expires_at: Utc::now() + Duration::hours(1),
        details: serde_json::json!({}),
        references: vec![],
    };
    let completing = store.clone();
    let id = job.id;
    let original_lease = job.lease;
    let task = tokio::spawn(async move { completing.complete(&job, &[evidence]).await });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        // Observe the exact blocked transaction before advancing beyond its lease.
        let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN jobs j ON j.id=$1 WHERE a.datname=current_database() AND a.wait_event_type='Lock' AND a.query LIKE $2 AND a.xact_start<j.lease_until)")
            .bind(id).bind(if context_lock {"SELECT revision FROM contexts%"}else{"SELECT lease_until FROM jobs%"}).fetch_one(&store.pool).await.unwrap();
        if waiting {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "completion did not enter its expected context lock wait"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    sqlx::query("SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM (lease_until-clock_timestamp())),0)::double precision+0.05) FROM jobs WHERE id=$1")
        .bind(id).execute(&store.pool).await.unwrap();
    blocker.commit().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE subject=$1")
        .bind(&subject)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(state, "running");
    let recovered = store.lease(&configuration, 30).await.unwrap().unwrap();
    assert_ne!(recovered.lease, original_lease);
    store.complete(&recovered, &[]).await.unwrap();
}
