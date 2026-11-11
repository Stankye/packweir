//! PostgreSQL-backed operational observations; HTTP authorization is tested separately.
use chrono::{DateTime, Duration, Utc};
use packweir::{
    model::{Evidence, Outcome},
    operations::{OperationalSnapshot, snapshot},
    store::Store,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

fn series(text: &str) -> BTreeSet<&str> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| line.split_whitespace().next().unwrap())
        .collect()
}

async fn clock(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn insert_evidence(
    pool: &PgPool,
    subject: &str,
    outcome: Outcome,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revision: i64,
    mutate: impl FnOnce(&mut Value),
) {
    let evidence = Evidence {
        subject: subject.into(),
        check: "private-scanner-name".into(),
        configuration: "private-configuration".into(),
        tool_version: "private-tool-version".into(),
        outcome,
        created_at,
        expires_at,
        details: json!({"token":"private-evidence-token"}),
        references: vec!["https://private-source.test/artifact".into()],
    };
    let mut document = serde_json::to_value(&evidence).unwrap();
    mutate(&mut document);
    sqlx::query("INSERT INTO evidence(id,subject,check_name,configuration,context_revision,created_at,expires_at,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::new_v4()).bind(subject).bind(&evidence.check).bind(&evidence.configuration)
        .bind(revision).bind(created_at).bind(expires_at).bind(document)
        .execute(pool).await.unwrap();
}

fn assert_evidence_partition(snapshot: &OperationalSnapshot) {
    let evidence = &snapshot.evidence;
    assert_eq!(
        evidence.total,
        evidence.current_context_time_valid
            + evidence.expired
            + evidence.future_dated
            + evidence.invalidated_context
            + evidence.binding_invalid
    );
    assert_eq!(
        evidence.current_context_time_valid,
        evidence.outcomes.pass
            + evidence.outcomes.fail
            + evidence.outcomes.inconclusive
            + evidence.outcomes.unsupported
            + evidence.outcomes.error
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn empty_database_has_zero_gauges_and_failure_is_not_reported_as_empty(pool: PgPool) {
    let store = Store { pool };
    let result = snapshot(&store).await.unwrap();
    assert_eq!(result.coverage.database_scope, "all_configurations");
    assert!(!result.coverage.physical_storage_verified);
    assert!(!result.coverage.worker_liveness_verified);
    assert!(!result.coverage.current_policy_approval_verified);
    assert_eq!(
        result.jobs.queued + result.jobs.running + result.jobs.complete + result.jobs.failed,
        0
    );
    assert_eq!(result.jobs.oldest_queued_age_seconds, 0.0);
    assert_eq!(result.evidence.total, 0);
    assert_eq!(result.artifacts.references, 0);
    assert_eq!(result.artifacts.recorded_digest_bytes, 0);
    assert_eq!(result.documents.references, 0);
    assert_eq!(result.discovery.claims, 0);
    assert_eq!(result.audit_records, 0);
    assert_evidence_partition(&result);
    let exposition = result.render_prometheus();
    assert!(exposition.ends_with('\n'));
    assert!(exposition.contains("# TYPE packweir_jobs gauge\n"));
    assert!(exposition.contains("packweir_jobs{state=\"queued\"} 0\n"));
    assert!(
        exposition.contains("packweir_current_context_evidence_outcomes{outcome=\"error\"} 0\n")
    );
    for line in exposition.lines().filter(|line| !line.starts_with('#')) {
        assert!(
            line.split_whitespace()
                .last()
                .unwrap()
                .parse::<f64>()
                .unwrap()
                .is_finite()
        );
    }
    store.pool.close().await;
    assert!(snapshot(&store).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn database_observations_count_queue_freshness_and_shared_references_without_leaking_labels(
    pool: PgPool,
) {
    let store = Store { pool };
    let empty_exposition = snapshot(&store).await.unwrap().render_prometheus();
    let now = clock(&store.pool).await;
    let sensitive = "private-package\ninjected_metric{token=\"fixture-secret\"} 999";
    let jobs = [
        ("queued", 0, None, true, 0),
        ("queued", 3, None, true, 0),
        ("queued", 0, None, true, 1),
        ("running", 1, Some(now + Duration::hours(1)), true, 0),
        ("running", 2, Some(now - Duration::hours(1)), true, 0),
        ("running", 3, Some(now - Duration::hours(1)), true, 0),
        ("running", 1, None, false, 0),
        ("complete", 1, None, true, 0),
        ("failed", 3, None, true, 0),
    ];
    for (index, (state, attempts, lease, token, current_revision)) in jobs.into_iter().enumerate() {
        let subject = format!("job-{index}-{sensitive}");
        sqlx::query("INSERT INTO contexts(subject,revision) VALUES($1,$2)")
            .bind(&subject)
            .bind(current_revision as i64)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO jobs(id,subject,configuration,context_revision,filename,state,attempts,lease_token,lease_until,created_at,error) VALUES($1,$2,$3,0,$4,$5,$6,$7,$8,$9,$10)")
            .bind(Uuid::new_v4()).bind(subject).bind(sensitive).bind(sensitive).bind(state).bind(attempts)
            .bind(token.then(Uuid::new_v4)).bind(lease).bind(now-Duration::hours(1)).bind(sensitive)
            .execute(&store.pool).await.unwrap();
    }
    for outcome in [
        Outcome::Pass,
        Outcome::Fail,
        Outcome::Inconclusive,
        Outcome::Unsupported,
        Outcome::Error,
    ] {
        insert_evidence(
            &store.pool,
            "valid",
            outcome,
            now - Duration::minutes(1),
            now + Duration::hours(1),
            0,
            |_| {},
        )
        .await;
    }
    insert_evidence(
        &store.pool,
        "expired",
        Outcome::Pass,
        now - Duration::hours(2),
        now - Duration::hours(1),
        0,
        |_| {},
    )
    .await;
    insert_evidence(
        &store.pool,
        "future",
        Outcome::Pass,
        now + Duration::hours(1),
        now + Duration::hours(2),
        0,
        |_| {},
    )
    .await;
    sqlx::query("INSERT INTO contexts(subject,revision) VALUES('invalidated',2)")
        .execute(&store.pool)
        .await
        .unwrap();
    insert_evidence(
        &store.pool,
        "invalidated",
        Outcome::Pass,
        now - Duration::hours(2),
        now - Duration::hours(1),
        1,
        |_| {},
    )
    .await;
    insert_evidence(
        &store.pool,
        "bad-binding",
        Outcome::Pass,
        now - Duration::minutes(1),
        now + Duration::hours(1),
        0,
        |doc| {
            doc["subject"] = json!("different-subject");
        },
    )
    .await;
    let digest_a = "a".repeat(64);
    let digest_b = "b".repeat(64);
    for (index, digest, size) in [
        (0, &digest_a, 10i64),
        (1, &digest_a, 12),
        (2, &digest_b, 12),
    ] {
        sqlx::query("INSERT INTO artifacts(repository,origin,digest,size,filename,content_type) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(if index==1 {"another-private-repository"} else {sensitive})
            .bind(format!("https://private-source.test/{index}?token=fixture-secret"))
            .bind(digest).bind(size).bind(sensitive).bind("application/private")
            .execute(&store.pool).await.unwrap();
    }
    for (index, origin, blob) in [
        (0, "publisher_declared", &digest_a),
        (1, "artifact_observed", &digest_a),
        (2, "client_resolved", &digest_b),
    ] {
        sqlx::query(
            "INSERT INTO documents(id,subject,kind,origin,blob_digest) VALUES($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(format!("subject-{index}"))
        .bind(sensitive)
        .bind(origin)
        .bind(blob)
        .execute(&store.pool)
        .await
        .unwrap();
    }
    for state in [
        "approved",
        "approved",
        "denied",
        "pending",
        "private-state-label",
    ] {
        sqlx::query(
            "INSERT INTO decisions(repository,subject,configuration,document) VALUES($1,$2,$3,$4)",
        )
        .bind(sensitive)
        .bind(&digest_a)
        .bind(sensitive)
        .bind(json!({"state":state,"secret":sensitive}))
        .execute(&store.pool)
        .await
        .unwrap();
    }
    for _ in 0..2 {
        sqlx::query("INSERT INTO audit(action,subject,details) VALUES($1,$2,$3)")
            .bind(sensitive)
            .bind(&digest_a)
            .bind(json!({"secret":sensitive}))
            .execute(&store.pool)
            .await
            .unwrap();
    }
    for (origin, coordinate, package) in [
        (
            "https://private-source.test/shared",
            "pkg:private/a@1",
            Some(json!({"private":sensitive})),
        ),
        (
            "https://private-source.test/shared",
            "pkg:private/b@1",
            Some(json!({"private":sensitive})),
        ),
        ("https://private-source.test/unknown", "unidentified", None),
    ] {
        sqlx::query("INSERT INTO package_claims(repository,origin,coordinate,source,package) VALUES($1,$2,$3,$4,$5)")
            .bind(sensitive).bind(origin).bind(coordinate).bind(sensitive).bind(package).execute(&store.pool).await.unwrap();
    }
    let result = snapshot(&store).await.unwrap();
    assert_eq!(
        (
            result.jobs.queued,
            result.jobs.running,
            result.jobs.complete,
            result.jobs.failed
        ),
        (3, 4, 1, 1)
    );
    assert_eq!(result.jobs.expired_leases, 2);
    assert_eq!(result.jobs.retryable_expired_leases, 1);
    assert_eq!(result.jobs.exhausted_expired_leases, 1);
    assert_eq!(result.jobs.invalid_running_leases, 1);
    assert_eq!(result.jobs.exhausted_queued, 1);
    assert_eq!(result.jobs.stale_context_active, 1);
    assert!(result.jobs.oldest_queued_age_seconds >= 3600.0);
    assert!(result.jobs.oldest_queued_age_seconds < 3700.0);
    assert_eq!(result.evidence.total, 9);
    assert_eq!(result.evidence.current_context_time_valid, 5);
    assert_eq!(result.evidence.expired, 1);
    assert_eq!(result.evidence.future_dated, 1);
    assert_eq!(result.evidence.invalidated_context, 1);
    assert_eq!(result.evidence.binding_invalid, 1);
    assert_evidence_partition(&result);
    assert_eq!(
        (
            result.artifacts.references,
            result.artifacts.distinct_digests,
            result.artifacts.repositories
        ),
        (3, 2, 2)
    );
    assert_eq!(result.artifacts.recorded_digest_bytes, 24);
    assert_eq!(result.artifacts.inconsistent_size_digests, 1);
    assert_eq!(
        (
            result.documents.references,
            result.documents.distinct_blob_digests
        ),
        (3, 2)
    );
    assert_eq!(
        (
            result.documents.publisher_declared,
            result.documents.artifact_observed,
            result.documents.client_resolved
        ),
        (1, 1, 1)
    );
    assert_eq!(
        (
            result.decisions.approved,
            result.decisions.denied,
            result.decisions.pending,
            result.decisions.unknown
        ),
        (2, 1, 1, 1)
    );
    assert_eq!(result.audit_records, 2);
    assert_eq!(
        (
            result.discovery.claims,
            result.discovery.unidentified_claims,
            result.discovery.conflicting_artifact_urls
        ),
        (3, 1, 1)
    );
    let exposition = result.render_prometheus();
    assert_eq!(
        series(&empty_exposition),
        series(&exposition),
        "untrusted database values must never add metric labels or series"
    );
    assert!(exposition.contains("packweir_jobs{state=\"running\"} 4\n"));
    assert!(exposition.contains("packweir_evidence_records{status=\"invalidated_context\"} 1\n"));
    for private in [
        "private-package",
        "fixture-secret",
        "private-scanner",
        "private-configuration",
        "private-source",
        "private-state-label",
        "private-evidence-token",
    ] {
        assert!(!exposition.contains(private));
        assert!(!serde_json::to_string(&result).unwrap().contains(private));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_documents_and_infinite_dates_do_not_become_valid_evidence_metrics(pool: PgPool) {
    let now = clock(&pool).await;
    let mutations: Vec<fn(&mut Value)> = vec![
        |doc| {
            *doc = Value::Null;
        },
        |doc| {
            *doc = json!(123);
        },
        |doc| {
            *doc = json!(["unexpected array"]);
        },
        |doc| {
            doc["created_at"] = json!("not-a-timestamp");
        },
        |doc| {
            doc["expires_at"] = json!("infinity");
        },
        |doc| {
            doc["references"] = json!(["valid", 17]);
        },
        |doc| {
            doc["unknown_field"] = json!("unexpected");
        },
        |doc| {
            doc["outcome"] = json!("unknown-result");
        },
        |doc| {
            doc["configuration"] = json!(true);
        },
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        insert_evidence(
            &pool,
            &format!("bad-{index}"),
            Outcome::Pass,
            now - Duration::minutes(1),
            now + Duration::hours(1),
            0,
            mutation,
        )
        .await;
    }
    insert_evidence(
        &pool,
        "bad-time-binding",
        Outcome::Pass,
        now - Duration::minutes(1),
        now + Duration::hours(1),
        0,
        |doc| {
            doc["expires_at"] = json!(Utc::now() + Duration::hours(2));
        },
    )
    .await;
    let result = snapshot(&Store { pool }).await.unwrap();
    assert_eq!(result.evidence.total, 10);
    assert_eq!(result.evidence.binding_invalid, 10);
    assert_eq!(result.evidence.current_context_time_valid, 0);
    assert_evidence_partition(&result);
}
