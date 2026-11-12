//! Durable intent and correlation for asynchronous external analysis.
//!
//! Persist `begin_submit` before sending a POST. Once that intent exists, only a
//! received and persisted remote identifier makes polling safe. An interrupted
//! submission is ambiguous, not evidence that the remote operation did not run.
//! Every worker mutation takes the context and job locks in the same order as
//! evidence completion, then checks the clock after all row-lock waits.

use crate::{
    scanner::ScannerOutput,
    store::{Job, Store},
};
use anyhow::{Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub check_name: String,
    /// Includes destination, exact service/version/rules pins and submission settings.
    pub service_fingerprint: String,
    pub request_digest: String,
    pub evidence_digest: String,
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.check_name.is_empty() && self.check_name.len() <= 128,
            "invalid remote analysis check name"
        );
        for digest in [
            &self.service_fingerprint,
            &self.request_digest,
            &self.evidence_digest,
        ] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "remote analysis binding requires lowercase SHA-256 digests"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared,
    Submitting,
    Submitted,
    Complete,
    Failed,
    Ambiguous,
}

impl State {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "prepared" => Self::Prepared,
            "submitting" => Self::Submitting,
            "submitted" => Self::Submitted,
            "complete" => Self::Complete,
            "failed" => Self::Failed,
            "ambiguous" => Self::Ambiguous,
            _ => bail!("invalid persisted remote analysis state"),
        })
    }
}

#[derive(Debug)]
pub struct Record {
    pub id: Uuid,
    pub job_id: Uuid,
    pub subject: String,
    pub configuration: String,
    pub context_revision: i64,
    pub generation: i32,
    pub binding: Binding,
    pub state: State,
    pub remote_id: Option<String>,
    pub submission_token: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub next_poll_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output: Option<ScannerOutput>,
    pub error: Option<String>,
    pub poll_attempts: i32,
    pub poll_failures: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct SubmissionPermit {
    pub correlation_id: Uuid,
    pub token: Uuid,
}

fn record(row: PgRow) -> Result<Record> {
    Ok(Record {
        id: row.get("id"),
        job_id: row.get("job_id"),
        subject: row.get("subject"),
        configuration: row.get("configuration"),
        context_revision: row.get("context_revision"),
        generation: row.get("generation"),
        binding: Binding {
            check_name: row.get("check_name"),
            service_fingerprint: row.get("service_fingerprint"),
            request_digest: row.get("request_digest"),
            evidence_digest: row.get("evidence_digest"),
        },
        state: State::parse(row.get("state"))?,
        remote_id: row.get("remote_id"),
        submission_token: row.get("submission_token"),
        created_at: row.get("created_at"),
        deadline_at: row.get("deadline_at"),
        next_poll_at: row.get("next_poll_at"),
        completed_at: row.get("completed_at"),
        output: row
            .get::<Option<serde_json::Value>, _>("output")
            .map(serde_json::from_value)
            .transpose()?,
        error: row.get("error"),
        poll_attempts: row.get("poll_attempts"),
        poll_failures: row.get("poll_failures"),
    })
}

async fn lock_job(connection: &mut PgConnection, job: &Job) -> Result<DateTime<Utc>> {
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
            .bind(&job.subject)
            .fetch_one(&mut *connection)
            .await?;
    ensure!(
        revision == job.context_revision,
        "remote analysis evidence context changed"
    );
    let lease_until: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT lease_until FROM jobs WHERE id=$1 AND subject=$2 AND configuration=$3 AND context_revision=$4 AND lease_token=$5 AND state='running' FOR UPDATE")
        .bind(job.id).bind(&job.subject).bind(&job.configuration).bind(job.context_revision).bind(job.lease)
        .fetch_optional(&mut *connection).await?.flatten();
    lease_until.ok_or_else(|| anyhow::anyhow!("remote analysis job lease lost"))
}

async fn check_clock(
    connection: &mut PgConnection,
    lease_until: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await?;
    ensure!(
        lease_until > now,
        "remote analysis job lease expired while waiting for locks"
    );
    Ok(now)
}

fn check_job_binding(current: &Record, job: &Job) -> Result<()> {
    ensure!(
        current.job_id == job.id
            && current.subject == job.subject
            && current.configuration == job.configuration
            && current.context_revision == job.context_revision,
        "persisted remote analysis job binding differs"
    );
    Ok(())
}

async fn locked_record(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
    expected: &Record,
) -> Result<(Record, DateTime<Utc>)> {
    let lease_until = lock_job(tx, job).await?;
    let current = record(
        sqlx::query("SELECT * FROM remote_analysis WHERE id=$1 FOR UPDATE")
            .bind(expected.id)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    let now = check_clock(tx, lease_until).await?;
    check_job_binding(&current, job)?;
    ensure!(
        current.binding == expected.binding,
        "remote analysis request binding differs"
    );
    Ok((current, now))
}

/// Reuse only the exact original request. An expired definitive receipt creates
/// a new generation, preserving the old receipt and its correlation ID. Partial,
/// failed or ambiguous analyses require an explicit new context to submit again.
pub async fn prepare(
    store: &Store,
    job: &Job,
    binding: &Binding,
    timeout_seconds: i64,
) -> Result<Record> {
    binding.validate()?;
    ensure!(
        (1..=604800).contains(&timeout_seconds),
        "remote analysis deadline outside supported bounds"
    );
    let mut tx = store.pool.begin().await?;
    let lease_until = lock_job(&mut tx, job).await?;
    let latest = sqlx::query("SELECT * FROM remote_analysis WHERE job_id=$1 AND check_name=$2 AND context_revision=$3 ORDER BY generation DESC LIMIT 1 FOR UPDATE")
        .bind(job.id).bind(&binding.check_name).bind(job.context_revision).fetch_optional(&mut *tx).await?
        .map(record).transpose()?;
    let now = check_clock(&mut tx, lease_until).await?;
    let current = match latest {
        Some(current) => {
            check_job_binding(&current, job)?;
            ensure!(
                &current.binding == binding,
                "remote analysis request changed within an evidence context"
            );
            let expired = current.state == State::Complete
                && current.output.as_ref().is_some_and(|output| {
                    matches!(
                        output.outcome,
                        crate::model::Outcome::Pass | crate::model::Outcome::Fail
                    ) && output.valid_until.is_some_and(|expiry| expiry <= now)
                });
            if expired {
                let generation = current
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("remote analysis generation exhausted"))?;
                insert_record(&mut tx, job, binding, generation, timeout_seconds, now).await?
            } else {
                current
            }
        }
        None => insert_record(&mut tx, job, binding, 0, timeout_seconds, now).await?,
    };
    tx.commit().await?;
    Ok(current)
}

async fn insert_record(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
    binding: &Binding,
    generation: i32,
    timeout_seconds: i64,
    now: DateTime<Utc>,
) -> Result<Record> {
    record(sqlx::query("INSERT INTO remote_analysis(id,job_id,subject,configuration,context_revision,check_name,service_fingerprint,request_digest,evidence_digest,generation,created_at,deadline_at,next_poll_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11+make_interval(secs => $12),$11) RETURNING *")
        .bind(Uuid::new_v4()).bind(job.id).bind(&job.subject).bind(&job.configuration).bind(job.context_revision)
        .bind(&binding.check_name).bind(&binding.service_fingerprint).bind(&binding.request_digest)
        .bind(&binding.evidence_digest).bind(generation).bind(now).bind(timeout_seconds as f64)
        .fetch_one(&mut **tx).await?)
}

pub async fn begin_submit(store: &Store, job: &Job, expected: &Record) -> Result<SubmissionPermit> {
    let mut tx = store.pool.begin().await?;
    let (current, now) = locked_record(&mut tx, job, expected).await?;
    ensure!(
        current.state == State::Prepared,
        "remote analysis submission already attempted"
    );
    ensure!(
        current.deadline_at > now,
        "remote analysis deadline elapsed before submission"
    );
    let permit = SubmissionPermit {
        correlation_id: current.id,
        token: Uuid::new_v4(),
    };
    sqlx::query("UPDATE remote_analysis SET state='submitting',submission_token=$2,submission_lease=$3,updated_at=clock_timestamp() WHERE id=$1")
        .bind(current.id).bind(permit.token).bind(job.lease).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(permit)
}

fn validate_remote_id(remote_id: &str) -> Result<()> {
    ensure!(
        !remote_id.is_empty()
            && remote_id.len() <= 256
            && remote_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid remote submission identifier"
    );
    Ok(())
}

pub async fn submitted(
    store: &Store,
    job: &Job,
    expected: &Record,
    permit: &SubmissionPermit,
    remote_id: &str,
) -> Result<Record> {
    validate_remote_id(remote_id)?;
    let mut tx = store.pool.begin().await?;
    let (current, _) = locked_record(&mut tx, job, expected).await?;
    ensure!(
        current.state == State::Submitting
            && permit.correlation_id == current.id
            && current.submission_token == Some(permit.token),
        "remote submission permit differs"
    );
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT submission_lease FROM remote_analysis WHERE id=$1")
            .bind(current.id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        owner == Some(job.lease),
        "remote submission belongs to a previous worker lease"
    );
    let updated = record(sqlx::query("UPDATE remote_analysis SET state='submitted',remote_id=$2,next_poll_at=clock_timestamp(),error=NULL,updated_at=clock_timestamp() WHERE id=$1 RETURNING *")
        .bind(current.id).bind(remote_id).fetch_one(&mut *tx).await?)?;
    tx.commit().await?;
    Ok(updated)
}

fn validate_reason(reason: &str) -> Result<()> {
    ensure!(
        !reason.is_empty() && reason.len() <= 4096,
        "invalid remote analysis failure reason"
    );
    Ok(())
}

pub async fn ambiguous(
    store: &Store,
    job: &Job,
    expected: &Record,
    reason: &str,
) -> Result<Record> {
    validate_reason(reason)?;
    let mut tx = store.pool.begin().await?;
    let (current, _) = locked_record(&mut tx, job, expected).await?;
    ensure!(
        current.state == State::Submitting,
        "only an interrupted submission is ambiguous"
    );
    let updated = record(sqlx::query("UPDATE remote_analysis SET state='ambiguous',error=$2,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 RETURNING *")
        .bind(current.id).bind(reason).fetch_one(&mut *tx).await?)?;
    tx.commit().await?;
    Ok(updated)
}

/// Record a safe GET attempt. Transport errors retain the SID; they never
/// transition back to a state from which submission can be repeated.
pub async fn pending(
    store: &Store,
    job: &Job,
    expected: &Record,
    poll_after_seconds: u64,
    error: Option<&str>,
) -> Result<Record> {
    ensure!(
        (1..=86400).contains(&poll_after_seconds),
        "invalid remote poll delay"
    );
    if let Some(reason) = error {
        validate_reason(reason)?;
    }
    let mut tx = store.pool.begin().await?;
    let (current, _) = locked_record(&mut tx, job, expected).await?;
    ensure!(
        current.state == State::Submitted && current.remote_id == expected.remote_id,
        "remote analysis is not awaiting this submission"
    );
    let updated = record(sqlx::query("UPDATE remote_analysis SET poll_attempts=poll_attempts+1,poll_failures=CASE WHEN $3::text IS NULL THEN 0 ELSE poll_failures+1 END,next_poll_at=LEAST(deadline_at,clock_timestamp()+make_interval(secs => $2)),error=$3,updated_at=clock_timestamp() WHERE id=$1 RETURNING *")
        .bind(current.id).bind(poll_after_seconds as f64).bind(error).fetch_one(&mut *tx).await?)?;
    tx.commit().await?;
    Ok(updated)
}

/// Persist the normalized output together with its first absolute expiry. Reuse
/// must preserve this expiry instead of granting a fresh TTL on each retry.
pub async fn complete(
    store: &Store,
    job: &Job,
    expected: &Record,
    output: &ScannerOutput,
) -> Result<Record> {
    ensure!(
        output.valid_until.is_some(),
        "remote output requires an absolute validity bound"
    );
    let document = serde_json::to_value(output)?;
    ensure!(
        serde_json::to_vec(&document)?.len() <= 8 * 1024 * 1024,
        "remote output exceeds limit"
    );
    let mut tx = store.pool.begin().await?;
    let (current, now) = locked_record(&mut tx, job, expected).await?;
    ensure!(
        current.state == State::Submitted && current.remote_id == expected.remote_id,
        "remote analysis is not awaiting this submission"
    );
    ensure!(
        current.deadline_at > now,
        "remote analysis deadline elapsed before completion"
    );
    let updated = record(sqlx::query("UPDATE remote_analysis SET state='complete',output=$2,completed_at=clock_timestamp(),error=NULL,updated_at=clock_timestamp() WHERE id=$1 RETURNING *")
        .bind(current.id).bind(document).fetch_one(&mut *tx).await?)?;
    tx.commit().await?;
    Ok(updated)
}

pub async fn fail(store: &Store, job: &Job, expected: &Record, reason: &str) -> Result<Record> {
    validate_reason(reason)?;
    let mut tx = store.pool.begin().await?;
    let (current, _) = locked_record(&mut tx, job, expected).await?;
    ensure!(
        matches!(current.state, State::Prepared | State::Submitted),
        "remote analysis cannot be failed from this state"
    );
    let updated = record(sqlx::query("UPDATE remote_analysis SET state='failed',error=$2,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 RETURNING *")
        .bind(current.id).bind(reason).fetch_one(&mut *tx).await?)?;
    tx.commit().await?;
    Ok(updated)
}

/// Attach an operator-reconciled SID only to the current ambiguous request.
/// The transport must verify correlation metadata and the subject on its next
/// GET before using any report. This function never initiates another POST.
pub async fn reconcile(store: &Store, id: Uuid, subject: &str, remote_id: &str) -> Result<Record> {
    validate_remote_id(remote_id)?;
    let mut tx = store.pool.begin().await?;
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
            .bind(subject)
            .fetch_one(&mut *tx)
            .await?;
    // Read the immutable job key before acquiring its lock. All mutations use
    // context -> job -> remote ordering, including this administrative path.
    let job_id: Uuid =
        sqlx::query_scalar("SELECT job_id FROM remote_analysis WHERE id=$1 AND subject=$2")
            .bind(id)
            .bind(subject)
            .fetch_one(&mut *tx)
            .await?;
    let job = sqlx::query(
        "SELECT subject,configuration,context_revision,state FROM jobs WHERE id=$1 FOR UPDATE",
    )
    .bind(job_id)
    .fetch_one(&mut *tx)
    .await?;
    let current = record(
        sqlx::query("SELECT * FROM remote_analysis WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?,
    )?;
    ensure!(
        current.state == State::Ambiguous
            && current.subject == subject
            && current.context_revision == revision
            && job.get::<String, _>("subject") == subject
            && job.get::<String, _>("configuration") == current.configuration
            && job.get::<i64, _>("context_revision") == revision,
        "only a current ambiguous remote request can be reconciled"
    );
    ensure!(
        job.get::<String, _>("state") != "running",
        "cannot reconcile a running job"
    );
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        current.deadline_at > now,
        "remote analysis reconciliation deadline elapsed"
    );
    let updated = record(sqlx::query("UPDATE remote_analysis SET state='submitted',remote_id=$2,error=NULL,completed_at=NULL,next_poll_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 RETURNING *")
        .bind(id).bind(remote_id).fetch_one(&mut *tx).await?)?;
    sqlx::query("UPDATE jobs SET state='queued',attempts=0,error=NULL,lease_token=NULL,lease_until=NULL,not_before=clock_timestamp() WHERE id=$1")
        .bind(job_id).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO audit(action,subject,details) VALUES('remote_analysis_reconciled',$1,$2)",
    )
    .bind(subject)
    .bind(serde_json::json!({"correlation_id":id,"submission_id":remote_id,"job":job_id}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(updated)
}

/// Load ordinary analysis inputs saved by this exact active context and lease.
pub async fn checkpoint(store: &Store, job: &Job) -> Result<Option<serde_json::Value>> {
    let mut tx = store.pool.begin().await?;
    let lease_until = lock_job(&mut tx, job).await?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT analysis_checkpoint FROM jobs WHERE id=$1 AND checkpoint_context_revision=$2",
    )
    .bind(job.id)
    .bind(job.context_revision)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    check_clock(&mut tx, lease_until).await?;
    tx.commit().await?;
    Ok(value)
}

pub async fn save_checkpoint(
    store: &Store,
    job: &Job,
    checkpoint: &serde_json::Value,
) -> Result<()> {
    ensure!(
        serde_json::to_vec(checkpoint)?.len() <= 8 * 1024 * 1024,
        "analysis checkpoint exceeds limit"
    );
    let mut tx = store.pool.begin().await?;
    let lease_until = lock_job(&mut tx, job).await?;
    check_clock(&mut tx, lease_until).await?;
    sqlx::query(
        "UPDATE jobs SET analysis_checkpoint=$2,checkpoint_context_revision=$3 WHERE id=$1",
    )
    .bind(job.id)
    .bind(checkpoint)
    .bind(job.context_revision)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Release a successful asynchronous scheduling step without spending one of
/// the bounded worker-failure retries. Normal lease and context guards apply.
pub async fn defer(store: &Store, job: &Job, not_before: DateTime<Utc>) -> Result<()> {
    let mut tx = store.pool.begin().await?;
    let lease_until = lock_job(&mut tx, job).await?;
    let now = check_clock(&mut tx, lease_until).await?;
    ensure!(
        not_before <= now + chrono::Duration::seconds(300),
        "remote deferral exceeds maximum delay"
    );
    let not_before = not_before.max(now + chrono::Duration::seconds(1));
    sqlx::query("UPDATE jobs SET state='queued',lease_token=NULL,lease_until=NULL,attempts=GREATEST(attempts-1,0),error='remote analysis pending',not_before=$2 WHERE id=$1")
        .bind(job.id).bind(not_before).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
