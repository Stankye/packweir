//! Immutable hosted Maven release reservations and evidence-bound publication.
//!
//! Callers authenticate/authorize roles, validate POM/packaging and store verified bytes before
//! adding a file. No package code is executed here. Publication is an intent, never a permanent
//! security approval: delivery must re-evaluate current policy and evidence.
use crate::{
    config::Config,
    identity::PackageIdentity,
    model::{Artifact, Decision, Ecosystem, Evidence, sha256},
    store::Store,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::fmt;
use uuid::Uuid;

const MAX_FILES: usize = 128;
const MAX_RELEASE_BYTES: i64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub enum HostedError {
    Invalid(String),
    Conflict(String),
    NotFound,
    NotApproved(String),
    Internal(String),
}
impl fmt::Display for HostedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) | Self::Conflict(s) | Self::NotApproved(s) | Self::Internal(s) => {
                s.fmt(f)
            }
            Self::NotFound => f.write_str("hosted stage not found"),
        }
    }
}
impl std::error::Error for HostedError {}
impl From<sqlx::Error> for HostedError {
    fn from(e: sqlx::Error) -> Self {
        if e.as_database_error()
            .is_some_and(|e| e.is_unique_violation())
        {
            Self::Conflict("hosted coordinate or stage ID is already reserved".into())
        } else {
            Self::Internal(e.to_string())
        }
    }
}
impl From<serde_json::Error> for HostedError {
    fn from(e: serde_json::Error) -> Self {
        Self::Internal(e.to_string())
    }
}
impl From<anyhow::Error> for HostedError {
    fn from(e: anyhow::Error) -> Self {
        Self::Invalid(e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, HostedError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageState {
    Open,
    Sealed,
    Published,
    Revoked,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub id: Uuid,
    pub repository: String,
    pub package: PackageIdentity,
    pub owner: String,
    pub state: StageState,
    pub manifest_digest: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sealed_at: Option<DateTime<Utc>>,
    pub published_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub aborted_at: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedFile {
    pub path: String,
    pub artifact: Artifact,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub stage: Uuid,
    pub repository: String,
    pub package: PackageIdentity,
    pub files: Vec<HostedFile>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealReceipt {
    pub stage: Stage,
    pub manifest: Manifest,
    pub manifest_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyRequest {
    pub id: Uuid,
    pub destination_repository: String,
    pub source_manifest_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyReceipt {
    pub source_stage: Uuid,
    pub source_repository: String,
    pub source_manifest_digest: String,
    pub source_evaluated_at: DateTime<Utc>,
    pub source_files: Vec<PromotionFile>,
    pub destination: SealReceipt,
    pub actor: String,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionFile {
    pub path: String,
    pub subject: String,
    pub configuration: String,
    pub context_revision: i64,
    pub policy: crate::policy::EffectivePolicy,
    pub evidence: Vec<Value>,
    pub evidence_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionReceipt {
    pub stage: Stage,
    pub manifest_digest: String,
    pub actor: String,
    pub evaluated_at: DateTime<Utc>,
    pub files: Vec<PromotionFile>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub stage: Stage,
    pub artifact: Artifact,
    pub configuration: String,
    pub decision: Decision,
}

fn actor_valid(actor: &str) -> Result<()> {
    if actor.is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
        return Err(HostedError::Invalid("invalid authenticated actor".into()));
    }
    Ok(())
}
fn stage_row(row: &PgRow) -> Result<Stage> {
    let state = match row.try_get::<&str, _>("state")? {
        "open" => StageState::Open,
        "sealed" => StageState::Sealed,
        "published" => StageState::Published,
        "revoked" => StageState::Revoked,
        "aborted" => StageState::Aborted,
        _ => return Err(HostedError::Internal("invalid hosted state".into())),
    };
    Ok(Stage {
        id: row.try_get("id")?,
        repository: row.try_get("repository")?,
        package: serde_json::from_value(row.try_get("package")?)?,
        owner: row.try_get("owner")?,
        state,
        manifest_digest: row.try_get("manifest_digest")?,
        created_at: row.try_get("created_at")?,
        sealed_at: row.try_get("sealed_at")?,
        published_at: row.try_get("published_at")?,
        revoked_at: row.try_get("revoked_at")?,
        aborted_at: row.try_get("aborted_at")?,
    })
}
async fn locked_stage(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<(Stage, PgRow)> {
    let row = sqlx::query("SELECT * FROM hosted_stages WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(HostedError::NotFound)?;
    Ok((stage_row(&row)?, row))
}
async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    id: Uuid,
    details: Value,
) -> Result<()> {
    sqlx::query("INSERT INTO audit(action,subject,details) VALUES($1,$2,$3)")
        .bind(action)
        .bind(id.to_string())
        .bind(details)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
pub async fn stage(store: &Store, id: Uuid) -> Result<Stage> {
    let row = sqlx::query("SELECT * FROM hosted_stages WHERE id=$1")
        .bind(id)
        .fetch_optional(&store.pool)
        .await?
        .ok_or(HostedError::NotFound)?;
    stage_row(&row)
}
pub async fn create_stage(
    store: &Store,
    id: Uuid,
    repository: &str,
    package: PackageIdentity,
    actor: &str,
) -> Result<Stage> {
    actor_valid(actor)?;
    let coordinate = crate::maven::Coordinate::new(&package.name, &package.version)?;
    if repository.is_empty()
        || repository.len() > 128
        || !repository
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        || package.ecosystem != Ecosystem::Maven
        || coordinate.package() != package
    {
        return Err(HostedError::Invalid(
            "hosted release requires canonical immutable Maven coordinates".into(),
        ));
    }
    let mut tx = store.pool.begin().await?;
    let inserted=sqlx::query("INSERT INTO hosted_stages(id,repository,package_name,version,package,owner) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING")
        .bind(id).bind(repository).bind(&package.name).bind(&package.version).bind(serde_json::to_value(&package)?).bind(actor).execute(&mut *tx).await?.rows_affected();
    let (stage, _) = locked_stage(&mut tx, id).await?;
    if stage.repository != repository || stage.owner != actor || stage.package != package {
        return Err(HostedError::Conflict(
            "stage idempotency key was used for a different request".into(),
        ));
    }
    if inserted > 0 {
        audit(
            &mut tx,
            "hosted_stage_created",
            id,
            json!({"actor":actor,"repository":repository,"package":package}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(stage)
}
pub async fn stage_files(store: &Store, id: Uuid) -> Result<Vec<HostedFile>> {
    stage(store, id).await?;
    let rows = sqlx::query(
        "SELECT path,artifact FROM hosted_files WHERE stage_id=$1 ORDER BY path LIMIT 129",
    )
    .bind(id)
    .fetch_all(&store.pool)
    .await?;
    decode_files(rows)
}
fn decode_files(rows: Vec<PgRow>) -> Result<Vec<HostedFile>> {
    if rows.len() > MAX_FILES {
        return Err(HostedError::Internal("hosted file bound exceeded".into()));
    }
    rows.into_iter()
        .map(|row| {
            Ok(HostedFile {
                path: row.try_get("path")?,
                artifact: serde_json::from_value(row.try_get("artifact")?)?,
            })
        })
        .collect()
}
async fn files_in(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<Vec<HostedFile>> {
    decode_files(
        sqlx::query(
            "SELECT path,artifact FROM hosted_files WHERE stage_id=$1 ORDER BY path LIMIT 129",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await?,
    )
}
fn file_valid(stage: &Stage, artifact: &Artifact, path: &str) -> Result<()> {
    let coordinate = crate::maven::Coordinate::new(&stage.package.name, &stage.package.version)?;
    let crate::maven::UploadKind::Artifact { filename, .. } =
        crate::maven::classify_upload(&coordinate, path)?
    else {
        return Err(HostedError::Invalid(
            "only artifact members belong in a sealed manifest".into(),
        ));
    };
    if stage.package != coordinate.package()
        || artifact.repository != stage.repository
        || artifact.package.as_ref() != Some(&stage.package)
        || artifact.filename != filename
        || artifact.size < 0
        || artifact.content_type.is_empty()
        || artifact.content_type.chars().any(char::is_control)
        || artifact.digest.len() != 64
        || !artifact
            .digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(HostedError::Invalid(
            "file does not match reserved Maven coordinates".into(),
        ));
    }
    Ok(())
}
pub async fn add_file(
    store: &Store,
    id: Uuid,
    artifact: Artifact,
    path: &str,
    actor: &str,
) -> Result<HostedFile> {
    actor_valid(actor)?;
    let mut tx = store.pool.begin().await?;
    let (stage, _) = locked_stage(&mut tx, id).await?;
    if stage.owner != actor {
        return Err(HostedError::Conflict("only stage owner may upload".into()));
    }
    if stage.state != StageState::Open {
        return Err(HostedError::Conflict("stage is no longer open".into()));
    }
    file_valid(&stage, &artifact, path)?;
    let document = serde_json::to_value(&artifact)?;
    let existing: Option<Value> =
        sqlx::query_scalar("SELECT artifact FROM hosted_files WHERE stage_id=$1 AND path=$2")
            .bind(id)
            .bind(path)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(existing) = existing {
        if existing != document {
            return Err(HostedError::Conflict(
                "hosted file binding is immutable".into(),
            ));
        }
    } else {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM hosted_files WHERE stage_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_FILES as i64 {
            return Err(HostedError::Invalid("too many hosted files".into()));
        }
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum((artifact->>'size')::bigint),0)::bigint FROM hosted_files WHERE stage_id=$1").bind(id).fetch_one(&mut *tx).await?;
        if artifact.size > MAX_RELEASE_BYTES || bytes > MAX_RELEASE_BYTES - artifact.size {
            return Err(HostedError::Invalid(
                "hosted release exceeds byte limit".into(),
            ));
        }
        sqlx::query("INSERT INTO hosted_files(stage_id,path,digest,artifact) VALUES($1,$2,$3,$4)")
            .bind(id)
            .bind(path)
            .bind(&artifact.digest)
            .bind(document)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            "hosted_file_added",
            id,
            json!({"actor":actor,"path":path,"artifact":artifact}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(HostedFile {
        path: path.into(),
        artifact,
    })
}

fn checked_config(config: &Config, stage: &Stage, files: &[HostedFile]) -> Result<()> {
    let repo = config
        .repositories
        .get(&stage.repository)
        .ok_or_else(|| HostedError::Invalid("unknown hosted repository".into()))?;
    if repo.kind != crate::config::RepositoryKind::Hosted
        || repo.ecosystem != Ecosystem::Maven
        || !repo.retain
    {
        return Err(HostedError::Invalid(
            "hosted Maven bytes must be retained".into(),
        ));
    }
    for file in files {
        file_valid(stage, &file.artifact, &file.path)?;
        let expected = config
            .public_url
            .join(&format!("r/{}/{}", stage.repository, file.path))
            .map_err(|e| HostedError::Invalid(e.to_string()))?;
        if file.artifact.origin != expected.as_str()
            || file.artifact.size as u64 > config.max_download_bytes as u64
        {
            return Err(HostedError::Invalid(
                "hosted artifact origin or size differs from final delivery".into(),
            ));
        }
        config.delivery_fingerprint(&file.artifact.scope())?;
    }
    Ok(())
}
fn manifest_from(row: &PgRow, stage: &Stage, files: Vec<HostedFile>) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_value(
        row.try_get::<Option<Value>, _>("manifest")?
            .ok_or_else(|| HostedError::Internal("sealed manifest missing".into()))?,
    )?;
    let rebuilt = Manifest {
        stage: stage.id,
        repository: stage.repository.clone(),
        package: stage.package.clone(),
        files,
    };
    if serde_json::to_value(&manifest)? != serde_json::to_value(&rebuilt)?
        || stage.manifest_digest.as_deref()
            != Some(sha256(&serde_json::to_vec(&manifest)?).as_str())
    {
        return Err(HostedError::Internal(
            "sealed manifest integrity mismatch".into(),
        ));
    }
    Ok(manifest)
}
pub async fn seal(store: &Store, id: Uuid, config: &Config, actor: &str) -> Result<SealReceipt> {
    let tx = store.pool.begin().await?;
    let (tx, receipt) = seal_in(tx, id, config, actor).await?;
    tx.commit().await?;
    Ok(receipt)
}

// Own the transaction so ordinary sealing and atomic cross-repository copying share the
// exact URL/context lock order, immutable registration, and job creation behavior.
async fn seal_in<'a>(
    mut tx: Transaction<'a, Postgres>,
    id: Uuid,
    config: &Config,
    actor: &str,
) -> Result<(Transaction<'a, Postgres>, SealReceipt)> {
    actor_valid(actor)?;
    let (mut stage, row) = locked_stage(&mut tx, id).await?;
    if matches!(stage.state, StageState::Revoked | StageState::Aborted) {
        return Err(HostedError::Conflict("stage is terminal".into()));
    }
    let files = files_in(&mut tx, id).await?;
    checked_config(config, &stage, &files)?;
    if stage.state != StageState::Open {
        let manifest = manifest_from(&row, &stage, files)?;
        let manifest_digest = stage.manifest_digest.clone().unwrap();
        return Ok((
            tx,
            SealReceipt {
                stage,
                manifest,
                manifest_digest,
            },
        ));
    }
    if files.is_empty() {
        return Err(HostedError::Invalid("cannot seal an empty stage".into()));
    }
    let name = stage.package.name.split_once(':').unwrap().1;
    if !files
        .iter()
        .any(|file| file.artifact.filename == format!("{name}-{}.pom", stage.package.version))
    {
        return Err(HostedError::Invalid(
            "release requires its exact primary POM".into(),
        ));
    }
    // Serialize final URL bindings with proxy register/claims before inserting, never upsert.
    for file in &files {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(serde_json::to_string(&(
                &file.artifact.repository,
                &file.artifact.origin,
            ))?)
            .execute(&mut *tx)
            .await?;
        let previous=sqlx::query("SELECT digest,size,filename,content_type,package FROM artifacts WHERE repository=$1 AND origin=$2 FOR UPDATE").bind(&stage.repository).bind(&file.artifact.origin).fetch_optional(&mut *tx).await?;
        if previous.is_some() {
            return Err(HostedError::Conflict(
                "final artifact URL is already registered".into(),
            ));
        }
    }
    let mut subjects: Vec<_> = files.iter().map(|f| f.artifact.digest.as_str()).collect();
    subjects.sort_unstable();
    subjects.dedup();
    for subject in subjects {
        sqlx::query("INSERT INTO contexts(subject) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(subject)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
            .bind(subject)
            .fetch_one(&mut *tx)
            .await?;
    }
    for file in &files {
        let a = &file.artifact;
        sqlx::query("INSERT INTO artifacts(repository,origin,digest,size,filename,content_type,package) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&a.repository).bind(&a.origin).bind(&a.digest).bind(a.size).bind(&a.filename).bind(&a.content_type).bind(serde_json::to_value(&a.package)?).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO jobs(id,subject,configuration,filename,context_revision,engine_configuration,scope) VALUES($1,$2,$3,$4,(SELECT revision FROM contexts WHERE subject=$2),$5,$6) ON CONFLICT(subject,configuration) DO UPDATE SET state=CASE WHEN jobs.state IN ('complete','failed') OR jobs.context_revision<>EXCLUDED.context_revision THEN 'queued' ELSE jobs.state END,attempts=CASE WHEN jobs.state IN ('complete','failed') OR jobs.context_revision<>EXCLUDED.context_revision THEN 0 ELSE jobs.attempts END,context_revision=EXCLUDED.context_revision")
            .bind(Uuid::new_v4()).bind(&a.digest).bind(config.delivery_fingerprint(&a.scope())?).bind(&a.filename).bind(config.fingerprint()).bind(serde_json::to_value(a.scope())?).execute(&mut *tx).await?;
    }
    let manifest = Manifest {
        stage: id,
        repository: stage.repository.clone(),
        package: stage.package.clone(),
        files,
    };
    let manifest_digest = sha256(&serde_json::to_vec(&manifest)?);
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE hosted_stages SET state='sealed',manifest=$2,manifest_digest=$3,sealed_at=$4 WHERE id=$1").bind(id).bind(serde_json::to_value(&manifest)?).bind(&manifest_digest).bind(now).execute(&mut *tx).await?;
    stage.state = StageState::Sealed;
    stage.manifest_digest = Some(manifest_digest.clone());
    stage.sealed_at = Some(now);
    audit(
        &mut tx,
        "hosted_stage_sealed",
        id,
        json!({"actor":actor,"manifest_digest":manifest_digest}),
    )
    .await?;
    Ok((
        tx,
        SealReceipt {
            stage,
            manifest,
            manifest_digest,
        },
    ))
}

fn validate_lineage(row: &PgRow, destination: &Stage) -> Result<CopyReceipt> {
    let mut receipt: CopyReceipt = serde_json::from_value(row.try_get("receipt")?)?;
    if receipt.source_stage != row.try_get::<Uuid, _>("source_stage_id")?
        || receipt.source_manifest_digest != row.try_get::<String, _>("source_manifest_digest")?
        || receipt.destination.stage.id != destination.id
        || receipt.destination.manifest_digest
            != row.try_get::<String, _>("destination_manifest_digest")?
        || destination.manifest_digest.as_deref()
            != Some(receipt.destination.manifest_digest.as_str())
        || receipt.destination.stage.repository != destination.repository
        || receipt.destination.stage.package != destination.package
        || receipt.destination.stage.owner != destination.owner
        || receipt.actor != row.try_get::<String, _>("actor")?
        || receipt.created_at != row.try_get::<DateTime<Utc>, _>("created_at")?
        || receipt.source_files.len() > MAX_FILES
        || receipt.destination.manifest_digest
            != sha256(&serde_json::to_vec(&receipt.destination.manifest)?)
    {
        return Err(HostedError::Internal(
            "copy receipt binding mismatch".into(),
        ));
    }
    for file in &receipt.source_files {
        if file.evidence.len() > 1024
            || file.evidence_digest != sha256(&serde_json::to_vec(&file.evidence)?)
        {
            return Err(HostedError::Internal(
                "copy source evidence integrity mismatch".into(),
            ));
        }
    }
    // A receipt is historical; retries report current destination state without reviving it.
    receipt.destination.stage = destination.clone();
    Ok(receipt)
}

pub async fn lineage(store: &Store, id: Uuid) -> Result<Option<CopyReceipt>> {
    let mut tx = store.pool.begin().await?;
    // One transaction keeps the current destination state and lineage consistent for inspection.
    let row=sqlx::query("SELECT l.receipt,l.source_stage_id,l.source_manifest_digest,l.destination_manifest_digest,l.actor,l.created_at FROM hosted_lineage l JOIN hosted_stages s ON s.id=l.destination_stage_id WHERE l.destination_stage_id=$1 FOR SHARE OF s")
        .bind(id).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let destination = stage_row(
        &sqlx::query("SELECT * FROM hosted_stages WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?,
    )?;
    let receipt = validate_lineage(&row, &destination)?;
    tx.commit().await?;
    Ok(Some(receipt))
}

/// Copy only immutable, published, currently approved bytes. Destination publication is a
/// separate decision: this transaction creates new final scopes and jobs, never evidence.
pub async fn copy_release(
    store: &Store,
    source_id: Uuid,
    config: &Config,
    request: &CopyRequest,
    actor: &str,
) -> Result<CopyReceipt> {
    actor_valid(actor)?;
    if source_id == request.id
        || request.destination_repository.is_empty()
        || request.source_manifest_digest.len() != 64
    {
        return Err(HostedError::Invalid(
            "copy requires distinct stage IDs and an exact source manifest".into(),
        ));
    }
    let mut tx = store.pool.begin().await?;
    // Serialize a caller-supplied operation ID even before its destination row exists.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("hosted-copy:{}", request.id))
        .execute(&mut *tx)
        .await?;
    // Multiple-stage operations take stage rows in UUID order, before origin/context locks.
    let rows = sqlx::query("SELECT * FROM hosted_stages WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![source_id, request.id])
        .fetch_all(&mut *tx)
        .await?;
    let source_row = rows
        .iter()
        .find(|row| row.get::<Uuid, _>("id") == source_id)
        .ok_or(HostedError::NotFound)?;
    let source = stage_row(source_row)?;
    let destination_row = rows
        .iter()
        .find(|row| row.get::<Uuid, _>("id") == request.id);
    if let Some(destination_row) = destination_row {
        let Some(record) =
            sqlx::query("SELECT * FROM hosted_lineage WHERE destination_stage_id=$1")
                .bind(request.id)
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Err(HostedError::Conflict(
                "destination stage ID already belongs to another operation".into(),
            ));
        };
        let receipt = validate_lineage(&record, &stage_row(destination_row)?)?;
        if receipt.source_stage != source_id
            || receipt.source_manifest_digest != request.source_manifest_digest
            || receipt.destination.stage.repository != request.destination_repository
            || receipt.actor != actor
        {
            return Err(HostedError::Conflict(
                "copy idempotency key was used for a different request".into(),
            ));
        }
        tx.commit().await?;
        return Ok(receipt);
    }
    if source.state != StageState::Published || source.repository == request.destination_repository
    {
        return Err(HostedError::Conflict(
            "copy requires a published source and a different repository".into(),
        ));
    }
    let source_files = files_in(&mut tx, source_id).await?;
    checked_config(config, &source, &source_files)?;
    manifest_from(source_row, &source, source_files.clone())?;
    if source.manifest_digest.as_deref() != Some(request.source_manifest_digest.as_str()) {
        return Err(HostedError::Conflict("source manifest changed".into()));
    }
    let group = source
        .package
        .namespace
        .as_deref()
        .ok_or_else(|| HostedError::Invalid("Maven group required".into()))?;
    if !config.access.owner_allowed(&source.repository, group)
        || !config
            .access
            .owner_allowed(&request.destination_repository, group)
    {
        return Err(HostedError::Invalid(
            "source or destination is outside namespace ownership".into(),
        ));
    }
    let Some(repository) = config.repositories.get(&request.destination_repository) else {
        return Err(HostedError::Invalid(
            "unknown destination repository".into(),
        ));
    };
    if repository.kind != crate::config::RepositoryKind::Hosted
        || repository.ecosystem != Ecosystem::Maven
        || !repository.retain
    {
        return Err(HostedError::Invalid(
            "destination must be retained hosted Maven storage".into(),
        ));
    }
    // Reserve before taking shared content locks. Colliding reservations roll back all work.
    sqlx::query("INSERT INTO hosted_stages(id,repository,package_name,version,package,owner) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(request.id).bind(&request.destination_repository).bind(&source.package.name).bind(&source.package.version).bind(serde_json::to_value(&source.package)?).bind(actor).execute(&mut *tx).await?;
    for file in &source_files {
        let mut artifact = file.artifact.clone();
        artifact.repository = request.destination_repository.clone();
        artifact.origin = config
            .public_url
            .join(&format!("r/{}/{}", artifact.repository, file.path))
            .map_err(|e| HostedError::Invalid(e.to_string()))?
            .to_string();
        sqlx::query("INSERT INTO hosted_files(stage_id,path,digest,artifact) VALUES($1,$2,$3,$4)")
            .bind(request.id)
            .bind(&file.path)
            .bind(&artifact.digest)
            .bind(serde_json::to_value(&artifact)?)
            .execute(&mut *tx)
            .await?;
    }
    // Sealing obtains final-origin advisory locks before sorted content locks, as every other
    // registration path does. Source approval is sampled after all of those waits.
    let (mut tx, destination) = seal_in(tx, request.id, config, actor).await?;
    let (source_evaluated_at, evidence, decision) =
        evaluate_files(&mut tx, config, &source_files).await?;
    if decision != Decision::Approved {
        return Err(HostedError::NotApproved(
            "source release is not currently approved".into(),
        ));
    }
    let created_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let receipt = CopyReceipt {
        source_stage: source.id,
        source_repository: source.repository,
        source_manifest_digest: request.source_manifest_digest.clone(),
        source_evaluated_at,
        source_files: evidence,
        destination,
        actor: actor.into(),
        created_at,
    };
    sqlx::query("INSERT INTO hosted_lineage(destination_stage_id,source_stage_id,source_manifest_digest,destination_manifest_digest,actor,created_at,receipt) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(request.id).bind(source_id).bind(&receipt.source_manifest_digest).bind(&receipt.destination.manifest_digest).bind(actor).bind(created_at).bind(serde_json::to_value(&receipt)?).execute(&mut *tx).await?;
    audit(
        &mut tx,
        "hosted_release_copied",
        request.id,
        serde_json::to_value(&receipt)?,
    )
    .await?;
    tx.commit().await?;
    Ok(receipt)
}

async fn evaluate_files(
    tx: &mut Transaction<'_, Postgres>,
    config: &Config,
    files: &[HostedFile],
) -> Result<(DateTime<Utc>, Vec<PromotionFile>, Decision)> {
    let mut subjects: Vec<_> = files.iter().map(|f| f.artifact.digest.as_str()).collect();
    subjects.sort_unstable();
    subjects.dedup();
    let mut revisions = std::collections::BTreeMap::new();
    for subject in subjects {
        let revision: Option<i64> =
            sqlx::query_scalar("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
                .bind(subject)
                .fetch_optional(&mut **tx)
                .await?;
        revisions.insert(
            subject,
            revision.ok_or_else(|| HostedError::NotApproved("artifact context missing".into()))?,
        );
    }
    // Unlike transaction_timestamp()/now(), clock_timestamp() advances while waiting for locks.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let mut evaluated = Vec::new();
    let mut denied = Vec::new();
    let mut pending = Vec::new();
    let mut total_evidence_bytes = 0i64;
    for file in files {
        let scope = file.artifact.scope();
        let configuration = config.delivery_fingerprint(&scope)?;
        let policy = config.effective_policy(&scope)?;
        let context_revision = revisions[file.artifact.digest.as_str()];
        let evidence_bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(octet_length(document::text)),0)::bigint FROM evidence WHERE subject=$1 AND configuration=$2 AND context_revision=$3 AND created_at<=$4 AND expires_at>$4")
            .bind(&file.artifact.digest).bind(&configuration).bind(context_revision).bind(now).fetch_one(&mut **tx).await?;
        total_evidence_bytes = total_evidence_bytes
            .checked_add(evidence_bytes)
            .ok_or_else(|| HostedError::NotApproved("evidence bound exceeded".into()))?;
        if total_evidence_bytes > 32 * 1024 * 1024 {
            return Err(HostedError::NotApproved(
                "release evidence exceeds receipt limit".into(),
            ));
        }
        let rows=sqlx::query("SELECT id,document FROM evidence WHERE subject=$1 AND configuration=$2 AND context_revision=$3 AND created_at<=$4 AND expires_at>$4 ORDER BY created_at,id LIMIT 1025")
            .bind(&file.artifact.digest).bind(&configuration).bind(context_revision).bind(now).fetch_all(&mut **tx).await?;
        if rows.len() > 1024 {
            return Err(HostedError::NotApproved(
                "too many current evidence records".into(),
            ));
        }
        let mut evidence = Vec::new();
        let mut bound = Vec::new();
        for row in rows {
            let document: Value = row.try_get("document")?;
            evidence.push(serde_json::from_value::<Evidence>(document.clone())?);
            bound.push(json!({"id":row.try_get::<Uuid,_>("id")?,"document":document}));
        }
        match policy
            .policy
            .evaluate(&file.artifact.digest, &configuration, &evidence, now)
        {
            Decision::Approved => {}
            Decision::Denied(reasons) => denied.extend(
                reasons
                    .into_iter()
                    .map(|reason| format!("{}: {reason}", file.path)),
            ),
            Decision::Pending(reasons) => pending.extend(
                reasons
                    .into_iter()
                    .map(|reason| format!("{}: {reason}", file.path)),
            ),
        }
        evaluated.push(PromotionFile {
            path: file.path.clone(),
            subject: file.artifact.digest.clone(),
            configuration,
            context_revision,
            policy,
            evidence_digest: sha256(&serde_json::to_vec(&bound)?),
            evidence: bound,
        });
    }
    let decision = if !denied.is_empty() {
        Decision::Denied(denied)
    } else if !pending.is_empty() {
        Decision::Pending(pending)
    } else {
        Decision::Approved
    };
    Ok((now, evaluated, decision))
}
pub async fn promote(
    store: &Store,
    id: Uuid,
    config: &Config,
    actor: &str,
) -> Result<PromotionReceipt> {
    actor_valid(actor)?;
    let mut tx = store.pool.begin().await?;
    let (mut stage, row) = locked_stage(&mut tx, id).await?;
    if stage.state != StageState::Sealed {
        return Err(HostedError::Conflict("only sealed stages can be promoted; inspect published receipts instead of replaying promotion".into()));
    }
    let files = files_in(&mut tx, id).await?;
    checked_config(config, &stage, &files)?;
    let _manifest = manifest_from(&row, &stage, files.clone())?;
    let (now, evaluated, decision) = evaluate_files(&mut tx, config, &files).await?;
    if decision != Decision::Approved {
        return Err(HostedError::NotApproved(
            "release members are not all currently approved".into(),
        ));
    }
    stage.state = StageState::Published;
    stage.published_at = Some(now);
    let receipt = PromotionReceipt {
        manifest_digest: stage.manifest_digest.clone().unwrap(),
        stage,
        actor: actor.into(),
        evaluated_at: now,
        files: evaluated,
    };
    sqlx::query("UPDATE hosted_stages SET state='published',published_at=$2,promotion_receipt=$3 WHERE id=$1").bind(id).bind(now).bind(serde_json::to_value(&receipt)?).execute(&mut *tx).await?;
    audit(
        &mut tx,
        "hosted_stage_published",
        id,
        serde_json::to_value(&receipt)?,
    )
    .await?;
    tx.commit().await?;
    Ok(receipt)
}
pub async fn revoke(store: &Store, id: Uuid, actor: &str) -> Result<Stage> {
    actor_valid(actor)?;
    let mut tx = store.pool.begin().await?;
    let (mut stage, _) = locked_stage(&mut tx, id).await?;
    if stage.state == StageState::Aborted {
        return Err(HostedError::Conflict("an aborted stage is terminal".into()));
    }
    if stage.state != StageState::Revoked {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("UPDATE hosted_stages SET state='revoked',revoked_at=$2 WHERE id=$1")
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        stage.state = StageState::Revoked;
        stage.revoked_at = Some(now);
        audit(
            &mut tx,
            "hosted_stage_revoked",
            id,
            json!({"actor":actor,"manifest_digest":stage.manifest_digest}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(stage)
}

/// Abandon an unsealed upload without deleting its history or blob references. A new UUID may
/// reserve the coordinate afterward; this stage UUID and all sealed coordinates stay immutable.
pub async fn abort(store: &Store, id: Uuid, actor: &str) -> Result<Stage> {
    actor_valid(actor)?;
    let mut tx = store.pool.begin().await?;
    let (mut stage, _) = locked_stage(&mut tx, id).await?;
    if stage.owner != actor {
        return Err(HostedError::Conflict("only stage owner may abort".into()));
    }
    match stage.state {
        StageState::Aborted => {}
        StageState::Open => {
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query("UPDATE hosted_stages SET state='aborted',aborted_at=$2 WHERE id=$1")
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            stage.state = StageState::Aborted;
            stage.aborted_at = Some(now);
            audit(
                &mut tx,
                "hosted_stage_aborted",
                id,
                json!({"actor":actor,"repository":stage.repository,"package":stage.package}),
            )
            .await?;
        }
        _ => {
            return Err(HostedError::Conflict(
                "only an open stage may be aborted".into(),
            ));
        }
    }
    tx.commit().await?;
    Ok(stage)
}
pub async fn published_file(
    store: &Store,
    repository: &str,
    path: &str,
) -> Result<Option<(Stage, Artifact)>> {
    let row=sqlx::query("SELECT s.*,f.artifact FROM hosted_stages s JOIN hosted_files f ON f.stage_id=s.id WHERE s.repository=$1 AND f.path=$2 AND s.state='published'")
        .bind(repository).bind(path).fetch_optional(&store.pool).await?;
    row.map(|row| {
        Ok((
            stage_row(&row)?,
            serde_json::from_value(row.try_get("artifact")?)?,
        ))
    })
    .transpose()
}
pub async fn published_versions(
    store: &Store,
    repository: &str,
    package: &str,
) -> Result<Vec<String>> {
    let versions=sqlx::query_scalar("SELECT version FROM hosted_stages WHERE repository=$1 AND package_name=$2 AND state='published' ORDER BY version LIMIT 1025")
        .bind(repository).bind(package).fetch_all(&store.pool).await?;
    if versions.len() > 1024 {
        return Err(HostedError::Invalid(
            "too many hosted versions for metadata".into(),
        ));
    }
    Ok(versions)
}
pub async fn promotion_receipt(store: &Store, id: Uuid) -> Result<Option<PromotionReceipt>> {
    let receipt: Option<Value> =
        sqlx::query_scalar("SELECT promotion_receipt FROM hosted_stages WHERE id=$1")
            .bind(id)
            .fetch_optional(&store.pool)
            .await?
            .ok_or(HostedError::NotFound)?;
    receipt
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

/// The grant linearizes while holding publication and context locks. Later revocation cannot
/// recall an already issued response; any subsequent grant rechecks membership and all files.
pub async fn delivery(
    store: &Store,
    repository: &str,
    path: &str,
    config: &Config,
) -> Result<Option<Delivery>> {
    let mut tx = store.pool.begin().await?;
    let row=sqlx::query("SELECT s.* FROM hosted_stages s JOIN hosted_files f ON f.stage_id=s.id WHERE s.repository=$1 AND f.path=$2 AND s.state='published' FOR UPDATE OF s")
        .bind(repository).bind(path).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let stage = stage_row(&row)?;
    let files = files_in(&mut tx, stage.id).await?;
    checked_config(config, &stage, &files)?;
    let _manifest = manifest_from(&row, &stage, files.clone())?;
    let artifact = files
        .iter()
        .find(|file| file.path == path)
        .ok_or_else(|| HostedError::Internal("published file missing from manifest".into()))?
        .artifact
        .clone();
    let (_, _, decision) = evaluate_files(&mut tx, config, &files).await?;
    let configuration = config.delivery_fingerprint(&artifact.scope())?;
    tx.commit().await?;
    Ok(Some(Delivery {
        stage,
        artifact,
        configuration,
        decision,
    }))
}
