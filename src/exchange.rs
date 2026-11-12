//! Administrative OCI evidence exchange. Imported statements remain foreign claims:
//! no imported outcome, decision, document origin, or source context grants approval.
use crate::{
    explain,
    gateway::{self, AppState},
    model::{Artifact, Evidence, sha256},
    oci::{self, EncodedBlob, Transfer, ValidatedBundle},
    store::policy_evidence_rows,
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use uuid::Uuid;

const ENVELOPE_BYTES: usize = 1024 * 1024;
const DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const DOCUMENT_TOTAL_BYTES: usize = 32 * 1024 * 1024;

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/artifacts/{digest}/evidence-export", get(export))
        .route("/api/v1/artifacts/{digest}/evidence-import", post(import))
        .route("/api/v1/artifacts/{digest}/evidence-imports", get(imports))
        .route(
            "/api/v1/artifacts/{digest}/evidence-imports/{id}",
            get(receipt),
        )
        .route(
            "/api/v1/artifacts/{digest}/evidence-imports/{id}/export",
            get(import_export),
        )
        .layer(DefaultBodyLimit::max(oci::MAX_TRANSFER_BYTES))
        .route_layer(middleware::from_fn(request_timeout))
        .route_layer(middleware::from_fn_with_state(state, gateway::admin_auth))
}

async fn request_timeout(request: Request, next: Next) -> Response {
    match tokio::time::timeout(Duration::from_secs(60), next.run(request)).await {
        Ok(response) => response,
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "evidence_exchange_timeout"),
    }
}

fn failure(status: StatusCode, error: &'static str) -> Response {
    (status, Json(json!({"error":error}))).into_response()
}

fn json_response(value: impl serde::Serialize) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

fn valid_subject(subject: &str) -> bool {
    subject.len() == 64
        && subject
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

async fn known(state: &AppState, subject: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest=$1)")
            .bind(subject)
            .fetch_one(&state.store.pool)
            .await?,
    )
}

/// Fetch a complete bounded set. PostgreSQL evaluates the bounds before returning
/// any potentially large JSON, so an oversize snapshot never masquerades as complete.
async fn rows(
    tx: &mut Transaction<'_, Postgres>,
    subject: &str,
    selection: &str,
    max_records: i64,
    max_bytes: i64,
) -> Result<Vec<Value>> {
    let query = format!(
        "WITH selected AS MATERIALIZED (SELECT document,row_number() OVER () AS ordinal FROM ({selection}) AS source), \
         bounds AS (SELECT count(*) AS records,COALESCE(sum(octet_length(document::text)),0)::bigint AS bytes FROM selected) \
         SELECT bounds.records,bounds.bytes,selected.document FROM bounds LEFT JOIN selected \
         ON bounds.records<=$2 AND bounds.bytes<=$3 ORDER BY selected.ordinal"
    );
    let result = sqlx::query(&query)
        .bind(subject)
        .bind(max_records)
        .bind(max_bytes)
        .fetch_all(&mut **tx)
        .await?;
    let bounds = result.first().expect("aggregate returns bounds");
    ensure!(
        bounds.get::<i64, _>("records") <= max_records
            && bounds.get::<i64, _>("bytes") <= max_bytes,
        "evidence snapshot exceeds bounded complete-set limits"
    );
    Ok(result
        .into_iter()
        .filter_map(|r| r.get::<Option<Value>, _>("document"))
        .collect())
}

fn bounded_envelope_part(value: &Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(value)?.len() <= ENVELOPE_BYTES,
        "evidence envelope exceeds 1 MiB"
    );
    Ok(())
}

/// Capture metadata in one database snapshot and use that database clock for all
/// freshness decisions. CAS reads then verify each exact document byte sequence.
pub async fn snapshot_bundle(state: &AppState, subject: &str) -> Result<ValidatedBundle> {
    ensure!(valid_subject(subject), "invalid artifact SHA-256");
    let mut tx = state.store.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM contexts WHERE subject=$1")
            .bind(subject)
            .fetch_optional(&mut *tx)
            .await?;
    let revision = revision.unwrap_or(0);
    let artifacts = rows(&mut tx, subject,
        "SELECT to_jsonb(a) AS document FROM artifacts a WHERE digest=$1 ORDER BY repository,origin",
        256, 1024 * 1024).await?;
    ensure!(!artifacts.is_empty(), "artifact not registered");
    let evidence = rows(&mut tx, subject,
        "SELECT to_jsonb(e) AS document FROM evidence e WHERE subject=$1 AND context_revision=COALESCE((SELECT revision FROM contexts WHERE subject=$1),0) ORDER BY configuration,created_at,id",
        1024, 32 * 1024 * 1024).await?;
    let documents = rows(
        &mut tx,
        subject,
        "SELECT to_jsonb(d) AS document FROM documents d WHERE subject=$1 ORDER BY created_at,id",
        256,
        1024 * 1024,
    )
    .await?;
    let decisions = rows(&mut tx, subject,
        "SELECT to_jsonb(d) AS document FROM (SELECT DISTINCT ON(repository,configuration) * FROM decisions WHERE subject=$1 ORDER BY repository,configuration,created_at DESC,id DESC) d",
        1024, 32 * 1024 * 1024).await?;
    let jobs = rows(&mut tx, subject,
        "SELECT to_jsonb(j)-'lease_token' AS document FROM jobs j WHERE subject=$1 ORDER BY configuration,id",
        256, 1024 * 1024).await?;
    let mut snapshot = json!({
        "context_revision":revision,
        "engine_configuration":state.config.fingerprint(),
        "database_snapshot":{"isolation":"repeatable_read","time":now},
        "artifact_scopes":[], "evidence":evidence,"documents":documents,
        "recorded_decisions":decisions,"jobs":jobs,
        "omissions":[
            {"domain":"original_package_bytes","reason":"not included in evidence exchange v1"},
            {"domain":"evidence_prior_contexts","reason":"only the captured source context is exported"},
            {"domain":"decision_history","reason":"latest recorded decision per repository and configuration only"},
            {"domain":"external_imports","reason":"foreign imports are not local evidence or scanner inputs"},
            {"domain":"job_lease_tokens","reason":"operational credentials omitted"}
        ]
    });
    bounded_envelope_part(&snapshot)?;
    let mut scopes = Vec::new();
    for raw in artifacts {
        let artifact: Artifact = serde_json::from_value(raw.clone())?;
        let repository = state.config.repositories.get(&artifact.repository);
        let mut entry = json!({"artifact":raw,"configured_repository":repository.is_some(),
            "repository_configuration":repository});
        if repository.is_some() {
            let scope = artifact.scope();
            let configuration = state.config.delivery_fingerprint(&scope)?;
            let policy = state.config.effective_policy(&scope)?;
            let selected =
                policy_evidence_rows(&mut *tx, subject, &configuration, Some(revision), now)
                    .await?;
            let history: Vec<Evidence> = selected
                .rows
                .into_iter()
                .map(|(_, value)| serde_json::from_value(value))
                .collect::<std::result::Result<_, _>>()?;
            entry["configuration"] = json!(configuration);
            entry["policy"] = serde_json::to_value(&policy)?;
            entry["explanation"] = serde_json::to_value(explain::scope(
                subject,
                scope,
                configuration,
                policy,
                &history,
                now,
            ))?;
        } else {
            entry["omission"] = json!({"domain":"current_policy_explanation","reason":"source repository is no longer configured"});
        }
        scopes.push(entry);
        snapshot["artifact_scopes"] = json!(&scopes);
        bounded_envelope_part(&snapshot)?;
    }
    tx.commit().await?;
    let mut blobs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for document in snapshot["documents"].as_array().expect("document array") {
        let digest = document["blob_digest"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid stored document digest"))?;
        if !seen.insert(digest.to_owned()) {
            continue;
        }
        let bytes = state.blobs.read_bounded(digest, DOCUMENT_BYTES).await?;
        ensure!(bytes.len() <= DOCUMENT_BYTES, "document exceeds 8 MiB");
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("document size overflow"))?;
        ensure!(total <= DOCUMENT_TOTAL_BYTES, "document set exceeds 32 MiB");
        // BlobStore::read verifies the raw digest before anything is exported.
        ensure!(
            sha256(&bytes) == digest,
            "stored document integrity failure"
        );
        blobs.push(bytes);
    }
    oci::build_bundle(
        subject,
        json!({
            "application":"packweir","version":env!("CARGO_PKG_VERSION"),
            "public_url":state.config.public_url,"snapshot_time":now,
            "context_revision":revision,"engine_configuration":state.config.fingerprint(),
            "claims_status":"source_snapshot_not_independent_verification"
        }),
        snapshot,
        blobs,
    )
}

async fn export(State(state): State<AppState>, Path(subject): Path<String>) -> Response {
    if !valid_subject(&subject) {
        return failure(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    match known(&state, &subject).await {
        Ok(false) => return failure(StatusCode::NOT_FOUND, "artifact_not_registered"),
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence_exchange_unavailable",
            );
        }
        Ok(true) => {}
    }
    match snapshot_bundle(&state, &subject).await {
        Ok(bundle) => json_response(bundle.transfer()),
        Err(error) => {
            tracing::warn!(%error, "evidence snapshot unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence_snapshot_unavailable",
            )
        }
    }
}

fn receipt_value(row: &sqlx::postgres::PgRow) -> Value {
    json!({"id":row.get::<Uuid,_>("id"),"subject":row.get::<String,_>("subject"),
        "manifest_digest":row.get::<String,_>("manifest_digest"),
        "imported_at":row.get::<DateTime<Utc>,_>("imported_at"),
        "source":row.get::<Value,_>("source"),
        "verified":false,"trust_status":"unverified","approval_effect":"none",
        "source_context_status":"historical_foreign_claim",
        "document_origin_status":"foreign_claim_including_artifact_observed"})
}

/// Register only this archive's metadata, audit event, and CAS references in one
/// transaction. Shared digest locks prevent non-retaining package delivery from
/// deleting bytes while their archive references are being committed. CAS writes
/// can still precede rollback and leave reclaimable orphans.
pub async fn register_bundle(
    state: &AppState,
    subject: &str,
    bundle: &ValidatedBundle,
) -> Result<(Value, bool)> {
    ensure!(
        valid_subject(subject) && bundle.envelope().subject == subject,
        "OCI subject mismatch"
    );
    let mut tx = state.store.pool.begin().await?;
    ensure!(
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest=$1)")
            .bind(subject)
            .fetch_one(&mut *tx)
            .await?,
        "artifact not registered"
    );
    let mut digests: BTreeSet<&str> = bundle
        .blobs()
        .keys()
        .map(|d| d.strip_prefix("sha256:").expect("validated OCI digest"))
        .collect();
    digests.insert(
        bundle
            .manifest_digest()
            .strip_prefix("sha256:")
            .expect("validated manifest digest"),
    );
    for digest in digests {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('packweir.cas.retention:' || $1,0))",
        )
        .bind(digest)
        .execute(&mut *tx)
        .await?;
    }
    let manifest = state.blobs.put(bundle.manifest_bytes().to_vec()).await?;
    ensure!(
        format!("sha256:{manifest}") == bundle.manifest_digest(),
        "manifest digest mismatch"
    );
    let mut blob_refs = BTreeMap::new();
    blob_refs.insert(
        manifest.clone(),
        (bundle.manifest_bytes().len() as i64, true),
    );
    for (digest, bytes) in bundle.blobs() {
        let stored = state.blobs.put(bytes.clone()).await?;
        ensure!(
            format!("sha256:{stored}") == *digest,
            "blob digest mismatch"
        );
        blob_refs
            .entry(stored)
            .or_insert((bytes.len() as i64, false));
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query("INSERT INTO external_imports(id,subject,manifest_digest,source,snapshot_metadata) VALUES($1,$2,$3,$4,$5) ON CONFLICT(subject,manifest_digest) DO NOTHING")
        .bind(id).bind(subject).bind(bundle.manifest_digest()).bind(&bundle.envelope().source)
        .bind(&bundle.envelope().snapshot).execute(&mut *tx).await?.rows_affected() == 1;
    if inserted {
        for (digest, (size, is_manifest)) in blob_refs {
            sqlx::query("INSERT INTO external_import_blobs(import_id,digest,size,is_manifest) VALUES($1,$2,$3,$4)")
                .bind(id).bind(digest).bind(size).bind(is_manifest).execute(&mut *tx).await?;
        }
        sqlx::query(
            "INSERT INTO audit(action,subject,details) VALUES('external_evidence_imported',$1,$2)",
        )
        .bind(subject)
        .bind(
            json!({"import_id":id,"manifest_digest":bundle.manifest_digest(),
                "verified":false,"trust_status":"unverified","approval_effect":"none"}),
        )
        .execute(&mut *tx)
        .await?;
    }
    let row = sqlx::query("SELECT * FROM external_imports WHERE subject=$1 AND manifest_digest=$2")
        .bind(subject)
        .bind(bundle.manifest_digest())
        .fetch_one(&mut *tx)
        .await?;
    let receipt = receipt_value(&row);
    tx.commit().await?;
    Ok((receipt, inserted))
}

async fn import(
    State(state): State<AppState>,
    Path(subject): Path<String>,
    request: Request,
) -> Response {
    if !valid_subject(&subject) {
        return failure(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    match known(&state, &subject).await {
        Ok(false) => return failure(StatusCode::NOT_FOUND, "artifact_not_registered"),
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence_exchange_unavailable",
            );
        }
        Ok(true) => {}
    }
    let bytes = match to_bytes(request.into_body(), oci::MAX_TRANSFER_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return failure(StatusCode::PAYLOAD_TOO_LARGE, "evidence_transfer_too_large"),
    };
    let bundle = match oci::parse_transfer(&bytes) {
        Ok(bundle) if bundle.envelope().subject == subject => bundle,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_evidence_transfer"),
    };
    match register_bundle(&state, &subject, &bundle).await {
        Ok((receipt, inserted)) => (
            if inserted {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            [(header::CACHE_CONTROL, "no-store")],
            Json(receipt),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(%error, "external evidence registration unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence_exchange_unavailable",
            )
        }
    }
}

async fn imports(State(state): State<AppState>, Path(subject): Path<String>) -> Response {
    if !valid_subject(&subject) {
        return failure(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    let result = async {
        if !known(&state, &subject).await? { return Ok(failure(StatusCode::NOT_FOUND, "artifact_not_registered")); }
        // A listing contains bounded receipt summaries. The individual receipt
        // retains source claims, and exact bundle readback retains the snapshot.
        let rows = sqlx::query("SELECT id,subject,manifest_digest,imported_at,'null'::jsonb AS source FROM external_imports WHERE subject=$1 ORDER BY imported_at,id LIMIT 1025")
            .bind(&subject).fetch_all(&state.store.pool).await?;
        ensure!(rows.len() <= 1024, "import listing exceeds 1024 records");
        Ok::<_,anyhow::Error>(json_response(json!({"subject":subject,"imports":rows.iter().map(receipt_value).collect::<Vec<_>>()})))
    }.await;
    result.unwrap_or_else(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_exchange_unavailable",
        )
    })
}

async fn receipt(
    State(state): State<AppState>,
    Path((subject, id)): Path<(String, Uuid)>,
) -> Response {
    if !valid_subject(&subject) {
        return failure(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    match sqlx::query("SELECT * FROM external_imports WHERE subject=$1 AND id=$2")
        .bind(subject)
        .bind(id)
        .fetch_optional(&state.store.pool)
        .await
    {
        Ok(Some(row)) => json_response(receipt_value(&row)),
        Ok(None) => failure(StatusCode::NOT_FOUND, "evidence_import_not_found"),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_exchange_unavailable",
        ),
    }
}

async fn read_import(state: &AppState, subject: &str, id: Uuid) -> Result<Option<Transfer>> {
    let manifest: Option<String> = sqlx::query_scalar(
        "SELECT manifest_digest FROM external_imports WHERE subject=$1 AND id=$2",
    )
    .bind(subject)
    .bind(id)
    .fetch_optional(&state.store.pool)
    .await?;
    let Some(manifest_digest) = manifest else {
        return Ok(None);
    };
    let references = sqlx::query("SELECT digest,size,is_manifest FROM external_import_blobs WHERE import_id=$1 ORDER BY digest")
        .bind(id).fetch_all(&state.store.pool).await?;
    ensure!(references.len() <= 260, "import has too many blobs");
    let mut manifest = None;
    let mut blobs = BTreeMap::new();
    let mut total = 0usize;
    for row in references {
        let digest: String = row.get("digest");
        let expected_size: i64 = row.get("size");
        ensure!(
            (0..=DOCUMENT_BYTES as i64).contains(&expected_size),
            "stored import blob exceeds bounds"
        );
        let bytes = state
            .blobs
            .read_bounded(&digest, expected_size as usize)
            .await?;
        ensure!(
            bytes.len() as i64 == expected_size,
            "stored import size mismatch"
        );
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("import size overflow"))?;
        ensure!(
            total <= oci::MAX_TRANSFER_BYTES,
            "stored import exceeds bounds"
        );
        let encoded = EncodedBlob(STANDARD.encode(bytes));
        if row.get::<bool, _>("is_manifest") {
            manifest = Some(encoded);
        } else {
            blobs.insert(format!("sha256:{digest}"), encoded);
        }
    }
    let transfer = Transfer {
        manifest_digest,
        manifest: manifest.ok_or_else(|| anyhow::anyhow!("import manifest missing"))?,
        blobs,
    };
    let bundle = oci::validate_transfer(transfer)?;
    ensure!(
        bundle.envelope().subject == subject,
        "stored import subject mismatch"
    );
    Ok(Some(bundle.transfer()))
}

async fn import_export(
    State(state): State<AppState>,
    Path((subject, id)): Path<(String, Uuid)>,
) -> Response {
    if !valid_subject(&subject) {
        return failure(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    match read_import(&state, &subject, id).await {
        Ok(Some(transfer)) => json_response(transfer),
        Ok(None) => failure(StatusCode::NOT_FOUND, "evidence_import_not_found"),
        Err(error) => {
            tracing::warn!(%error, "stored external evidence unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence_exchange_unavailable",
            )
        }
    }
}
