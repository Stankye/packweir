//! Immutable, context-bound derived products. These never enter package routing
//! or the document input bundle and never inherit a parent's approval.
use crate::{
    gateway::{self, AppState},
    model::{Evidence, sha256},
    storage::BlobStore,
    store::Job,
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;

pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Constructed only after provider-neutral manifest validation by the engine.
/// Persistence additionally binds the complete manifest to producing evidence.
pub struct OutputDraft {
    pub check_name: String,
    manifest: Arc<Value>,
    manifest_sha256: String,
    input_sha256: String,
    producer_identity_sha256: String,
    output_sha256: String,
    kind: String,
    media_type: String,
    derivation_sha256: String,
    metadata: Value,
    bytes: Vec<u8>,
}

impl OutputDraft {
    pub fn from_manifest(
        check_name: &str,
        manifest: &Value,
        logical_paths: &[String],
    ) -> Result<Vec<Self>> {
        ensure!(
            !check_name.is_empty() && check_name.len() <= 128,
            "invalid derived-output check"
        );
        ensure!(
            serde_json::to_vec(manifest)?.len() <= 512 * 1024,
            "derived manifest exceeds limit"
        );
        ensure!(
            logical_paths.len() <= 256
                && logical_paths
                    .iter()
                    .all(|p| p.len() <= 4096 && crate::bounds::safe_path(p)),
            "invalid derived input paths"
        );
        let input = text(manifest, "/input/sha256")?;
        let identity = text(manifest, "/producer/identity_sha256")?;
        crate::oci::validate_subject(&input)?;
        crate::oci::validate_subject(&identity)?;
        let manifest_sha256 = sha256(&serde_json::to_vec(manifest)?);
        let manifest = Arc::new(manifest.clone());
        let outputs = manifest["outputs"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("derived outputs missing"))?;
        ensure!(outputs.len() <= 256, "too many derived outputs");
        let mut total = 0usize;
        let mut metadata_bytes = 0usize;
        let mut drafts = Vec::new();
        for output in outputs {
            let encoded = output["data_base64"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("derived output data missing"))?;
            ensure!(
                encoded.len() <= MAX_OUTPUT_BYTES.div_ceil(3) * 4,
                "derived output exceeds limit"
            );
            let bytes = STANDARD.decode(encoded)?;
            ensure!(
                bytes.len() <= MAX_OUTPUT_BYTES && STANDARD.encode(&bytes) == encoded,
                "derived output is not canonical bounded base64"
            );
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| anyhow::anyhow!("derived output size overflow"))?;
            ensure!(total <= 256 * 1024, "derived manifest outputs exceed limit");
            let output_sha256 = text(output, "/sha256")?;
            ensure!(
                sha256(&bytes) == output_sha256
                    && output["size"].as_u64() == Some(bytes.len() as u64),
                "derived output bytes differ from descriptor"
            );
            let kind = text(output, "/kind")?;
            ensure!(
                matches!(kind.as_str(), "decompiled_c" | "pcode" | "decoded_bytes"),
                "invalid derived output kind"
            );
            let media_type = text(output, "/media_type")?;
            ensure!(
                media_type.len() <= 128 && !media_type.chars().any(char::is_control),
                "invalid derived output media type"
            );
            let derivation = &output["derivation"];
            ensure!(
                derivation.is_object() && derivation["input_sha256"] == input,
                "derived output input differs"
            );
            let derivation_sha256 = sha256(&serde_json::to_vec(derivation)?);
            let mut descriptor = output.clone();
            descriptor
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("invalid output descriptor"))?
                .remove("data_base64");
            let metadata = json!({"manifest_sha256":manifest_sha256,"input_sha256":input,
                "producer_identity_sha256":identity,"logical_paths":logical_paths,
                "producer":manifest["producer"],"analysis":manifest["analysis"],"output":descriptor,
                "approval_effect":"none","trust_scope":"qualified_tool_observation"});
            metadata_bytes = metadata_bytes
                .checked_add(serde_json::to_vec(&metadata)?.len())
                .ok_or_else(|| anyhow::anyhow!("derived metadata overflow"))?;
            ensure!(
                metadata_bytes <= MAX_BATCH_BYTES,
                "derived metadata exceeds limit"
            );
            drafts.push(Self {
                check_name: check_name.into(),
                manifest: Arc::clone(&manifest),
                manifest_sha256: manifest_sha256.clone(),
                input_sha256: input.clone(),
                producer_identity_sha256: identity.clone(),
                output_sha256,
                kind,
                media_type,
                derivation_sha256,
                metadata,
                bytes,
            });
        }
        Ok(drafts)
    }
}

fn text(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("derived output field missing: {pointer}"))
}

pub(crate) async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    job: &Job,
    evidence: &[Evidence],
    evidence_ids: &BTreeMap<String, Uuid>,
    outputs: &[OutputDraft],
    blobs: &BlobStore,
) -> Result<()> {
    ensure!(outputs.len() <= 256, "derived output count exceeds limit");
    let mut total = 0usize;
    let mut metadata_bytes = 0usize;
    let mut metadata_records = Vec::new();
    let mut digests = BTreeSet::new();
    for output in outputs {
        let finding = evidence
            .iter()
            .find(|e| e.check == output.check_name)
            .ok_or_else(|| anyhow::anyhow!("producing evidence missing"))?;
        let manifests = finding.details["binary_analysis"]["manifests"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("producing binary analysis manifests missing"))?;
        let entry = manifests
            .iter()
            .find(|item| {
                item["manifest_sha256"] == output.manifest_sha256
                    && item["manifest"] == *output.manifest
            })
            .ok_or_else(|| anyhow::anyhow!("derived output does not match producing evidence"))?;
        let mut metadata = output.metadata.clone();
        let normalized = entry["validation"]["outputs"]
            .as_array()
            .and_then(|records| {
                records.iter().find(|record| {
                    record["sha256"] == output.output_sha256
                        && record["kind"] == output.kind
                        && record["derivation"] == metadata["output"]["derivation"]
                })
            });
        // Digest/source-span checks do not prove that decompiled code is
        // semantically equivalent to the original executable. Preserve exact
        // engine validation instead of inventing a general "verified" verdict.
        metadata["validation"] = normalized.cloned().unwrap_or_else(|| {
            json!({
            "source_spans_verified":null,"xor_recomputed":null,
            "semantic_equivalence_verified":false,"basis":"no_engine_validation_supplied"})
        });
        metadata["manifest_validation"] = json!({"complete":entry["validation"]["complete"],
            "input_bytes_verified":entry["validation"]["input_bytes_verified"],
            "reasons":entry["validation"]["reasons"],
            "informational_warning_policy":entry["validation"]["informational_warning_policy"],
            "acknowledged_warnings":entry["validation"]["acknowledged_warnings"],
            "unacknowledged_warnings":entry["validation"]["unacknowledged_warnings"]});
        metadata["service_validation"] = entry["service_validation"].clone();
        ensure!(
            evidence_ids.contains_key(&output.check_name),
            "producing evidence identity missing"
        );
        total = total
            .checked_add(output.bytes.len())
            .ok_or_else(|| anyhow::anyhow!("derived size overflow"))?;
        metadata_bytes = metadata_bytes
            .checked_add(serde_json::to_vec(&metadata)?.len())
            .ok_or_else(|| anyhow::anyhow!("derived metadata overflow"))?;
        ensure!(
            total <= MAX_BATCH_BYTES && metadata_bytes <= MAX_BATCH_BYTES,
            "derived output batch exceeds limit"
        );
        digests.insert(output.output_sha256.as_str());
        metadata_records.push(metadata);
    }
    // This is the same sorted digest-lock namespace used by evidence imports
    // and non-retaining package deletion. References and bytes become visible
    // together; a racing package delivery cannot delete a new derived product.
    for digest in digests {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('packweir.cas.retention:' || $1,0))",
        )
        .bind(digest)
        .execute(&mut **tx)
        .await?;
    }
    for (output, metadata) in outputs.iter().zip(metadata_records) {
        ensure!(
            blobs.put(output.bytes.clone()).await? == output.output_sha256,
            "derived CAS digest differs"
        );
        sqlx::query("INSERT INTO analysis_outputs(id,evidence_id,job_id,subject,configuration,context_revision,check_name,manifest_sha256,input_sha256,producer_identity_sha256,output_sha256,kind,media_type,size,derivation_sha256,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT DO NOTHING")
            .bind(Uuid::new_v4()).bind(evidence_ids[&output.check_name]).bind(job.id).bind(&job.subject)
            .bind(&job.configuration).bind(job.context_revision).bind(&output.check_name).bind(&output.manifest_sha256)
            .bind(&output.input_sha256).bind(&output.producer_identity_sha256).bind(&output.output_sha256)
            .bind(&output.kind).bind(&output.media_type).bind(output.bytes.len() as i64)
            .bind(&output.derivation_sha256).bind(&metadata).execute(&mut **tx).await?;
    }
    Ok(())
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/artifacts/{digest}/analysis-outputs", get(list))
        .route(
            "/api/v1/artifacts/{digest}/analysis-outputs/{id}",
            get(download),
        )
        .route_layer(middleware::from_fn_with_state(state, gateway::admin_auth))
}

fn failure(status: StatusCode, error: &'static str) -> Response {
    (status, Json(json!({"error":error}))).into_response()
}

async fn list(State(state): State<AppState>, Path(subject): Path<String>) -> Response {
    if crate::oci::validate_subject(&subject).is_err() {
        return failure(StatusCode::BAD_REQUEST, "invalid_subject");
    }
    let rows = sqlx::query("WITH selected AS MATERIALIZED (SELECT to_jsonb(o) AS document FROM analysis_outputs o WHERE subject=$1 ORDER BY created_at,id), bounds AS (SELECT count(*) AS records,COALESCE(sum(octet_length(document::text)),0)::bigint AS bytes FROM selected) SELECT bounds.records,bounds.bytes,selected.document FROM bounds LEFT JOIN selected ON bounds.records<=1024 AND bounds.bytes<=8388608")
        .bind(&subject).fetch_all(&state.store.pool).await;
    match rows {
        Ok(rows)
            if rows.first().is_some_and(|r| {
                r.get::<i64, _>("records") <= 1024 && r.get::<i64, _>("bytes") <= 8 * 1024 * 1024
            }) =>
        {
            let records: Vec<Value> = rows
                .into_iter()
                .filter_map(|r| r.get::<Option<Value>, _>("document"))
                .collect();
            (
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({"subject":subject,"approval_effect":"none","outputs":records})),
            )
                .into_response()
        }
        _ => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "analysis_outputs_unavailable",
        ),
    }
}

async fn download(
    State(state): State<AppState>,
    Path((subject, id)): Path<(String, Uuid)>,
) -> Response {
    if crate::oci::validate_subject(&subject).is_err() {
        return failure(StatusCode::BAD_REQUEST, "invalid_subject");
    }
    let result: Result<Option<(String, Vec<u8>)>> = async {
        let row = sqlx::query(
            "SELECT output_sha256,size FROM analysis_outputs WHERE id=$1 AND subject=$2",
        )
        .bind(id)
        .bind(&subject)
        .fetch_optional(&state.store.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let digest: String = row.get("output_sha256");
        let bytes = state.blobs.read_bounded(&digest, MAX_OUTPUT_BYTES).await?;
        ensure!(
            bytes.len() as i64 == row.get::<i64, _>("size"),
            "derived output size differs"
        );
        Ok(Some((digest, bytes)))
    }
    .await;
    match result {
        Ok(Some((digest, bytes))) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_DISPOSITION, "attachment"),
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (
                    header::HeaderName::from_static("x-packweir-sha256"),
                    digest.as_str(),
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => failure(StatusCode::NOT_FOUND, "analysis_output_not_found"),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "analysis_output_unavailable",
        ),
    }
}
