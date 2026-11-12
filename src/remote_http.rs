//! Administrative diagnostics and explicit recovery of ambiguous remote submissions.
use crate::{
    gateway::{self, AppState},
    remote_analysis,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/artifacts/{digest}/remote-analysis", get(list))
        .route(
            "/api/v1/artifacts/{digest}/remote-analysis/{id}",
            get(detail),
        )
        .route(
            "/api/v1/artifacts/{digest}/remote-analysis/{id}/reconcile",
            post(reconcile),
        )
        .route_layer(middleware::from_fn_with_state(state, gateway::admin_auth))
}
fn response(value: Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}
fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error":code}))).into_response()
}
async fn list(State(state): State<AppState>, Path(subject): Path<String>) -> Response {
    if crate::oci::validate_subject(&subject).is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    let rows = sqlx::query_scalar::<_,Value>("SELECT to_jsonb(r)-'output'-'submission_token'-'submission_lease' FROM remote_analysis r WHERE subject=$1 ORDER BY created_at,id LIMIT 257")
        .bind(&subject).fetch_all(&state.store.pool).await;
    match rows {
        Ok(rows) if rows.len() <= 256 => response(json!({"subject":subject,"analyses":rows})),
        _ => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "remote_analysis_unavailable",
        ),
    }
}
async fn detail(
    State(state): State<AppState>,
    Path((subject, id)): Path<(String, Uuid)>,
) -> Response {
    if crate::oci::validate_subject(&subject).is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid_digest");
    }
    match sqlx::query_scalar::<_,Value>("SELECT to_jsonb(r)-'submission_token'-'submission_lease' FROM remote_analysis r WHERE subject=$1 AND id=$2")
        .bind(&subject).bind(id).fetch_optional(&state.store.pool).await {
        Ok(Some(value)) => response(value),
        Ok(None) => error(StatusCode::NOT_FOUND,"remote_analysis_not_found"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE,"remote_analysis_unavailable"),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconcile {
    submission_id: String,
}
async fn reconcile(
    State(state): State<AppState>,
    Path((subject, id)): Path<(String, Uuid)>,
    Json(input): Json<Reconcile>,
) -> Response {
    if crate::oci::validate_subject(&subject).is_err()
        || crate::assemblyline_http::validate_sid(&input.submission_id).is_err()
    {
        return error(StatusCode::BAD_REQUEST, "invalid_remote_analysis_binding");
    }
    let check = async {
        let row = sqlx::query("SELECT r.check_name,r.configuration,r.service_fingerprint,j.scope FROM remote_analysis r JOIN jobs j ON j.id=r.job_id WHERE r.id=$1 AND r.subject=$2")
            .bind(id).bind(&subject).fetch_optional(&state.store.pool).await?;
        let Some(row) = row else { return Ok::<_,anyhow::Error>(false); };
        let check: String = row.get("check_name");
        let Some(profile) = state.config.remote_scanners.get(&check) else { return Ok(false); };
        let scope: Option<Value> = row.get("scope");
        let configuration = match scope {
            Some(scope) => state.config.delivery_fingerprint(&serde_json::from_value(scope)?)?,
            None => state.config.fingerprint(),
        };
        Ok(configuration == row.get::<String,_>("configuration")
            && profile.assemblyline().fingerprint() == row.get::<String,_>("service_fingerprint"))
    }.await;
    match check {
        Ok(true) => {}
        Ok(false) => {
            return error(
                StatusCode::CONFLICT,
                "remote_analysis_configuration_changed_or_not_found",
            );
        }
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "remote_analysis_unavailable",
            );
        }
    }
    match remote_analysis::reconcile(&state.store, id, &subject, &input.submission_id).await {
        Ok(record) => response(
            json!({"id":record.id,"subject":record.subject,"submission_id":record.remote_id,
            "state":record.state,"approval_effect":"none","next_action":"worker must verify the original subject, correlation, effective parameters, and full service results"}),
        ),
        Err(_) => error(StatusCode::CONFLICT, "remote_analysis_not_reconcilable"),
    }
}
