//! Hosted release control plane. Publishing credentials never confer administrative access.
use crate::{
    access::{Action, Principal},
    config::RepositoryKind,
    gateway::{self, AppState},
    hosted::{self, HostedError, Stage, StageState},
    maven::{self, Coordinate, ReadPath, UploadKind},
    model::{Artifact, Decision, Ecosystem},
};
use anyhow::Result;
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{OriginalUri, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/repositories/{name}/staging", post(create))
        .route("/api/v1/staging/{id}", get(inspect))
        .route("/api/v1/staging/{id}/seal", post(seal))
        .route("/api/v1/staging/{id}/abort", post(abort))
        .route("/api/v1/staging/{id}/copy", post(copy))
        .route("/api/v1/staging/{id}/promote", post(promote))
        .route("/api/v1/staging/{id}/revoke", post(revoke))
        .route(
            "/api/v1/staging/{id}/{*path}",
            put(upload).get(staging_resource),
        )
        .route_layer(middleware::from_fn_with_state(state, authenticate))
}

pub(crate) fn failure(status: StatusCode, error: &'static str) -> Response {
    (status, Json(json!({"error":error}))).into_response()
}

pub(crate) fn error(error: HostedError) -> Response {
    match error {
        HostedError::NotFound => failure(StatusCode::NOT_FOUND, "release_not_found"),
        HostedError::Invalid(_) => failure(StatusCode::BAD_REQUEST, "invalid_release"),
        HostedError::Conflict(_) => failure(StatusCode::CONFLICT, "immutable_release_conflict"),
        HostedError::NotApproved(_) => failure(StatusCode::CONFLICT, "release_not_approved"),
        HostedError::Internal(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
    }
}

async fn authenticate(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let Some(principal) = state.access.authenticate(request.headers()) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"Packweir publishing\"",
            )],
        )
            .into_response();
    };
    request.extensions_mut().insert(principal);
    match tokio::time::timeout(Duration::from_secs(120), next.run(request)).await {
        Ok(response) => response,
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
    }
}

pub(crate) fn allowed(
    state: &AppState,
    principal: &Principal,
    stage: &Stage,
    action: Action,
) -> bool {
    state
        .config
        .repositories
        .get(&stage.repository)
        .is_some_and(|repo| {
            repo.kind == RepositoryKind::Hosted
                && matches!(repo.ecosystem, Ecosystem::Maven | Ecosystem::Nuget)
                && repo.ecosystem == stage.package.ecosystem
                && principal.allows_package(&stage.repository, action, &stage.package)
                && state
                    .config
                    .access
                    .package_owner_allowed(&stage.repository, &stage.package)
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    #[serde(default = "Uuid::new_v4")]
    id: Uuid,
    name: String,
    version: String,
}

async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    Json(request): Json<Create>,
) -> Response {
    let Some(repo) = state.config.repositories.get(&name) else {
        return failure(StatusCode::NOT_FOUND, "repository_not_found");
    };
    if repo.kind != RepositoryKind::Hosted
        || !matches!(repo.ecosystem, Ecosystem::Maven | Ecosystem::Nuget)
    {
        return failure(StatusCode::BAD_REQUEST, "hosted_repository_required");
    }
    let package = match repo.ecosystem {
        Ecosystem::Maven => Coordinate::new(&request.name, &request.version).map(|c| c.package()),
        Ecosystem::Nuget => {
            crate::nuget::Coordinate::new(&request.name, &request.version).map(|c| c.package())
        }
        _ => unreachable!(),
    };
    let Ok(package) = package else {
        return failure(StatusCode::BAD_REQUEST, "invalid_coordinates");
    };
    if !principal.allows_package(&name, Action::Write, &package)
        || !state.config.access.package_owner_allowed(&name, &package)
    {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    match hosted::create_stage(&state.store, request.id, &name, package, &principal.id).await {
        Ok(stage) => {
            let upload_url = state.config.public_url.join(&if stage.package.ecosystem
                == Ecosystem::Nuget
            {
                format!("api/v1/staging/{}/nuget/index.json", stage.id)
            } else {
                format!("api/v1/staging/{}/", stage.id)
            });
            match upload_url {
                Ok(upload_url) => (
                    StatusCode::CREATED,
                    Json(json!({"id":stage.id,"stage":stage,"upload_url":upload_url})),
                )
                    .into_response(),
                Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
            }
        }
        Err(e) => error(e),
    }
}

async fn inspect(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Write)
        && !allowed(&state, &principal, &stage, Action::Promote)
    {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    match hosted::stage_files(&state.store, id).await {
        Ok(files) => match hosted::promotion_receipt(&state.store, id).await {
            Ok(receipt) => match hosted::lineage(&state.store,id).await {
                Ok(copy)=>Json(json!({"stage":stage,"files":files,"promotion":receipt,"copy":copy.as_ref().map(copy_view)})).into_response(),
                Err(e)=>error(e),
            },
            Err(e) => error(e),
        },
        Err(e) => error(e),
    }
}

/// Byte readers can transfer packages without gaining access to private source scanner reports.
/// Full source evidence remains in the immutable audit/lineage record.
fn copy_view(receipt: &hosted::CopyReceipt) -> serde_json::Value {
    let sources:Vec<_> = receipt.source_files.iter().map(|file|{
        let ids:Vec<_> = file.evidence.iter().filter_map(|entry|entry.get("id").cloned()).collect();
        json!({"path":file.path,"subject":file.subject,"configuration":file.configuration,
            "context_revision":file.context_revision,"evidence_digest":file.evidence_digest,"evidence_ids":ids})
    }).collect();
    json!({"source_stage":receipt.source_stage,"source_repository":receipt.source_repository,
        "source_manifest_digest":receipt.source_manifest_digest,"source_evaluated_at":receipt.source_evaluated_at,
        "source_files":sources,"destination":receipt.destination,"actor":receipt.actor,"created_at":receipt.created_at})
}

/// Mounted only in the administrative router. Service roles receive the redacted view instead.
pub async fn copy_evidence(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match hosted::lineage(&state.store, id).await {
        Ok(Some(receipt)) => ([(header::CACHE_CONTROL, "no-store")], Json(receipt)).into_response(),
        Ok(None) => failure(StatusCode::NOT_FOUND, "copy_not_found"),
        Err(e) => error(e),
    }
}

async fn copy(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<hosted::CopyRequest>,
) -> Response {
    let source = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    let Some(destination) = state
        .config
        .repositories
        .get(&request.destination_repository)
    else {
        return failure(StatusCode::NOT_FOUND, "repository_not_found");
    };
    if !allowed(&state, &principal, &source, Action::Read)
        || !principal.allows_package_copy(
            &source.repository,
            &request.destination_repository,
            &source.package,
        )
        || !state
            .config
            .access
            .package_owner_allowed(&request.destination_repository, &source.package)
    {
        return failure(StatusCode::FORBIDDEN, "copy_access_denied");
    }
    if destination.kind != RepositoryKind::Hosted
        || destination.ecosystem != source.package.ecosystem
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "matching_hosted_repository_required",
        );
    }
    let existing = match hosted::lineage(&state.store, request.id).await {
        Ok(receipt) => receipt,
        Err(e) => return error(e),
    };
    if existing.is_none() {
        if source.state != StageState::Published {
            return failure(StatusCode::CONFLICT, "source_not_published");
        }
        if let Err(response) = validate_release(&state, &source).await {
            return *response;
        }
    }
    match hosted::copy_release(&state.store, id, &state.config, &request, &principal.id).await {
        Ok(receipt) => (StatusCode::CREATED, Json(copy_view(&receipt))).into_response(),
        Err(e @ HostedError::NotApproved(_)) => {
            if queue_release(&state, id).await.is_err() {
                return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable");
            }
            error(e)
        }
        Err(e) => error(e),
    }
}

async fn upload(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, path)): Path<(Uuid, String)>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Write) || stage.owner != principal.id {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    if stage.state != StageState::Open {
        return failure(StatusCode::CONFLICT, "release_is_sealed");
    }
    // Inspect the original URI too: Axum's decoded wildcard must not hide encoded separators.
    if uri.query().is_some() || uri.path().contains('%') {
        return failure(StatusCode::BAD_REQUEST, "noncanonical_publication_path");
    }
    if stage.package.ecosystem == Ecosystem::Nuget {
        return crate::hosted_nuget::upload_raw(&state, &principal, &stage, &path, request).await;
    }
    let Ok(coordinate) = Coordinate::new(&stage.package.name, &stage.package.version) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_coordinates");
    };
    let Ok(kind) = maven::classify_upload(&coordinate, &path) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_publication_path");
    };
    let max = match &kind {
        UploadKind::Artifact { filename, .. } if filename.ends_with(".pom") => {
            state.config.max_download_bytes.min(2 * 1024 * 1024)
        }
        UploadKind::Artifact { .. } => state.config.max_download_bytes,
        _ => 64 * 1024,
    };
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > max as u64)
    {
        return failure(StatusCode::PAYLOAD_TOO_LARGE, "upload_exceeds_limit");
    }
    let Ok(_permit) = state.downloads.acquire().await else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable");
    };
    let bytes =
        match tokio::time::timeout(Duration::from_secs(60), to_bytes(request.into_body(), max))
            .await
        {
            Ok(Ok(bytes)) => bytes.to_vec(),
            Ok(Err(_)) => return failure(StatusCode::PAYLOAD_TOO_LARGE, "upload_exceeds_limit"),
            Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "upload_timed_out"),
        };
    match kind {
        UploadKind::IgnoredMetadata => StatusCode::NO_CONTENT.into_response(),
        UploadKind::Checksum {
            base_path,
            algorithm,
        } => {
            let files = match hosted::stage_files(&state.store, id).await {
                Ok(files) => files,
                Err(e) => return error(e),
            };
            let Some(file) = files.iter().find(|f| f.path == base_path) else {
                return failure(StatusCode::CONFLICT, "checksum_target_missing");
            };
            let source = match state.blobs.read(&file.artifact.digest).await {
                Ok(bytes) => bytes,
                Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
            };
            if maven::validate_checksum(&bytes, &maven::checksum(&source, algorithm), algorithm)
                .is_err()
            {
                return failure(StatusCode::BAD_REQUEST, "checksum_mismatch");
            }
            StatusCode::NO_CONTENT.into_response()
        }
        UploadKind::Artifact {
            filename,
            content_type,
        } => {
            if filename.ends_with(".pom") && maven::validate_pom(&bytes, &coordinate).is_err() {
                return failure(StatusCode::BAD_REQUEST, "pom_coordinates_mismatch");
            }
            let size = bytes.len() as i64;
            let digest = match state.blobs.put(bytes).await {
                Ok(digest) => digest,
                Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
            };
            let origin = match state
                .config
                .public_url
                .join(&format!("r/{}/{path}", stage.repository))
            {
                Ok(url) => url.to_string(),
                Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_publication_path"),
            };
            let artifact = Artifact {
                repository: stage.repository,
                origin,
                digest,
                size,
                filename,
                content_type,
                package: Some(coordinate.package()),
            };
            match hosted::add_file(&state.store, id, artifact, &path, &principal.id).await {
                Ok(_) => StatusCode::CREATED.into_response(),
                Err(e) => error(e),
            }
        }
    }
}

async fn staging_resource(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, path)): Path<(Uuid, String)>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Write) || stage.owner != principal.id {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    if stage.package.ecosystem == Ecosystem::Nuget {
        return failure(StatusCode::NOT_FOUND, "staging_resource_not_public");
    }
    if uri.query().is_some()
        || uri.path().contains('%')
        || Coordinate::new(&stage.package.name, &stage.package.version)
            .and_then(|c| maven::classify_upload(&c, &path))
            .is_err()
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_publication_path");
    }
    // A publishing client can probe metadata without gaining access to quarantined bytes.
    failure(StatusCode::NOT_FOUND, "staging_resource_not_public")
}

async fn seal(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Write) || stage.owner != principal.id {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    if let Err(response) = validate_release(&state, &stage).await {
        return *response;
    }
    match hosted::seal(&state.store, id, &state.config, &principal.id).await {
        Ok(receipt) => Json(receipt).into_response(),
        Err(e) => error(e),
    }
}

async fn abort(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Write) || stage.owner != principal.id {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    match hosted::abort(&state.store, id, &principal.id).await {
        Ok(stage) => Json(stage).into_response(),
        Err(e) => error(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRequest {
    manifest_digest: String,
}

fn matches_manifest(stage: &Stage, request: &ManifestRequest) -> bool {
    request.manifest_digest.len() == 64
        && stage.manifest_digest.as_deref() == Some(&request.manifest_digest)
}

async fn promote(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<ManifestRequest>,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Promote) {
        return failure(StatusCode::FORBIDDEN, "promotion_access_denied");
    }
    if !matches_manifest(&stage, &request) {
        return failure(StatusCode::CONFLICT, "manifest_changed");
    }
    if let Err(response) = validate_release(&state, &stage).await {
        return *response;
    }
    match hosted::promote(&state.store, id, &state.config, &principal.id).await {
        Ok(receipt) => Json(receipt).into_response(),
        Err(e @ HostedError::NotApproved(_)) => {
            if queue_release(&state, id).await.is_err() {
                return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable");
            }
            error(e)
        }
        Err(e) => error(e),
    }
}

async fn validate_release(
    state: &AppState,
    stage: &Stage,
) -> std::result::Result<(), Box<Response>> {
    if stage.package.ecosystem == Ecosystem::Nuget {
        return crate::hosted_nuget::validate_release(state, stage).await;
    }
    let reject = |status, code| Box::new(failure(status, code));
    let files = hosted::stage_files(&state.store, stage.id)
        .await
        .map_err(|e| Box::new(error(e)))?;
    let coordinate = Coordinate::new(&stage.package.name, &stage.package.version)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "invalid_coordinates"))?;
    let pom = format!("{}.pom", coordinate.artifact_prefix());
    let Some(pom_file) = files.iter().find(|file| file.path == pom) else {
        return Err(reject(StatusCode::BAD_REQUEST, "primary_pom_missing"));
    };
    let bytes = state
        .blobs
        .read(&pom_file.artifact.digest)
        .await
        .map_err(|_| reject(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"))?;
    let primary = maven::required_primary(&bytes, &coordinate)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "invalid_pom"))?;
    if primary.is_some_and(|required| !files.iter().any(|file| file.path == required)) {
        return Err(reject(StatusCode::BAD_REQUEST, "primary_artifact_missing"));
    }
    for file in files {
        if state.blobs.read(&file.artifact.digest).await.is_err() {
            return Err(reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "release_unavailable",
            ));
        }
    }
    Ok(())
}

async fn revoke(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<ManifestRequest>,
) -> Response {
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !allowed(&state, &principal, &stage, Action::Promote) {
        return failure(StatusCode::FORBIDDEN, "promotion_access_denied");
    }
    if !matches_manifest(&stage, &request) {
        return failure(StatusCode::CONFLICT, "manifest_changed");
    }
    match hosted::revoke(&state.store, id, &principal.id).await {
        Ok(stage) => Json(stage).into_response(),
        Err(e) => error(e),
    }
}

async fn queue_release(state: &AppState, id: Uuid) -> Result<()> {
    for file in hosted::stage_files(&state.store, id).await? {
        let fingerprint = state.config.delivery_fingerprint(&file.artifact.scope())?;
        let effective = state.config.effective_policy(&file.artifact.scope())?;
        let evidence = state
            .store
            .evidence(&file.artifact.digest, &fingerprint)
            .await?;
        if matches!(
            effective.policy.evaluate(
                &file.artifact.digest,
                &fingerprint,
                &evidence,
                chrono::Utc::now()
            ),
            Decision::Pending(_)
        ) {
            state
                .store
                .enqueue_delivery(&file.artifact, &fingerprint, &state.config.fingerprint())
                .await?;
        }
    }
    Ok(())
}

/// Read only published membership; every file in the frozen release must still pass policy.
pub async fn download(
    state: &AppState,
    name: &str,
    path: &str,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Response> {
    if state
        .config
        .repositories
        .get(name)
        .is_some_and(|r| r.ecosystem == Ecosystem::Nuget)
    {
        return crate::hosted_nuget::download(state, name, path, uri, headers).await;
    }
    if uri.query().is_some() || uri.path().contains('%') {
        return Ok(failure(
            StatusCode::BAD_REQUEST,
            "noncanonical_publication_path",
        ));
    }
    let route = match maven::parse_read_path(path) {
        Ok(route) => route,
        Err(_) => return Ok(failure(StatusCode::NOT_FOUND, "release_not_found")),
    };
    let (base, checksum) = match route {
        ReadPath::Metadata {
            name: package,
            algorithm,
        } => {
            let versions = hosted::published_versions(&state.store, name, &package).await?;
            let mut current = Vec::new();
            for version in versions {
                let coordinate = Coordinate::new(&package, &version)?;
                let pom = format!("{}.pom", coordinate.artifact_prefix());
                if let Some(delivery) =
                    hosted::delivery(&state.store, name, &pom, &state.config).await?
                {
                    if delivery.decision == Decision::Approved {
                        current.push(version);
                    } else if matches!(delivery.decision, Decision::Pending(_)) {
                        queue_release(state, delivery.stage.id).await?;
                    }
                }
            }
            if current.is_empty() {
                return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
            }
            let bytes = maven::metadata_xml(&package, &current);
            let (bytes, media) = if let Some(algorithm) = algorithm {
                (
                    maven::checksum(&bytes, algorithm).into_bytes(),
                    "text/plain",
                )
            } else {
                (bytes, "application/xml")
            };
            return gateway::response(bytes, media, None, headers);
        }
        ReadPath::Artifact { .. } => (path.to_owned(), None),
        ReadPath::Checksum {
            base_path,
            algorithm,
            ..
        } => (base_path, Some(algorithm)),
    };
    let Some(delivery) = hosted::delivery(&state.store, name, &base, &state.config).await? else {
        return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
    };
    match &delivery.decision {
        Decision::Approved => {
            let bytes = state.blobs.read(&delivery.artifact.digest).await?;
            // Recheck after storage I/O so a completed revoke/invalidation cannot authorize this response.
            let Some(current) = hosted::delivery(&state.store, name, &base, &state.config).await?
            else {
                return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
            };
            if current.decision != Decision::Approved {
                return Ok(failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "release_no_longer_approved",
                ));
            }
            if let Some(algorithm) = checksum {
                return gateway::response(
                    maven::checksum(&bytes, algorithm).into_bytes(),
                    "text/plain",
                    None,
                    headers,
                );
            }
            gateway::response(
                bytes,
                &delivery.artifact.content_type,
                Some(&delivery.artifact.digest),
                headers,
            )
        }
        Decision::Denied(_) => Ok(failure(StatusCode::FORBIDDEN, "release_denied")),
        Decision::Pending(_) => {
            queue_release(state, delivery.stage.id).await?;
            let mut response = (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"release_pending","digest":delivery.artifact.digest,"stage":delivery.stage.id}))).into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, "3".parse()?);
            Ok(response)
        }
    }
}
