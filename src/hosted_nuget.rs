//! Native NuGet transport over immutable staged releases. Signatures remain original bytes;
//! package signature trust is a separate required check or native-client policy.
use crate::{
    access::{Action, Principal},
    config::RepositoryKind,
    gateway::{self, AppState},
    hosted::{self, Stage, StageState},
    hosted_http::{allowed, error, failure},
    model::{Artifact, Decision, Ecosystem},
    nuget::{self, Coordinate, ReadPath},
};
use anyhow::Result;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Multipart, OriginalUri, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

pub fn router(state: AppState) -> Router<AppState> {
    let limit = state.config.max_download_bytes.saturating_add(64 * 1024);
    let publishing = Router::new()
        .route("/api/v1/staging/{id}/nuget/push", put(push).post(push))
        // NuGet's native client appends a slash to the discovered publishing URL.
        .route("/api/v1/staging/{id}/nuget/push/", put(push).post(push))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_push,
        ))
        .layer(DefaultBodyLimit::max(limit));
    Router::new()
        // This discovery document contains only the opaque publishing URL. It is identical
        // for unknown stages and does not expose package existence, coordinates or bytes.
        .route("/api/v1/staging/{id}/nuget/index.json", get(staging_index))
        .merge(publishing)
}

async fn staging_index(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let Ok(url) = state
        .config
        .public_url
        .join(&format!("api/v1/staging/{id}/nuget/push"))
    else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable");
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(nuget::service_index(None, Some(url.as_str()))),
    )
        .into_response()
}

async fn authenticate_push(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(principal) = state.access.authenticate_nuget_push(request.headers()) else {
        return failure(
            StatusCode::UNAUTHORIZED,
            "publication_authentication_required",
        );
    };
    request.extensions_mut().insert(principal);
    match tokio::time::timeout(Duration::from_secs(120), next.run(request)).await {
        Ok(response) => response,
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
    }
}

fn is_nuget(state: &AppState, stage: &Stage) -> bool {
    stage.package.ecosystem == Ecosystem::Nuget
        && state
            .config
            .repositories
            .get(&stage.repository)
            .is_some_and(|repo| {
                repo.kind == RepositoryKind::Hosted && repo.ecosystem == Ecosystem::Nuget
            })
}

async fn push(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    if uri.query().is_some() || uri.path().contains('%') {
        return failure(StatusCode::BAD_REQUEST, "noncanonical_publication_path");
    }
    let stage = match hosted::stage(&state.store, id).await {
        Ok(stage) => stage,
        Err(e) => return error(e),
    };
    if !is_nuget(&state, &stage) {
        return failure(StatusCode::BAD_REQUEST, "hosted_nuget_repository_required");
    }
    if !allowed(&state, &principal, &stage, Action::Write) || stage.owner != principal.id {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    if stage.state != StageState::Open {
        return failure(StatusCode::CONFLICT, "release_is_sealed");
    }
    let max = state.config.max_download_bytes;
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > max.saturating_add(64 * 1024) as u64)
    {
        return failure(StatusCode::PAYLOAD_TOO_LARGE, "upload_exceeds_limit");
    }
    let Ok(_permit) = state.downloads.acquire().await else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable");
    };
    let bytes = match tokio::time::timeout(Duration::from_secs(60), async {
        let mut multipart = Multipart::from_request(request, &state)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let field = multipart
            .next_field()
            .await
            .map_err(|e| e.status())?
            .ok_or(StatusCode::BAD_REQUEST)?;
        // NuGet's protocol uses the FIRST item regardless of its name or filename.
        let bytes = field.bytes().await.map_err(|e| e.status())?;
        if bytes.len() > max {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        // Ignore later fields semantically, while retaining the total request-size budget.
        while let Some(mut field) = multipart.next_field().await.map_err(|e| e.status())? {
            while field.chunk().await.map_err(|e| e.status())?.is_some() {}
        }
        Ok(bytes.to_vec())
    })
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(status)) => return failure(status, "invalid_nuget_upload"),
        Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "upload_timed_out"),
    };
    if !allowed(&state, &principal, &stage, Action::Write) {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    ingest(&state, &principal, &stage, bytes).await
}

async fn ingest(
    state: &AppState,
    principal: &Principal,
    stage: &Stage,
    bytes: Vec<u8>,
) -> Response {
    let Ok(coordinate) = Coordinate::new(&stage.package.name, &stage.package.version) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_coordinates");
    };
    let expected = coordinate.clone();
    let checked = tokio::task::spawn_blocking(move || {
        nuget::validate_package(&bytes, &expected)?;
        Ok::<_, anyhow::Error>(bytes)
    })
    .await;
    let bytes = match checked {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return failure(StatusCode::BAD_REQUEST, "invalid_nuget_package"),
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
    };
    let size = bytes.len() as i64;
    let digest = match state.blobs.put(bytes).await {
        Ok(digest) => digest,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable"),
    };
    let path = format!("flatcontainer/{}", coordinate.package_path());
    let Ok(origin) = state
        .config
        .public_url
        .join(&format!("r/{}/{path}", stage.repository))
    else {
        return failure(StatusCode::BAD_REQUEST, "invalid_publication_path");
    };
    let artifact = Artifact {
        repository: stage.repository.clone(),
        origin: origin.into(),
        digest,
        size,
        filename: coordinate.filename(),
        content_type: "application/octet-stream".into(),
        package: Some(coordinate.package()),
    };
    if !allowed(state, principal, stage, Action::Write) || stage.owner != principal.id {
        return failure(StatusCode::FORBIDDEN, "publication_access_denied");
    }
    match hosted::add_file(&state.store, stage.id, artifact, &path, &principal.id).await {
        Ok(file) => (
            StatusCode::CREATED,
            Json(json!({"stage":stage.id,"digest":file.artifact.digest,"path":file.path})),
        )
            .into_response(),
        Err(e) => error(e),
    }
}

/// The ordinary upload CLI can also supply the canonical package file without multipart.
pub async fn upload_raw(
    state: &AppState,
    principal: &Principal,
    stage: &Stage,
    path: &str,
    request: Request,
) -> Response {
    let Ok(coordinate) = Coordinate::new(&stage.package.name, &stage.package.version) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_coordinates");
    };
    if path != format!("flatcontainer/{}", coordinate.package_path()) {
        return failure(StatusCode::BAD_REQUEST, "invalid_publication_path");
    }
    let Ok(_permit) = state.downloads.acquire().await else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "release_unavailable");
    };
    let bytes = match tokio::time::timeout(
        Duration::from_secs(60),
        axum::body::to_bytes(request.into_body(), state.config.max_download_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes.to_vec(),
        Ok(Err(_)) => return failure(StatusCode::PAYLOAD_TOO_LARGE, "upload_exceeds_limit"),
        Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "upload_timed_out"),
    };
    ingest(state, principal, stage, bytes).await
}

pub async fn validate_release(
    state: &AppState,
    stage: &Stage,
) -> std::result::Result<(), Box<Response>> {
    let files = hosted::stage_files(&state.store, stage.id)
        .await
        .map_err(|e| Box::new(error(e)))?;
    let coordinate = Coordinate::new(&stage.package.name, &stage.package.version)
        .map_err(|_| Box::new(failure(StatusCode::BAD_REQUEST, "invalid_coordinates")))?;
    if files.len() != 1 || files[0].path != format!("flatcontainer/{}", coordinate.package_path()) {
        return Err(Box::new(failure(
            StatusCode::BAD_REQUEST,
            "primary_package_missing",
        )));
    }
    let bytes = state
        .blobs
        .read(&files[0].artifact.digest)
        .await
        .map_err(|_| {
            Box::new(failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "release_unavailable",
            ))
        })?;
    match tokio::task::spawn_blocking(move || nuget::validate_package(&bytes, &coordinate)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Err(Box::new(failure(
            StatusCode::BAD_REQUEST,
            "invalid_nuget_package",
        ))),
        Err(_) => Err(Box::new(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "release_unavailable",
        ))),
    }
}

async fn enqueue_pending(state: &AppState, artifact: &Artifact) -> Result<()> {
    let configuration = state.config.delivery_fingerprint(&artifact.scope())?;
    state
        .store
        .enqueue_delivery(artifact, &configuration, &state.config.fingerprint())
        .await
}

pub async fn download(
    state: &AppState,
    name: &str,
    path: &str,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Response> {
    if uri.query().is_some() || uri.path().contains('%') {
        return Ok(failure(
            StatusCode::BAD_REQUEST,
            "noncanonical_publication_path",
        ));
    }
    if path == "index.json" {
        let base = state
            .config
            .public_url
            .join(&format!("r/{name}/flatcontainer/"))?;
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(nuget::service_index(Some(base.as_str()), None)),
        )
            .into_response());
    }
    let Some(relative) = path.strip_prefix("flatcontainer/") else {
        return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
    };
    let resource = match nuget::parse_read_path(relative) {
        Ok(resource) => resource,
        Err(_) => return Ok(failure(StatusCode::NOT_FOUND, "release_not_found")),
    };
    let coordinate = match resource {
        ReadPath::Versions { name: package } => {
            let versions = hosted::published_versions(&state.store, name, &package).await?;
            let mut current = Vec::new();
            for version in versions {
                let coordinate = Coordinate::new(&package, &version)?;
                let key = format!("flatcontainer/{}", coordinate.package_path());
                if let Some(delivery) =
                    hosted::delivery(&state.store, name, &key, &state.config).await?
                {
                    match delivery.decision {
                        Decision::Approved => current.push(version),
                        Decision::Pending(_) => enqueue_pending(state, &delivery.artifact).await?,
                        Decision::Denied(_) => {}
                    }
                }
            }
            if current.is_empty() {
                return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
            }
            return Ok((
                [(header::CACHE_CONTROL, "no-store")],
                Json(nuget::versions_json(&current)),
            )
                .into_response());
        }
        ReadPath::Package { ref coordinate }
        | ReadPath::Nuspec { ref coordinate }
        | ReadPath::Sha512 { ref coordinate } => coordinate.clone(),
    };
    let key = format!("flatcontainer/{}", coordinate.package_path());
    let Some(delivery) = hosted::delivery(&state.store, name, &key, &state.config).await? else {
        return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
    };
    match delivery.decision {
        Decision::Denied(_) => return Ok(failure(StatusCode::FORBIDDEN, "release_denied")),
        Decision::Pending(_) => {
            enqueue_pending(state, &delivery.artifact).await?;
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "3")],
                Json(json!({"error":"release_pending","digest":delivery.artifact.digest})),
            )
                .into_response());
        }
        Decision::Approved => {}
    }
    let bytes = state.blobs.read(&delivery.artifact.digest).await?;
    let (body, media, digest) = match resource {
        ReadPath::Package { .. } => (
            bytes,
            "application/octet-stream",
            Some(delivery.artifact.digest.as_str()),
        ),
        ReadPath::Sha512 { .. } => (nuget::checksum(&bytes).into_bytes(), "text/plain", None),
        ReadPath::Nuspec { .. } => {
            let package =
                tokio::task::spawn_blocking(move || nuget::validate_package(&bytes, &coordinate))
                    .await??;
            (package.nuspec, "application/xml", None)
        }
        ReadPath::Versions { .. } => unreachable!(),
    };
    // Re-evaluate membership and live policy after storage I/O AND asynchronous
    // manifest inspection; neither an earlier snapshot nor derived metadata authorizes reads.
    let Some(current) = hosted::delivery(&state.store, name, &key, &state.config).await? else {
        return Ok(failure(StatusCode::NOT_FOUND, "release_not_found"));
    };
    if current.decision != Decision::Approved {
        return Ok(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "release_no_longer_approved",
        ));
    }
    gateway::response(body, media, digest, headers)
}
