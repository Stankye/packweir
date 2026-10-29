pub use crate::bounds::parse_range;
use crate::{
    config::{Config, Repository},
    inventory,
    model::{Artifact, Decision, Ecosystem, sha256},
    network, registry,
    storage::BlobStore,
    store::Store,
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, OriginalUri, Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};
use url::Url;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Store,
    pub blobs: BlobStore,
    pub admin_token: Arc<String>,
    pub read_token: Arc<String>,
    locks: Arc<Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>>,
    downloads: Arc<Semaphore>,
}
impl AppState {
    pub fn new(
        config: Arc<Config>,
        store: Store,
        blobs: BlobStore,
        admin_token: String,
        read_token: String,
    ) -> Self {
        Self {
            config,
            store,
            blobs,
            admin_token: Arc::new(admin_token),
            read_token: Arc::new(read_token),
            locks: Default::default(),
            downloads: Arc::new(Semaphore::new(8)),
        }
    }
    async fn lock(&self, key: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, v| v.strong_count() > 0);
        if let Some(lock) = locks.get(key).and_then(|l| l.upgrade()) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.into(), Arc::downgrade(&lock));
        lock
    }
}

pub fn router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/artifacts/{digest}", get(inspect))
        .route("/api/v1/artifacts/{digest}/documents", post(ingest))
        .route("/api/v1/artifacts/{digest}/documents/{blob}", get(document))
        .route("/api/v1/artifacts/{digest}/rescan", post(rescan))
        .route("/api/v1/prefetch", post(prefetch))
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth));
    let packages = Router::new()
        .route("/r/{name}/", get(root))
        .route("/r/{name}/{*path}", get(proxy))
        .route_layer(middleware::from_fn_with_state(state.clone(), read_auth));
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ready", get(ready))
        .merge(admin)
        .merge(packages)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state)
}

async fn ready(State(state): State<AppState>) -> Response {
    let checked = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let database = async {
            sqlx::query("SELECT 1").execute(&state.store.pool).await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(database, state.blobs.check())?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if matches!(checked, Ok(Ok(()))) {
        (StatusCode::OK, Json(json!({"ready":true}))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready":false})),
        )
            .into_response()
    }
}

pub fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    !token.is_empty()
        && sha256(value.as_bytes())
            .as_bytes()
            .ct_eq(sha256(token.as_bytes()).as_bytes())
            .into()
}
async fn admin_auth(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !authorized(request.headers(), &state.admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}
async fn read_auth(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !read_authorized(request.headers(), &state.read_token) {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"Packweir\"".parse().expect("static header"),
        );
        return response;
    }
    next.run(request).await
}

pub fn read_authorized(headers: &HeaderMap, token: &str) -> bool {
    use base64::Engine;
    if authorized(headers, token) {
        return true;
    }
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let candidate = if let Some(encoded) = raw.strip_prefix("Basic ") {
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((_, password)) = decoded.split_once(':') else {
            return false;
        };
        password.to_owned()
    } else {
        raw.to_owned()
    }; // Cargo uses an opaque Authorization token.
    !token.is_empty()
        && sha256(candidate.as_bytes())
            .as_bytes()
            .ct_eq(sha256(token.as_bytes()).as_bytes())
            .into()
}

fn failure(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error":code}))).into_response()
}
fn internal(error: anyhow::Error) -> Response {
    // Upstream URLs and scanner errors may contain credentials or package secrets.
    tracing::warn!(error_type=%std::any::type_name_of_val(&error),"request failed; inspect audit records");
    failure(StatusCode::BAD_GATEWAY, "request_failed")
}
async fn root(
    State(state): State<AppState>,
    Path(name): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    proxy_inner(&state, &name, "", &uri, &headers)
        .await
        .unwrap_or_else(internal)
}
async fn proxy(
    State(state): State<AppState>,
    Path((name, path)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    proxy_inner(&state, &name, &path, &uri, &headers)
        .await
        .unwrap_or_else(internal)
}

async fn target(state: &AppState, name: &str, path: &str, query: Option<&str>) -> Result<Url> {
    let repo = state
        .config
        .repositories
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("unknown repository"))?;
    let mut url = if let Some(encoded) = path.strip_prefix("_fetch/") {
        registry::unwrap_path(encoded)?
    } else if let Some(download) = path.strip_prefix("_cargo/") {
        ensure!(repo.ecosystem == Ecosystem::Cargo, "not a Cargo repository");
        let parts: Vec<_> = download.split('/').collect();
        ensure!(
            parts.len() == 3 && parts[2] == "download",
            "invalid crate download"
        );
        let index_path = registry::cargo_index_path(parts[0])?;
        ensure!(
            parts[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b)),
            "invalid crate version"
        );
        let index = network::fetch(
            repo,
            &repo.upstream.join(&index_path)?,
            None,
            8 * 1024 * 1024,
            state.config.allow_private_upstreams,
        )
        .await?;
        ensure!(index.status == 200, "crate index unavailable");
        let checksum = std::str::from_utf8(&index.bytes)?
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|v| v["vers"].as_str() == Some(parts[1]))
            .and_then(|v| v["cksum"].as_str().map(str::to_owned))
            .ok_or_else(|| anyhow::anyhow!("crate checksum missing"))?;
        let template = repo
            .cargo_download_template
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing Cargo template"))?;
        let mut url = Url::parse(
            &template
                .replace("{crate}", parts[0])
                .replace("{version}", parts[1]),
        )?;
        url.set_fragment(Some(&format!("sha256={checksum}")));
        url
    } else {
        ensure!(
            !path.starts_with('/') && !path.contains('\\') && !path.split('/').any(|p| p == ".."),
            "invalid registry path"
        );
        repo.upstream.join(path)?
    };
    if let Some(query) = query {
        let joined = match url.query() {
            Some(existing) => format!("{existing}&{query}"),
            None => query.into(),
        };
        url.set_query(Some(&joined));
    }
    ensure!(network::allowed(repo, &url), "origin not allowed");
    Ok(url)
}

async fn proxy_inner(
    state: &AppState,
    name: &str,
    path: &str,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> Result<Response> {
    let Some(repo) = state.config.repositories.get(name) else {
        return Ok(failure(StatusCode::NOT_FOUND, "repository_not_found"));
    };
    let _permit = state.downloads.acquire().await?;
    if repo.ecosystem == Ecosystem::Cargo && path == "config.json" {
        return Ok(Json(json!({"dl":format!("{}r/{name}/_cargo/{{crate}}/{{version}}/download",state.config.public_url),"auth-required":true})).into_response());
    }
    let url = target(state, name, path, uri.query()).await?;
    let lock = state.lock(&format!("{name}:{url}")).await;
    let _guard = lock.lock().await;
    // A configured Cargo download template need not end in .crate or /download.
    let metadata = !path.starts_with("_cargo/") && registry::is_metadata(repo.ecosystem, &url);
    if !metadata
        && repo.retain
        && let Some(artifact) = state.store.artifact(name, url.as_str()).await?
        && let Ok(bytes) = state.blobs.read(&artifact.digest).await
    {
        // The URL fragment is part of the origin mapping and is verified on each delivery.
        network::verify_fragment(&url, &bytes)?;
        return gate(state, repo, artifact, bytes, headers).await;
    }
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let download = network::fetch(
        repo,
        &url,
        accept,
        state.config.max_download_bytes,
        state.config.allow_private_upstreams,
    )
    .await?;
    if download.status != 200 {
        // Never forward an upstream error body, which can contain unapproved artifact bytes.
        return Ok(failure(
            if download.status == 404 {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            },
            "upstream_unavailable",
        ));
    }
    if metadata {
        let bytes = rewrite_metadata(
            state,
            repo,
            name,
            &url,
            &download.content_type,
            &download.bytes,
        )?;
        return response(bytes, &download.content_type, None, headers);
    }
    if network::verify_fragment(&url, &download.bytes).is_err() {
        state
            .store
            .audit(
                "integrity_rejected",
                &sha256(&download.bytes),
                json!({"repository":name}),
            )
            .await?;
        return Ok(failure(
            StatusCode::FORBIDDEN,
            "upstream_integrity_mismatch",
        ));
    }
    let bytes = download.bytes.to_vec();
    let digest = state.blobs.put(bytes.clone()).await?;
    let filename = url
        .path_segments()
        .and_then(|mut p| p.next_back())
        .filter(|s| !s.is_empty())
        .unwrap_or("artifact")
        .to_owned();
    let artifact = Artifact {
        repository: name.into(),
        origin: url.to_string(),
        digest,
        size: bytes.len() as i64,
        filename,
        content_type: download.content_type,
    };
    state.store.register(&artifact).await?;
    gate(state, repo, artifact, bytes, headers).await
}

fn rewrite_metadata(
    state: &AppState,
    repo: &Repository,
    name: &str,
    url: &Url,
    content_type: &str,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    if repo.ecosystem == Ecosystem::Pypi && !content_type.contains("json") {
        return Ok(registry::rewrite_html(
            std::str::from_utf8(bytes)?,
            url,
            repo,
            name,
            &state.config.public_url,
        )?
        .into_bytes());
    }
    if matches!(
        repo.ecosystem,
        Ecosystem::Npm | Ecosystem::Nuget | Ecosystem::Pypi
    ) {
        let mut value: Value = serde_json::from_slice(bytes)?;
        registry::rewrite_json(&mut value, repo, name, &state.config.public_url)?;
        return Ok(serde_json::to_vec(&value)?);
    }
    if repo.ecosystem == Ecosystem::Cargo {
        // An opaque _fetch token must not turn arbitrary download-origin bytes into metadata.
        registry::validate_cargo_index(bytes)?;
    }
    // Validated sparse Cargo entries and Maven sidecars retain their original representation.
    Ok(bytes.to_vec())
}

async fn gate(
    state: &AppState,
    repo: &Repository,
    artifact: Artifact,
    bytes: Vec<u8>,
    headers: &HeaderMap,
) -> Result<Response> {
    let config = state.config.fingerprint();
    let evidence = state.store.evidence(&artifact.digest, &config).await?;
    let decision = state
        .config
        .policy
        .evaluate(&artifact.digest, &config, &evidence, Utc::now());
    state
        .store
        .decision(&artifact.repository, &artifact.digest, &config, &decision)
        .await?;
    match &decision {
        Decision::Approved => {
            let response = response(
                bytes,
                &artifact.content_type,
                Some(&artifact.digest),
                headers,
            )?;
            if !repo.retain {
                // Only delete if no retaining repository or active analysis references this blob.
                let retained: Vec<String> = state
                    .config
                    .repositories
                    .iter()
                    .filter(|(_, r)| r.retain)
                    .map(|(n, _)| n.clone())
                    .collect();
                let referenced:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest=$1 AND repository=ANY($2)) OR EXISTS(SELECT 1 FROM jobs WHERE subject=$1 AND state IN ('queued','running'))")
                    .bind(&artifact.digest).bind(&retained).fetch_one(&state.store.pool).await?;
                if !referenced {
                    state.blobs.delete(&artifact.digest).await?;
                }
            }
            Ok(response)
        }
        Decision::Denied(_) => Ok((
            StatusCode::FORBIDDEN,
            Json(json!({"digest":artifact.digest,"decision":decision})),
        )
            .into_response()),
        Decision::Pending(_) => {
            state
                .store
                .enqueue(&artifact.digest, &config, &artifact.filename)
                .await?;
            let mut response = (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"digest":artifact.digest,"decision":decision})),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, "3".parse()?);
            Ok(response)
        }
    }
}

pub fn response(
    bytes: Vec<u8>,
    content_type: &str,
    digest: Option<&str>,
    headers: &HeaderMap,
) -> Result<Response> {
    let len = bytes.len();
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff");
    if let Some(digest) = digest {
        builder = builder.header("x-packweir-sha256", digest);
    }
    if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let Some((start, end)) = parse_range(range, len) {
            return Ok(builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, end - start + 1)
                .body(Body::from(bytes[start..=end].to_vec()))?);
        }
        return Ok(builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{len}"))
            .body(Body::empty())?);
    }
    Ok(builder
        .header(header::CONTENT_LENGTH, len)
        .body(Body::from(bytes))?)
}

async fn capabilities() -> Json<Value> {
    Json(
        json!({"version":env!("CARGO_PKG_VERSION"),"ecosystems":["npm","pypi","cargo","maven","nuget"],
        "status":"experimental", "hosted_publishing":false,"oci_serving":false,
        "checks":{"inventory":"builtin","provenance":"source_bound_slsa_driver_or_operator_adapter","agent":"operator_adapter_required",
        "vulnerabilities":"osv_driver_requires_package_mappings_and_pinned_offline_databases","source_posture":"hipcheck_driver_requires_source_mappings_and_pinned_policy",
        "sigstore_blob_signature":"cosign_driver_requires_pinned_executable_and_trust_root"},
        "sbom":{"formats":["SPDX-2.3","CycloneDX-1.6"],"validation":"envelope_only"}}),
    )
}
async fn inspect(State(state): State<AppState>, Path(digest): Path<String>) -> Response {
    let result = async {
        let config=state.config.fingerprint();
        let evidence=state.store.evidence(&digest,&config).await?;
        let decision=state.config.policy.evaluate(&digest,&config,&evidence,Utc::now());
        Ok::<_,anyhow::Error>(Json(json!({"digest":digest,"configuration":config,"decision":decision,"evidence":evidence,"documents":state.store.documents(&digest).await?,"identities":state.store.identities(&digest).await?})).into_response())
    }.await;
    result.unwrap_or_else(internal)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ingest {
    kind: String,
    origin: String,
    document: Value,
}
async fn ingest(
    State(state): State<AppState>,
    Path(digest): Path<String>,
    Json(input): Json<Ingest>,
) -> Response {
    let result = async {
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid digest"
        );
        ensure!(
            ["publisher_declared", "client_resolved"].contains(&input.origin.as_str()),
            "invalid document origin"
        );
        match input.kind.as_str() {
            "sbom" => {
                inventory::sbom_format(&input.document)?;
            }
            "attestation" | "vex" | "lockfile" | "sigstore_bundle" => {}
            _ => anyhow::bail!("unsupported document kind"),
        }
        let blob = state
            .blobs
            .put(serde_json::to_vec(&input.document)?)
            .await?;
        state
            .store
            .document(&digest, &input.kind, &input.origin, &blob)
            .await?;
        state
            .store
            .audit(
                "document_ingested",
                &digest,
                json!({"kind":input.kind,"origin":input.origin,"blob":blob,"verified":false}),
            )
            .await?;
        Ok::<_, anyhow::Error>(
            (
                StatusCode::CREATED,
                Json(json!({"blob_digest":blob,"verified":false})),
            )
                .into_response(),
        )
    }
    .await;
    result.unwrap_or_else(|_| failure(StatusCode::BAD_REQUEST, "document_rejected"))
}
async fn document(
    State(state): State<AppState>,
    Path((digest, blob)): Path<(String, String)>,
) -> Response {
    let result = async {
        let docs = state.store.documents(&digest).await?;
        if !docs
            .iter()
            .any(|v| v["blob_digest"].as_str() == Some(blob.as_str()))
        {
            return Ok(failure(StatusCode::NOT_FOUND, "document_not_found"));
        }
        response(
            state.blobs.read(&blob).await?,
            "application/json",
            Some(&blob),
            &HeaderMap::new(),
        )
    }
    .await;
    result.unwrap_or_else(internal)
}
async fn rescan(State(state): State<AppState>, Path(digest): Path<String>) -> Response {
    let result = async {
        state.blobs.read(&digest).await?;
        let filename: Option<String> =
            sqlx::query_scalar("SELECT filename FROM artifacts WHERE digest=$1 LIMIT 1")
                .bind(&digest)
                .fetch_optional(&state.store.pool)
                .await?;
        let filename = filename.ok_or_else(|| anyhow::anyhow!("artifact not registered"))?;
        let config = state.config.fingerprint();
        state.store.invalidate(&digest).await?;
        state.store.enqueue(&digest, &config, &filename).await?;
        state
            .store
            .audit("rescan_requested", &digest, json!({"configuration":config}))
            .await?;
        Ok::<_, anyhow::Error>(StatusCode::ACCEPTED.into_response())
    }
    .await;
    result.unwrap_or_else(internal)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prefetch {
    repository: String,
    path: String,
}
async fn prefetch(State(state): State<AppState>, Json(input): Json<Prefetch>) -> Response {
    let uri = axum::http::Uri::from_static("/");
    match proxy_inner(
        &state,
        &input.repository,
        &input.path,
        &uri,
        &HeaderMap::new(),
    )
    .await
    {
        Ok(response) if response.status().is_success() => {
            Json(json!({"state":"approved"})).into_response()
        }
        Ok(response) => response,
        Err(error) => internal(error),
    }
}
