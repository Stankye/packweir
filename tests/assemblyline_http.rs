//! Controlled HTTP/SQL/CLI qualification of Packweir's native Assemblyline path.
//! The server uses upstream-ODM fixtures; it is not a real malware analysis service.
#[allow(dead_code)]
mod support;

use axum::{
    Json, Router,
    body::Body,
    extract::{Multipart, State},
    http::{HeaderMap, Request, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    config::{CommandScanner, Config, PinnedResource, ScannerDriver, StorageConfig},
    gateway::{self, AppState},
    identity,
    model::{Artifact, Evidence, Outcome, sha256},
    storage::BlobStore,
    store::Store,
};
use serde_json::{Value, json};
use sqlx::{ConnectOptions, Row};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Output,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
use tower::ServiceExt;

const ARTIFACT_PATH: &str = "dev/private/library/1.0.0/library-1.0.0.jar";
const ROOT_BYTES: &[u8] = b"Packweir Assemblyline schema compatibility root\n";
const SID: &str = "00000000-0000-4000-8000-000000000001";
const USER: &str = "assemblyline-fixture-user";
const KEY: &str = "fixture-key:test-only-not-a-credential";

fn fixture(name: &str) -> Value {
    let text = match name {
        "full" => include_str!("assemblyline/fixtures/submission.full.completed.json"),
        "error" => include_str!("assemblyline/fixtures/submission.full.service_error.json"),
        "status" => include_str!("assemblyline/fixtures/submission.completed.json"),
        "accepted" => include_str!("assemblyline/fixtures/submit.accepted.json"),
        "tree" => include_str!("assemblyline/fixtures/submission.tree.completed.json"),
        "manifest" => include_str!("assemblyline/fixtures/manifest.json"),
        _ => unreachable!(),
    };
    serde_json::from_str(text).unwrap()
}

fn envelope(body: Value) -> Value {
    json!({"api_response":body,"api_error_message":"","api_server_version":"4.7.4.stable11","api_status_code":200})
}

#[derive(Debug, Clone)]
enum Behavior {
    Complete,
    Pending,
    PollUnavailable,
    LosePostResponse,
    MetadataMismatch,
    SubjectMismatch,
    TreeFiltered,
    ServicePinMismatch,
    EffectiveParamsMismatch,
    OmittedOptionalSelections,
    InvalidOptionalSelection,
    ServiceError,
    ExternalService,
    UnknownPrivilege,
    InventoryRedirect(String),
    HoldStatus,
}

struct MockState {
    behavior: Mutex<Behavior>,
    accepted: Mutex<Option<Value>>,
    uploaded: Mutex<Vec<u8>>,
    requests: Mutex<Vec<(String, bool)>>,
    posts: AtomicUsize,
    polls: AtomicUsize,
    redirect_hits: AtomicUsize,
    status_entered: Notify,
    status_release: Notify,
}

impl MockState {
    fn mode(&self) -> Behavior {
        self.behavior.lock().unwrap().clone()
    }

    fn record(&self, uri: &str, headers: &HeaderMap) -> bool {
        let valid = headers.get("x-user").and_then(|v| v.to_str().ok()) == Some(USER)
            && headers.get("x-apikey").and_then(|v| v.to_str().ok()) == Some(KEY);
        self.requests.lock().unwrap().push((uri.into(), valid));
        valid
    }

    fn response(&self, kind: &str) -> Value {
        let mut response = fixture(kind);
        let accepted = self
            .accepted
            .lock()
            .unwrap()
            .clone()
            .expect("upload preceded poll");
        let body = response.get_mut("api_response").unwrap();
        body["metadata"] = accepted["metadata"].clone();
        body["params"] = accepted["params"].clone();
        let completed = (Utc::now() - Duration::seconds(1)).to_rfc3339();
        let started = (Utc::now() - Duration::seconds(2)).to_rfc3339();
        if let Some(results) = body.get_mut("results").and_then(Value::as_object_mut) {
            for result in results.values_mut() {
                result["created"] = json!(completed);
                result["response"]["milestones"]["service_started"] = json!(started);
                result["response"]["milestones"]["service_completed"] = json!(completed);
            }
        }
        match self.mode() {
            Behavior::MetadataMismatch => body["metadata"]["packweir_run_id"] = json!("wrong-run"),
            Behavior::SubjectMismatch => body["files"][0]["sha256"] = json!("a".repeat(64)),
            Behavior::EffectiveParamsMismatch => body["params"]["deep_scan"] = json!(true),
            Behavior::OmittedOptionalSelections => {
                for name in ["excluded", "rescan", "resubmit"] {
                    body["params"]["services"]
                        .as_object_mut()
                        .unwrap()
                        .remove(name);
                }
            }
            Behavior::InvalidOptionalSelection => {
                body["params"]["services"]["resubmit"] = Value::Null
            }
            Behavior::ServicePinMismatch => {
                if let Some(results) = body.get_mut("results").and_then(Value::as_object_mut) {
                    for result in results.values_mut() {
                        result["response"]["service_version"] = json!("4.8.0.unqualified");
                    }
                }
            }
            _ => {}
        }
        response
    }
}

struct MockServer {
    origin: String,
    state: Arc<MockState>,
    task: tokio::task::JoinHandle<()>,
}

#[sqlx::test(migrations = "./migrations")]
async fn optional_service_lists_default_to_empty_only_when_absent(pool: sqlx::PgPool) {
    let harness = Harness::new(pool, Behavior::OmittedOptionalSelections).await;
    harness.worker().await;
    harness.due().await;
    harness.worker().await;
    assert_eq!(harness.remote().await.get::<String, _>("state"), "complete");
    assert!(
        harness
            .evidence()
            .await
            .iter()
            .any(|e| e.check == "assemblyline" && e.outcome == Outcome::Pass)
    );
    assert_eq!(harness.download().await.0, StatusCode::OK);
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn optional_service_lists_reject_explicit_null(pool: sqlx::PgPool) {
    let harness = Harness::new(pool, Behavior::InvalidOptionalSelection).await;
    harness.worker().await;
    for _ in 0..3 {
        harness.due().await;
        harness.worker().await;
    }
    assert!(
        !harness
            .evidence()
            .await
            .iter()
            .any(|e| e.check == "assemblyline" && e.outcome == Outcome::Pass)
    );
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockServer {
    async fn start(mode: Behavior) -> Self {
        let state = Arc::new(MockState {
            behavior: Mutex::new(mode),
            accepted: Mutex::new(None),
            uploaded: Mutex::new(vec![]),
            requests: Mutex::new(vec![]),
            posts: AtomicUsize::new(0),
            polls: AtomicUsize::new(0),
            redirect_hits: AtomicUsize::new(0),
            status_entered: Notify::new(),
            status_release: Notify::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/api/v4/service/all/", get(inventory))
            .route("/api/v4/submit/", post(upload))
            .route("/api/v4/submission/{sid}/", get(status))
            .route("/api/v4/submission/full/{sid}/", get(full))
            .route("/api/v4/submission/tree/{sid}/", get(tree))
            .route("/credential-target/", get(redirect_target))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            origin,
            state,
            task,
        }
    }
}

async fn inventory(State(state): State<Arc<MockState>>, headers: HeaderMap) -> Response {
    if !state.record("inventory", &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Behavior::InventoryRedirect(destination) = state.mode() {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, destination)],
        )
            .into_response();
    }
    let mut service = json!({"name":"Extract","version":"4.8.0.stable0","enabled":true,
        "accepts":".*","rejects":"empty","is_external":false,"privileged":false});
    match state.mode() {
        Behavior::ExternalService => service["is_external"] = json!(true),
        Behavior::UnknownPrivilege => {
            service.as_object_mut().unwrap().remove("privileged");
        }
        _ => {}
    }
    Json(envelope(json!([service]))).into_response()
}

async fn upload(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
    mut form: Multipart,
) -> Response {
    if !state.record("submit", &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state.posts.fetch_add(1, Ordering::SeqCst);
    let mut request = None;
    let mut binary = None;
    while let Some(part) = form.next_field().await.unwrap() {
        match part.name() {
            Some("json") => {
                request = Some(serde_json::from_str::<Value>(&part.text().await.unwrap()).unwrap())
            }
            Some("bin") => binary = Some(part.bytes().await.unwrap().to_vec()),
            _ => panic!("unexpected multipart part"),
        }
    }
    *state.uploaded.lock().unwrap() = binary.expect("binary multipart part");
    let request = request.expect("JSON multipart part");
    *state.accepted.lock().unwrap() = Some(request.clone());
    if matches!(state.mode(), Behavior::LosePostResponse) {
        // Record acceptance first; the caller times out before this valid reply.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut response = fixture("accepted");
    response["api_response"]["metadata"] = request["metadata"].clone();
    response["api_response"]["params"] = request["params"].clone();
    Json(response).into_response()
}

async fn status(State(state): State<Arc<MockState>>, headers: HeaderMap) -> Response {
    if !state.record("status", &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state.polls.fetch_add(1, Ordering::SeqCst);
    if matches!(state.mode(), Behavior::PollUnavailable) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if matches!(state.mode(), Behavior::HoldStatus) {
        state.status_entered.notify_one();
        state.status_release.notified().await;
    }
    let mut response = state.response("status");
    if matches!(state.mode(), Behavior::Pending) {
        response["api_response"]["state"] = json!("submitted");
    }
    Json(response).into_response()
}

async fn full(State(state): State<Arc<MockState>>, headers: HeaderMap, uri: Uri) -> Response {
    if !state.record("full", &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(uri.query(), Some("get_full_tree=true"));
    Json(
        state.response(if matches!(state.mode(), Behavior::ServiceError) {
            "error"
        } else {
            "full"
        }),
    )
    .into_response()
}

async fn tree(State(state): State<Arc<MockState>>, headers: HeaderMap, uri: Uri) -> Response {
    if !state.record("tree", &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    assert_eq!(uri.query(), Some("get_full_tree=true"));
    let mut response = fixture("tree");
    if matches!(state.mode(), Behavior::TreeFiltered) {
        response["api_response"]["filtered"] = json!(true);
    }
    Json(response).into_response()
}

async fn redirect_target(State(state): State<Arc<MockState>>, headers: HeaderMap) -> Response {
    state.redirect_hits.fetch_add(1, Ordering::SeqCst);
    state.record("redirect-target", &headers);
    Json(envelope(json!([]))).into_response()
}

struct Harness {
    server: MockServer,
    directory: tempfile::TempDir,
    config_path: PathBuf,
    config: Arc<Config>,
    store: Store,
    artifact: Artifact,
    configuration: String,
    app: Router,
}

impl Harness {
    async fn new(pool: sqlx::PgPool, behavior: Behavior) -> Self {
        Self::with_ordinary(pool, behavior, Outcome::Pass).await
    }

    async fn with_ordinary(pool: sqlx::PgPool, behavior: Behavior, ordinary: Outcome) -> Self {
        Self::with_options(pool, behavior, ordinary, false).await
    }

    async fn with_options(
        pool: sqlx::PgPool,
        behavior: Behavior,
        ordinary: Outcome,
        agent: bool,
    ) -> Self {
        let server = MockServer::start(behavior).await;
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("capture")).unwrap();
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        config.repositories.retain(|name, _| name == "maven");
        config.storage = StorageConfig::Fs {
            root: directory.path().join("storage").to_string_lossy().into(),
        };
        config.policy.required.push("assemblyline".into());
        if ordinary == Outcome::Pass {
            config.policy.required.push("a_ordinary".into());
        }
        let report = directory.path().join("ordinary.json");
        let report_bytes = serde_json::to_vec(
            &json!({"outcome":ordinary,"details":{"ordinary_observation":true}}),
        )
        .unwrap();
        std::fs::write(&report, &report_bytes).unwrap();
        let program = support::escalation_fixture_program();
        config.scanners.insert(
            "a_ordinary".into(),
            CommandScanner {
                program: program.to_string_lossy().into(),
                args: vec!["a_ordinary".into()],
                version: "test-owned-ordinary-v1".into(),
                timeout_seconds: 10,
                environment: BTreeMap::from([(
                    "PACKWEIR_ESCALATION_CAPTURE".into(),
                    directory.path().join("capture").to_string_lossy().into(),
                )]),
                program_sha256: Some(sha256(&std::fs::read(program).unwrap())),
                resources: BTreeMap::from([(
                    "report".into(),
                    PinnedResource {
                        path: report.to_string_lossy().into(),
                        sha256: sha256(&report_bytes),
                    },
                )]),
                driver: ScannerDriver::Command,
            },
        );
        if agent {
            config.policy.trust_agent = true;
            config.policy.agent_escalation = Some(packweir::policy::AgentEscalation {
                when_any: vec![packweir::policy::OutcomeCondition {
                    check: "assemblyline".into(),
                    outcomes: vec![Outcome::Inconclusive],
                }],
            });
            let report = directory.path().join("agent.json");
            let report_bytes = serde_json::to_vec(&json!({"outcome":"pass","details":{
                "model":"test-owned-protocol-only","prompt_digest":sha256(b"fixture prompt"),
                "toolset_digest":sha256(b"fixture tools"),"evidence_digest":"$EVIDENCE_DIGEST",
                "trace_digest":sha256(b"fixture trace")
            }}))
            .unwrap();
            std::fs::write(&report, &report_bytes).unwrap();
            config.scanners.insert(
                "agent".into(),
                CommandScanner {
                    program: program.to_string_lossy().into(),
                    args: vec!["agent".into()],
                    version: "test-owned-agent-v1".into(),
                    timeout_seconds: 10,
                    program_sha256: Some(sha256(&std::fs::read(program).unwrap())),
                    environment: BTreeMap::from([(
                        "PACKWEIR_ESCALATION_CAPTURE".into(),
                        directory.path().join("capture").to_string_lossy().into(),
                    )]),
                    resources: BTreeMap::from([(
                        "report".into(),
                        PinnedResource {
                            path: report.to_string_lossy().into(),
                            sha256: sha256(&report_bytes),
                        },
                    )]),
                    driver: ScannerDriver::Command,
                },
            );
        }
        let manifest = fixture("manifest");
        let pin = manifest["configuration_key"]
            .as_str()
            .unwrap()
            .strip_prefix('c')
            .unwrap();
        config.remote_scanners.insert("assemblyline".into(), serde_json::from_value(json!({
            "kind":"assemblyline","endpoint":server.origin,"server_version":"4.7.4.stable11",
            "user_env":"PACKWEIR_TEST_AL_USER","api_key_env":"PACKWEIR_TEST_AL_KEY",
            "allow_upload":true,"classification":fixture("full")["api_response"]["classification"],
            "retention_days":7,"profile_revision":"qualified-fixture-schema-v1","submission_profile":"packweir-static",
            "service_spec":{"Extract":{}},
            "policy":{"required_services":{"Extract":{"version":"4.8.0.stable0","tool_version":null,"configuration_key":pin}},
                      "deny_rules":[],"max_result_age_seconds":86400},
            "allow_private_network":true,"allow_insecure_http":true,
            "allow_external_services":false,"allow_privileged_services":false,"ca_certificate":null,
            "request_timeout_seconds":1,"analysis_timeout_seconds":60,"poll_interval_seconds":1,"max_poll_failures":2
        })).unwrap());
        config.validate().unwrap();
        let config_path = directory.path().join("packweir.toml");
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let config = Arc::new(config);
        let store = Store { pool };
        let blobs = BlobStore::new(&config.storage).unwrap();
        let repository = &config.repositories["maven"];
        let origin = repository
            .proxy_upstream()
            .unwrap()
            .join(ARTIFACT_PATH)
            .unwrap();
        let digest = blobs.put(ROOT_BYTES.to_vec()).await.unwrap();
        assert_eq!(digest, manifest["subject_sha256"].as_str().unwrap());
        let artifact = store
            .register(&Artifact {
                repository: "maven".into(),
                origin: origin.to_string(),
                digest,
                size: ROOT_BYTES.len() as i64,
                filename: "library-1.0.0.jar".into(),
                content_type: "application/java-archive".into(),
                package: identity::observe(repository, &origin, ARTIFACT_PATH),
            })
            .await
            .unwrap();
        let configuration = config.delivery_fingerprint(&artifact.scope()).unwrap();
        store
            .enqueue_delivery(&artifact, &configuration, &config.fingerprint())
            .await
            .unwrap();
        let app = gateway::router(AppState::new(
            config.clone(),
            store.clone(),
            blobs,
            "a".repeat(32),
            "r".repeat(32),
        ));
        Self {
            server,
            directory,
            config_path,
            config,
            store,
            artifact,
            configuration,
            app,
        }
    }

    fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_packweir"));
        command
            .kill_on_drop(true)
            .arg("--config")
            .arg(&self.config_path)
            .arg("worker")
            .arg("--once")
            .env(
                "DATABASE_URL",
                self.store.pool.connect_options().to_url_lossy().as_str(),
            )
            .env("PACKWEIR_TEST_AL_USER", USER)
            .env("PACKWEIR_TEST_AL_KEY", KEY)
            .env("RUST_LOG", "error");
        command
    }

    async fn worker(&self) -> Output {
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(120), self.command().output())
                .await
                .unwrap()
                .unwrap();
        assert!(
            output.status.success(),
            "worker CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains(KEY));
        output
    }

    async fn due(&self) {
        sqlx::query("UPDATE jobs SET not_before=now()-interval '1 second' WHERE subject=$1 AND configuration=$2")
            .bind(&self.artifact.digest).bind(&self.configuration).execute(&self.store.pool).await.unwrap();
        sqlx::query("UPDATE remote_analysis SET next_poll_at=now()-interval '1 second' WHERE subject=$1 AND configuration=$2")
            .bind(&self.artifact.digest).bind(&self.configuration).execute(&self.store.pool).await.unwrap();
    }

    async fn remote(&self) -> sqlx::postgres::PgRow {
        sqlx::query("SELECT * FROM remote_analysis WHERE subject=$1 AND configuration=$2 ORDER BY created_at DESC LIMIT 1")
            .bind(&self.artifact.digest).bind(&self.configuration).fetch_one(&self.store.pool).await.unwrap()
    }

    async fn job(&self) -> sqlx::postgres::PgRow {
        sqlx::query("SELECT * FROM jobs WHERE subject=$1 AND configuration=$2")
            .bind(&self.artifact.digest)
            .bind(&self.configuration)
            .fetch_one(&self.store.pool)
            .await
            .unwrap()
    }

    async fn evidence(&self) -> Vec<Evidence> {
        self.store
            .evidence(&self.artifact.digest, &self.configuration)
            .await
            .unwrap()
    }

    async fn download(&self) -> (StatusCode, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/r/maven/{ARTIFACT_PATH}"))
                    .header(header::AUTHORIZATION, format!("Bearer {}", "r".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "3");
        }
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["decision"]["state"], "pending");
            assert_ne!(bytes, ROOT_BYTES, "pending delivery exposed artifact bytes");
        }
        (status, bytes)
    }

    async fn administration(
        &self,
        path: &str,
        admin: bool,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().uri(path).header(
            header::AUTHORIZATION,
            format!("Bearer {}", if admin { "a" } else { "r" }.repeat(32)),
        );
        let body = match body {
            Some(value) => {
                request = request
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&value).unwrap())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn ordinary_calls(&self) -> usize {
        std::fs::read_to_string(self.directory.path().join("capture/calls.log"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn assert_authenticated(&self) {
        let requests = self.server.state.requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert!(requests.iter().all(|(_, authenticated)| *authenticated));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn cli_worker_defers_without_spending_retries_and_resumes_one_submission(pool: sqlx::PgPool) {
    let harness = Harness::new(pool, Behavior::Pending).await;
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    harness.worker().await;
    let first = harness.job().await;
    assert_eq!(first.get::<String, _>("state"), "queued");
    assert_eq!(first.get::<i32, _>("attempts"), 0);
    assert!(
        first
            .get::<Option<chrono::DateTime<Utc>>, _>("lease_until")
            .is_none()
    );
    let checkpoint = first
        .get::<Option<Value>, _>("analysis_checkpoint")
        .expect("ordinary results retained");
    assert_eq!(harness.ordinary_calls(), 1);
    assert!(harness.evidence().await.is_empty());
    let submitted = harness.remote().await;
    assert_eq!(submitted.get::<String, _>("state"), "submitted");
    assert_eq!(
        submitted.get::<Option<String>, _>("remote_id").as_deref(),
        Some(SID)
    );
    let correlation: uuid::Uuid = submitted.get("id");
    let captured = harness
        .server
        .state
        .accepted
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(
        captured["metadata"]["packweir_run_id"],
        correlation.to_string()
    );
    assert_eq!(
        captured["metadata"]["packweir_request_digest"],
        submitted.get::<String, _>("request_digest")
    );
    assert_eq!(captured["submission_profile"], "packweir-static");
    assert_eq!(
        captured["params"]["services"]["selected"],
        json!(["Extract"])
    );
    assert_eq!(captured["params"]["ignore_cache"], false);
    assert_eq!(*harness.server.state.uploaded.lock().unwrap(), ROOT_BYTES);
    // Make eligibility explicit: process startup can outlast a short poll
    // interval, particularly when this suite runs many worker processes at once.
    sqlx::query("UPDATE jobs SET not_before=clock_timestamp()+interval '5 minutes' WHERE subject=$1 AND configuration=$2")
        .bind(&harness.artifact.digest).bind(&harness.configuration).execute(&harness.store.pool).await.unwrap();
    sqlx::query("UPDATE remote_analysis SET next_poll_at=clock_timestamp()+interval '5 minutes' WHERE subject=$1 AND configuration=$2")
        .bind(&harness.artifact.digest).bind(&harness.configuration).execute(&harness.store.pool).await.unwrap();
    let requests_before_restart = harness.server.state.requests.lock().unwrap().len();
    harness.worker().await;
    let deferred = harness.job().await;
    assert_eq!(deferred.get::<String, _>("state"), "queued");
    assert_eq!(deferred.get::<i32, _>("attempts"), 0);
    assert_eq!(
        harness.server.state.requests.lock().unwrap().len(),
        requests_before_restart
    );
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.server.state.polls.load(Ordering::SeqCst), 0);
    harness.due().await;
    harness.worker().await;
    assert_eq!(
        harness
            .job()
            .await
            .get::<Option<Value>, _>("analysis_checkpoint"),
        Some(checkpoint)
    );
    assert_eq!(harness.ordinary_calls(), 1);
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    *harness.server.state.behavior.lock().unwrap() = Behavior::Complete;
    harness.due().await;
    harness.worker().await;
    assert_eq!(harness.remote().await.get::<String, _>("state"), "complete");
    assert_eq!(harness.ordinary_calls(), 1);
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    let evidence = harness.evidence().await;
    assert_eq!(
        evidence
            .iter()
            .filter(|e| e.check == "assemblyline" && e.outcome == Outcome::Pass)
            .count(),
        1
    );
    assert_eq!(
        evidence.iter().filter(|e| e.check == "a_ordinary").count(),
        1
    );
    let (status, bytes) = harness.download().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, ROOT_BYTES);
    harness.assert_authenticated();
}

#[sqlx::test(migrations = "./migrations")]
async fn known_submission_survives_transient_poll_failure_and_cli_restart(pool: sqlx::PgPool) {
    let harness = Harness::new(pool, Behavior::PollUnavailable).await;
    harness.worker().await;
    let original_id: uuid::Uuid = harness.remote().await.get("id");
    harness.due().await;
    harness.worker().await;
    let failed_poll = harness.remote().await;
    assert_eq!(failed_poll.get::<String, _>("state"), "submitted");
    assert_eq!(failed_poll.get::<i32, _>("poll_failures"), 1);
    assert_eq!(failed_poll.get::<uuid::Uuid, _>("id"), original_id);
    *harness.server.state.behavior.lock().unwrap() = Behavior::Complete;
    harness.due().await;
    harness.worker().await;
    assert_eq!(harness.remote().await.get::<String, _>("state"), "complete");
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.ordinary_calls(), 1);
    assert_eq!(harness.download().await.0, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn optional_ordinary_failure_does_not_drop_required_remote_work_after_deferral(
    pool: sqlx::PgPool,
) {
    let harness = Harness::with_ordinary(pool, Behavior::Complete, Outcome::Fail).await;
    harness.worker().await;
    assert_eq!(
        harness.remote().await.get::<String, _>("state"),
        "submitted"
    );
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    harness.due().await;
    harness.worker().await;
    assert_eq!(harness.remote().await.get::<String, _>("state"), "complete");
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.ordinary_calls(), 1);
    let evidence = harness.evidence().await;
    assert!(
        evidence
            .iter()
            .any(|e| e.check == "a_ordinary" && e.outcome == Outcome::Fail)
    );
    assert!(
        evidence
            .iter()
            .any(|e| e.check == "assemblyline" && e.outcome == Outcome::Pass)
    );
    assert_eq!(harness.download().await.0, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_poll_credential_defers_known_submission_without_spending_worker_retries(
    pool: sqlx::PgPool,
) {
    let harness = Harness::new(pool, Behavior::Complete).await;
    harness.worker().await;
    let submitted = harness.remote().await;
    let original_id: uuid::Uuid = submitted.get("id");
    assert_eq!(submitted.get::<String, _>("state"), "submitted");
    assert_eq!(
        submitted.get::<Option<String>, _>("remote_id").as_deref(),
        Some(SID)
    );
    let request_count = harness.server.state.requests.lock().unwrap().len();
    harness.due().await;
    // Credentials belong to each worker process. Simulate a temporary secret
    // mount failure without changing configuration or its evidence fingerprint.
    let mut command = harness.command();
    command.env_remove("PACKWEIR_TEST_AL_KEY");
    let output = tokio::time::timeout(std::time::Duration::from_secs(120), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "worker CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(KEY));
    let pending = harness.remote().await;
    assert_eq!(pending.get::<String, _>("state"), "submitted");
    assert_eq!(pending.get::<uuid::Uuid, _>("id"), original_id);
    assert_eq!(
        pending.get::<Option<String>, _>("remote_id").as_deref(),
        Some(SID)
    );
    assert_eq!(pending.get::<i32, _>("poll_failures"), 1);
    let job = harness.job().await;
    assert_eq!(job.get::<String, _>("state"), "queued");
    assert_eq!(job.get::<i32, _>("attempts"), 0);
    assert!(
        job.get::<Option<chrono::DateTime<Utc>>, _>("lease_until")
            .is_none()
    );
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.server.state.polls.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness.server.state.requests.lock().unwrap().len(),
        request_count
    );
    assert_eq!(harness.ordinary_calls(), 1);
    harness.due().await;
    harness.worker().await;
    let completed = harness.remote().await;
    assert_eq!(completed.get::<String, _>("state"), "complete");
    assert_eq!(completed.get::<uuid::Uuid, _>("id"), original_id);
    assert_eq!(
        completed.get::<Option<String>, _>("remote_id").as_deref(),
        Some(SID)
    );
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.server.state.polls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.ordinary_calls(), 1);
    assert_eq!(harness.download().await.0, StatusCode::OK);
    harness.assert_authenticated();
}

#[sqlx::test(migrations = "./migrations")]
async fn accepted_upload_with_lost_response_is_ambiguous_and_never_automatically_reposted(
    pool: sqlx::PgPool,
) {
    let harness = Harness::new(pool, Behavior::LosePostResponse).await;
    harness.worker().await;
    let ambiguous = harness.remote().await;
    assert_eq!(ambiguous.get::<String, _>("state"), "ambiguous");
    assert!(ambiguous.get::<Option<String>, _>("remote_id").is_none());
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    // Requeue the same active job as a manual retry would, without reconciliation.
    harness
        .store
        .enqueue_delivery(
            &harness.artifact,
            &harness.configuration,
            &harness.config.fingerprint(),
        )
        .await
        .unwrap();
    harness.due().await;
    harness.worker().await;
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.remote().await.get::<String, _>("state"),
        "ambiguous"
    );
    assert!(
        harness
            .evidence()
            .await
            .iter()
            .filter(|e| e.check == "assemblyline")
            .all(|e| e.outcome != Outcome::Pass)
    );
    let id: uuid::Uuid = ambiguous.get("id");
    let path = format!(
        "/api/v1/artifacts/{}/remote-analysis",
        harness.artifact.digest
    );
    assert_eq!(
        harness.administration(&path, false, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, list) = harness.administration(&path, true, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(list["analyses"][0]["state"], "ambiguous");
    assert!(list["analyses"][0].get("submission_token").is_none());
    assert!(list["analyses"][0].get("submission_lease").is_none());
    assert!(!serde_json::to_string(&list).unwrap().contains(KEY));
    let reconcile = format!("{path}/{id}/reconcile");
    assert_eq!(
        harness
            .administration(
                &reconcile,
                false,
                Some(json!({"submission_id":"forged-sid"}))
            )
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness
            .administration(
                &reconcile,
                true,
                Some(json!({"submission_id":"../outside"}))
            )
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, _, recovered) = harness
        .administration(
            &reconcile,
            true,
            Some(json!({"submission_id":"forged-sid"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recovered["approval_effect"], "none");
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    // An administrator may attach a SID for verification, but that attachment
    // cannot make an unrelated submission's real response satisfy this job.
    *harness.server.state.behavior.lock().unwrap() = Behavior::Complete;
    for _ in 0..2 {
        harness.due().await;
        harness.worker().await;
    }
    assert_eq!(harness.remote().await.get::<String, _>("state"), "failed");
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    harness.assert_authenticated();
}

async fn incomplete_case(pool: sqlx::PgPool, behavior: Behavior) {
    let harness = Harness::new(pool, behavior.clone()).await;
    harness.worker().await;
    for _ in 0..2 {
        harness.due().await;
        harness.worker().await;
    }
    let evidence = harness.evidence().await;
    assert!(
        evidence.iter().any(|e| e.check == "assemblyline"),
        "{behavior:?}"
    );
    assert!(
        evidence
            .iter()
            .filter(|e| e.check == "assemblyline")
            .all(|e| e.outcome != Outcome::Pass),
        "{behavior:?}"
    );
    assert_eq!(
        harness.download().await.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "{behavior:?}"
    );
    assert_eq!(
        harness.server.state.posts.load(Ordering::SeqCst),
        1,
        "{behavior:?}"
    );
}

macro_rules! incomplete_test {
    ($name:ident,$behavior:ident) => {
        #[sqlx::test(migrations = "./migrations")]
        async fn $name(pool: sqlx::PgPool) {
            incomplete_case(pool, Behavior::$behavior).await;
        }
    };
}
incomplete_test!(metadata_mismatch_keeps_delivery_pending, MetadataMismatch);
incomplete_test!(subject_mismatch_keeps_delivery_pending, SubjectMismatch);
incomplete_test!(filtered_child_tree_keeps_delivery_pending, TreeFiltered);
incomplete_test!(
    changed_service_pin_keeps_delivery_pending,
    ServicePinMismatch
);
incomplete_test!(
    changed_effective_profile_keeps_delivery_pending,
    EffectiveParamsMismatch
);
incomplete_test!(service_error_keeps_delivery_pending, ServiceError);

async fn inventory_denied_case(pool: sqlx::PgPool, behavior: Behavior) {
    let harness = Harness::new(pool, behavior.clone()).await;
    harness.worker().await;
    assert_eq!(
        harness.server.state.posts.load(Ordering::SeqCst),
        0,
        "{behavior:?}"
    );
    assert_eq!(
        harness.download().await.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "{behavior:?}"
    );
    assert!(
        harness
            .evidence()
            .await
            .iter()
            .all(|e| e.check != "assemblyline" || e.outcome != Outcome::Pass)
    );
    harness.assert_authenticated();
}

#[sqlx::test(migrations = "./migrations")]
async fn external_service_blocks_upload(pool: sqlx::PgPool) {
    inventory_denied_case(pool, Behavior::ExternalService).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_service_privilege_blocks_upload(pool: sqlx::PgPool) {
    inventory_denied_case(pool, Behavior::UnknownPrivilege).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn conditional_agent_waits_for_remote_completion_and_binds_current_result(
    pool: sqlx::PgPool,
) {
    let harness = Harness::with_options(pool, Behavior::ServiceError, Outcome::Pass, true).await;
    harness.worker().await;
    assert_eq!(
        harness.remote().await.get::<String, _>("state"),
        "submitted"
    );
    assert_eq!(harness.ordinary_calls(), 1);
    assert!(
        !harness
            .directory
            .path()
            .join("capture/agent.request.json")
            .exists()
    );
    harness.due().await;
    harness.worker().await;
    assert_eq!(harness.remote().await.get::<String, _>("state"), "complete");
    let evidence = harness.evidence().await;
    let remote = evidence.iter().find(|e| e.check == "assemblyline").unwrap();
    assert_eq!(remote.outcome, Outcome::Inconclusive);
    let agent = evidence.iter().find(|e| e.check == "agent").unwrap();
    assert_eq!(agent.outcome, Outcome::Pass);
    assert_eq!(
        agent.details["packweir_inputs"]["findings"]["assemblyline"],
        packweir::model::evidence_fingerprint(remote)
    );
    let bundle: Value = serde_json::from_slice(
        &std::fs::read(harness.directory.path().join("capture/agent.bundle.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(bundle["escalation"]["state"], "triggered");
    assert!(
        bundle["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["check"] == "assemblyline" && e["outcome"] == "inconclusive")
    );
    assert_eq!(
        harness.ordinary_calls(),
        2,
        "one ordinary adapter and one conditional agent"
    );
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test(migrations = "./migrations")]
async fn context_change_during_remote_poll_prevents_stale_completion(pool: sqlx::PgPool) {
    let harness = Harness::new(pool, Behavior::HoldStatus).await;
    harness.worker().await;
    harness.due().await;
    let mut command = harness.command();
    let worker = tokio::spawn(async move { command.output().await.unwrap() });
    tokio::time::timeout(
        std::time::Duration::from_secs(120),
        harness.server.state.status_entered.notified(),
    )
    .await
    .unwrap();
    harness
        .store
        .invalidate(&harness.artifact.digest)
        .await
        .unwrap();
    harness.server.state.status_release.notify_one();
    let output = tokio::time::timeout(std::time::Duration::from_secs(120), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success());
    assert_ne!(harness.remote().await.get::<String, _>("state"), "complete");
    assert!(harness.evidence().await.is_empty());
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 1);
}

async fn redirect_case(pool: sqlx::PgPool, cross_origin: bool) {
    let target = MockServer::start(Behavior::Complete).await;
    let harness = Harness::new(pool, Behavior::Complete).await;
    let destination = format!(
        "{}credential-target/",
        if cross_origin {
            &target.origin
        } else {
            &harness.server.origin
        }
    );
    *harness.server.state.behavior.lock().unwrap() = Behavior::InventoryRedirect(destination);
    harness.worker().await;
    assert_eq!(harness.server.state.posts.load(Ordering::SeqCst), 0);
    assert_eq!(harness.server.state.redirect_hits.load(Ordering::SeqCst), 0);
    assert_eq!(target.state.redirect_hits.load(Ordering::SeqCst), 0);
    assert!(target.state.requests.lock().unwrap().is_empty());
    assert_eq!(harness.download().await.0, StatusCode::SERVICE_UNAVAILABLE);
    harness.assert_authenticated();
}

#[sqlx::test(migrations = "./migrations")]
async fn same_origin_redirect_is_not_followed(pool: sqlx::PgPool) {
    redirect_case(pool, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn cross_origin_redirect_never_receives_credentials(pool: sqlx::PgPool) {
    redirect_case(pool, true).await;
}
