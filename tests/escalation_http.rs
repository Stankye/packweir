//! Conditional investigation through the real worker and HTTP delivery gate.
//! The subprocess is a test-owned protocol fixture, not an LLM/provider qualification.
#[allow(dead_code)]
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use packweir::{
    config::{CommandScanner, Config, PinnedResource, ScannerDriver, StorageConfig},
    gateway::{self, AppState},
    identity,
    model::{Artifact, Evidence, Outcome, sha256},
    policy::{AgentEscalation, OutcomeCondition, PolicyRequirements, PolicyScope},
    scanner,
    storage::BlobStore,
    store::Store,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tower::ServiceExt;

const PATH: &str = "dev/private/library/1.0.0/library-1.0.0.jar";

fn jar() -> Vec<u8> {
    jar_variant(b"harmless investigation fixture")
}

fn jar_variant(contents: &[u8]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("library.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap().into_inner()
}

fn rule(check: &str) -> AgentEscalation {
    AgentEscalation {
        when_any: vec![OutcomeCondition {
            check: check.into(),
            outcomes: vec![Outcome::Fail],
        }],
    }
}

fn agent_report() -> Value {
    json!({"outcome":"pass","details":{
        "model":"protocol-fixture-only",
        "prompt_digest":sha256(b"test-owned prompt"),
        "toolset_digest":sha256(b"test-owned tools"),
        "evidence_digest":"$EVIDENCE_DIGEST",
        "trace_digest":sha256(b"test-owned trace")
    }})
}

fn install(config: &mut Config, root: &Path, name: &str, report: Value, mode: Option<&str>) {
    let bytes = serde_json::to_vec(&report).unwrap();
    let path = root.join(format!("{name}.report.json"));
    std::fs::write(&path, &bytes).unwrap();
    let binary = support::escalation_fixture_program();
    let mut args = vec![name.into()];
    args.extend(mode.map(str::to_owned));
    config.scanners.insert(
        name.into(),
        CommandScanner {
            program: binary.to_string_lossy().into(),
            program_sha256: Some(sha256(&std::fs::read(binary).unwrap())),
            args,
            version: "test-owned-escalation-protocol-v1".into(),
            timeout_seconds: 15,
            environment: BTreeMap::from([(
                "PACKWEIR_ESCALATION_CAPTURE".into(),
                root.join("capture").to_string_lossy().into(),
            )]),
            resources: BTreeMap::from([(
                "report".into(),
                PinnedResource {
                    path: path.to_string_lossy().into(),
                    sha256: sha256(&bytes),
                },
            )]),
            driver: ScannerDriver::Command,
        },
    );
}

struct Fixture {
    app: Router,
    config: Arc<Config>,
    store: Store,
    blobs: BlobStore,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new(pool: sqlx::PgPool, configure: impl FnOnce(&mut Config, &Path)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("capture")).unwrap();
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        config.repositories.retain(|name, _| name == "maven");
        config.storage = StorageConfig::Fs {
            root: directory.path().join("storage").to_string_lossy().into(),
        };
        config.policy.trust_agent = true;
        config.policy.agent_escalation = Some(rule("a_heuristic"));
        install(
            &mut config,
            directory.path(),
            "a_heuristic",
            json!({"outcome":"fail","details":{"reason":"test-owned investigation lead"}}),
            None,
        );
        install(
            &mut config,
            directory.path(),
            "z_late",
            json!({"outcome":"pass","details":{"last_ordinary_check":true}}),
            None,
        );
        install(&mut config, directory.path(), "agent", agent_report(), None);
        configure(&mut config, directory.path());
        config.validate().unwrap();
        let config = Arc::new(config);
        let store = Store { pool };
        let blobs = BlobStore::new(&config.storage).unwrap();
        let app = gateway::router(AppState::new(
            config.clone(),
            store.clone(),
            blobs.clone(),
            "a".repeat(32),
            "r".repeat(32),
        ));
        Self {
            app,
            config,
            store,
            blobs,
            directory,
        }
    }

    fn capture(&self, name: &str) -> PathBuf {
        self.directory.path().join("capture").join(name)
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.capture("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    async fn register(&self, path: &str, bytes: Vec<u8>) -> Artifact {
        let repository = &self.config.repositories["maven"];
        let origin = repository.proxy_upstream().unwrap().join(path).unwrap();
        let digest = self.blobs.put(bytes.clone()).await.unwrap();
        let artifact = self
            .store
            .register(&Artifact {
                repository: "maven".into(),
                origin: origin.to_string(),
                digest,
                size: bytes.len() as i64,
                filename: path.rsplit('/').next().unwrap().into(),
                content_type: "application/java-archive".into(),
                package: identity::observe(repository, &origin, path),
            })
            .await
            .unwrap();
        self.store
            .enqueue_delivery(
                &artifact,
                &self.config.delivery_fingerprint(&artifact.scope()).unwrap(),
                &self.config.fingerprint(),
            )
            .await
            .unwrap();
        artifact
    }

    async fn request(&self, path: &str, admin: bool) -> (StatusCode, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", if admin { "a" } else { "r" }.repeat(32)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        (
            response.status(),
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    async fn download(&self, path: &str) -> StatusCode {
        self.request(&format!("/r/maven/{path}"), false).await.0
    }

    async fn analyze(&self) {
        scanner::worker(
            self.config.clone(),
            self.store.clone(),
            self.blobs.clone(),
            true,
        )
        .await
        .unwrap();
    }

    async fn evidence(&self, artifact: &Artifact) -> Vec<Evidence> {
        self.store
            .evidence_history(
                &artifact.digest,
                &self.config.delivery_fingerprint(&artifact.scope()).unwrap(),
            )
            .await
            .unwrap()
    }

    async fn inspect(&self, artifact: &Artifact) -> Value {
        let (status, bytes) = self
            .request(&format!("/api/v1/artifacts/{}", artifact.digest), true)
            .await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn finding<'a>(evidence: &'a [Evidence], check: &str) -> &'a Evidence {
    let matches: Vec<_> = evidence.iter().filter(|e| e.check == check).collect();
    assert_eq!(matches.len(), 1, "one current result for {check}");
    matches[0]
}

#[sqlx::test(migrations = "./migrations")]
async fn triggered_agent_runs_once_after_all_ordinary_checks_with_the_bound_bundle(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, |config, root| {
        install(
            config,
            root,
            "z_late",
            json!({"outcome":"pass","details":{"last_ordinary_check":true},
                "valid_until":Utc::now()+Duration::minutes(10)}),
            None,
        );
    });
    let bytes = jar();
    let artifact = fixture.register(PATH, bytes.clone()).await;
    assert_eq!(
        fixture.download(PATH).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.analyze().await;
    assert_eq!(fixture.calls(), ["a_heuristic", "z_late", "agent"]);
    let evidence = fixture.evidence(&artifact).await;
    assert_eq!(finding(&evidence, "a_heuristic").outcome, Outcome::Fail);
    let agent = finding(&evidence, "agent");
    assert_eq!(agent.outcome, Outcome::Pass);
    let bundle_bytes = std::fs::read(fixture.capture("agent.bundle.json")).unwrap();
    let bundle: Value = serde_json::from_slice(&bundle_bytes).unwrap();
    let request: Value =
        serde_json::from_slice(&std::fs::read(fixture.capture("agent.request.json")).unwrap())
            .unwrap();
    assert_eq!(bundle["subject"], artifact.digest);
    assert_eq!(bundle["configuration"], agent.configuration);
    assert_eq!(bundle["context_revision"], request["context_revision"]);
    assert_eq!(bundle["escalation"]["state"], "triggered");
    assert_eq!(bundle["escalation"]["checks"], json!(["a_heuristic"]));
    assert_eq!(bundle["identities"][0]["repository"], "maven");
    assert!(!bundle["documents"].as_array().unwrap().is_empty());
    let inputs: Vec<Evidence> = serde_json::from_value(bundle["findings"].clone()).unwrap();
    for check in [
        "package_identity",
        "inventory",
        "archive_safety",
        "a_heuristic",
        "z_late",
    ] {
        let input = finding(&inputs, check);
        assert_eq!(input.subject, artifact.digest);
        assert_eq!(input.configuration, agent.configuration);
        assert!(agent.expires_at <= input.expires_at);
    }
    assert_eq!(inputs.len(), evidence.len() - 1);
    assert!(inputs.iter().all(|e| e.check != "agent"));
    assert_eq!(agent.details["evidence_digest"], sha256(&bundle_bytes));
    assert_eq!(request["evidence_digest"], sha256(&bundle_bytes));
    let (status, delivered) = fixture.request(&format!("/r/maven/{PATH}"), false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(delivered, bytes);
}

#[sqlx::test(migrations = "./migrations")]
async fn nontriggered_optional_agent_is_skipped_but_an_unconditional_requirement_still_runs(
    pool: sqlx::PgPool,
) {
    for required in [false, true] {
        let fixture = Fixture::new(pool.clone(), |config, root| {
            install(
                config,
                root,
                "a_heuristic",
                json!({"outcome":"pass","details":{}}),
                None,
            );
            if required {
                config.policy.required.push("agent".into());
            }
        });
        let artifact = fixture
            .register(
                PATH,
                jar_variant(if required { b"required" } else { b"optional" }),
            )
            .await;
        fixture.analyze().await;
        let evidence = fixture.evidence(&artifact).await;
        let agent = finding(&evidence, "agent");
        assert_eq!(
            agent.outcome,
            if required {
                Outcome::Pass
            } else {
                Outcome::Skipped
            }
        );
        assert_eq!(
            fixture
                .calls()
                .iter()
                .filter(|name| *name == "agent")
                .count(),
            usize::from(required)
        );
        if !required {
            assert_eq!(agent.details["reason"], "condition_not_triggered");
            assert!(!fixture.capture("agent.bundle.json").exists());
        }
        assert_eq!(fixture.download(PATH).await, StatusCode::OK);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn agent_approval_never_waives_required_checks_or_missing_result_bindings(
    pool: sqlx::PgPool,
) {
    for case in [
        "hard_failure",
        "required_unknown",
        "missing_binding",
        "wrong_digest",
        "error",
        "skipped",
        "unresolved",
    ] {
        let fixture = Fixture::new(pool.clone(), |config, root| match case {
            "hard_failure" | "required_unknown" => {
                let check = if case == "hard_failure" {
                    "required_signature"
                } else {
                    "critical"
                };
                install(
                    config,
                    root,
                    check,
                    json!({"outcome":if case == "hard_failure" { "fail" } else { "inconclusive" },"details":{}}),
                    None,
                );
                config.policy.required.push(check.into());
            }
            "missing_binding" => install(
                config,
                root,
                "agent",
                json!({"outcome":"pass","details":{"model":"protocol-fixture-only"}}),
                None,
            ),
            "wrong_digest" => {
                let mut report = agent_report();
                report["details"]["evidence_digest"] = json!("0".repeat(64));
                install(config, root, "agent", report, None);
            }
            "error" => install(config, root, "agent", agent_report(), Some("error")),
            "skipped" => {
                let mut report = agent_report();
                report["outcome"] = json!("skipped");
                install(config, root, "agent", report, None);
            }
            "unresolved" => install(
                config,
                root,
                "a_heuristic",
                json!({"outcome":"inconclusive","details":{},
                    "valid_until":Utc::now()-Duration::seconds(1)}),
                None,
            ),
            _ => unreachable!(),
        });
        let artifact = fixture.register(PATH, jar_variant(case.as_bytes())).await;
        fixture.analyze().await;
        let evidence = fixture.evidence(&artifact).await;
        let agent = finding(&evidence, "agent");
        if ["hard_failure", "required_unknown"].contains(&case) {
            assert_eq!(agent.outcome, Outcome::Pass, "{case}");
        } else {
            assert_ne!(agent.outcome, Outcome::Pass, "{case}");
        }
        if case == "unresolved" {
            assert_eq!(agent.outcome, Outcome::Skipped);
            assert_eq!(agent.details["reason"], "condition_unresolved");
        }
        if case == "skipped" {
            assert_eq!(agent.outcome, Outcome::Skipped);
        }
        assert_eq!(
            fixture.download(PATH).await,
            if case == "hard_failure" {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            "{case}"
        );
        assert_eq!(
            fixture
                .calls()
                .iter()
                .filter(|name| *name == "agent")
                .count(),
            usize::from(case != "unresolved"),
            "{case}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_condition_input_reopens_the_http_gate_until_fresh_analysis(pool: sqlx::PgPool) {
    let fixture = Fixture::new(pool, |_, _| {});
    let artifact = fixture.register(PATH, jar()).await;
    fixture.analyze().await;
    assert_eq!(fixture.download(PATH).await, StatusCode::OK);
    let configuration = fixture
        .config
        .delivery_fingerprint(&artifact.scope())
        .unwrap();
    let expired = Utc::now() - Duration::seconds(1);
    sqlx::query("UPDATE evidence SET expires_at=$1,document=jsonb_set(document,'{expires_at}',$2) WHERE subject=$3 AND configuration=$4 AND check_name='a_heuristic'")
        .bind(expired).bind(serde_json::to_value(expired).unwrap()).bind(&artifact.digest).bind(&configuration)
        .execute(&fixture.store.pool).await.unwrap();
    assert_eq!(
        fixture.download(PATH).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let report = fixture.inspect(&artifact).await;
    assert_eq!(report["decision"]["state"], "pending");
    assert!(
        report["decision"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "agent_escalation:a_heuristic")
    );
    fixture.analyze().await;
    assert_eq!(fixture.download(PATH).await, StatusCode::OK);
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|name| *name == "agent")
            .count(),
        2
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn global_repository_and_namespace_conditions_accumulate_into_one_investigation(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool.clone(), |config, root| {
        for check in ["repository_signal", "namespace_signal"] {
            install(
                config,
                root,
                check,
                json!({"outcome":"fail","details":{"lead_only":true}}),
                None,
            );
        }
        config.repositories.get_mut("maven").unwrap().policy = Some(PolicyRequirements {
            revision: "repository-investigation-v1".into(),
            required: vec![],
            deny_on_failure: vec![],
            agent_escalation: Some(rule("repository_signal")),
        });
        config.policy_scopes.push(PolicyScope {
            name: "private-investigation".into(),
            repository: "maven".into(),
            namespace: Some("dev.private".into()),
            package: None,
            policy: PolicyRequirements {
                revision: "namespace-investigation-v1".into(),
                required: vec![],
                deny_on_failure: vec![],
                agent_escalation: Some(rule("namespace_signal")),
            },
        });
    });
    let artifact = fixture.register(PATH, jar()).await;
    fixture.analyze().await;
    let bundle: Value =
        serde_json::from_slice(&std::fs::read(fixture.capture("agent.bundle.json")).unwrap())
            .unwrap();
    assert_eq!(
        bundle["escalation"]["checks"],
        json!(["a_heuristic", "namespace_signal", "repository_signal"])
    );
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|name| *name == "agent")
            .count(),
        1
    );
    assert_eq!(fixture.download(PATH).await, StatusCode::OK);
    let report = fixture.inspect(&artifact).await;
    assert_eq!(
        report["scopes"][0]["policy"]["layers"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for required in [false, true] {
        let outside = Fixture::new(pool.clone(), |config, _| {
            config.policy.agent_escalation = None;
            if required {
                config.policy.required.push("agent".into());
            }
            config.policy_scopes.push(PolicyScope {
                name: "private-only".into(),
                repository: "maven".into(),
                namespace: Some("dev.private".into()),
                package: None,
                policy: PolicyRequirements {
                    revision: "private-only-v1".into(),
                    required: vec![],
                    deny_on_failure: vec![],
                    agent_escalation: Some(rule("a_heuristic")),
                },
            });
        });
        let path = "org/other/library/1.0.0/library-1.0.0.jar";
        let artifact = outside
            .register(
                path,
                jar_variant(if required {
                    b"outside-required"
                } else {
                    b"outside-private-rule"
                }),
            )
            .await;
        outside.analyze().await;
        let evidence = outside.evidence(&artifact).await;
        let agent = finding(&evidence, "agent");
        assert_eq!(
            agent.outcome,
            if required {
                Outcome::Pass
            } else {
                Outcome::Skipped
            }
        );
        assert_eq!(
            outside
                .calls()
                .iter()
                .filter(|name| *name == "agent")
                .count(),
            usize::from(required)
        );
        if !required {
            assert_eq!(agent.details["reason"], "scope_not_selected");
            assert!(!outside.capture("agent.bundle.json").exists());
        }
        assert_eq!(outside.download(path).await, StatusCode::OK);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn context_or_artifact_changes_during_agent_execution_cannot_commit_partial_evidence(
    pool: sqlx::PgPool,
) {
    for replace_artifact in [false, true] {
        let fixture = Fixture::new(pool.clone(), |config, root| {
            install(config, root, "agent", agent_report(), Some("pause"));
        });
        let artifact = fixture
            .register(
                PATH,
                jar_variant(if replace_artifact {
                    b"replacement"
                } else {
                    b"context"
                }),
            )
            .await;
        let job = fixture
            .store
            .lease(&fixture.config.fingerprint(), 60)
            .await
            .unwrap()
            .unwrap();
        let config = fixture.config.clone();
        let store = fixture.store.clone();
        let blobs = fixture.blobs.clone();
        let worker =
            tokio::spawn(async move { scanner::analyze(&config, &store, &blobs, &job).await });
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            while !fixture.capture("agent.ready").exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("agent fixture reached the synchronization barrier");
        if replace_artifact {
            let mut changed = artifact.clone();
            changed.digest = fixture
                .blobs
                .put(b"different raw package bytes".to_vec())
                .await
                .unwrap();
            changed.size = 27;
            fixture.store.register(&changed).await.unwrap();
        } else {
            fixture.store.invalidate(&artifact.digest).await.unwrap();
        }
        std::fs::write(fixture.capture("agent.release"), b"release").unwrap();
        assert!(
            worker.await.unwrap().is_err(),
            "stale context cannot complete"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE subject=$1")
            .bind(&artifact.digest)
            .fetch_one(&fixture.store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "ordinary and agent evidence commit atomically");
        assert_eq!(
            fixture.download(PATH).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn rejected_archives_forbid_every_external_tool_even_when_agent_is_required(
    pool: sqlx::PgPool,
) {
    let fixture = Fixture::new(pool, |config, _| {
        config.policy.required.push("agent".into())
    });
    let artifact = fixture
        .register(PATH, b"PK\x03\x04invalid archive".to_vec())
        .await;
    fixture.analyze().await;
    assert!(fixture.calls().is_empty());
    let evidence = fixture.evidence(&artifact).await;
    assert_eq!(finding(&evidence, "archive_safety").outcome, Outcome::Fail);
    assert_eq!(finding(&evidence, "agent").outcome, Outcome::Skipped);
    assert_eq!(
        finding(&evidence, "agent").details["reason"],
        "unsafe_archive"
    );
    assert_eq!(fixture.download(PATH).await, StatusCode::FORBIDDEN);
}
