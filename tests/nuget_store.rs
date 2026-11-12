//! NuGet archives share hosted transactional publication without sharing approvals.
use chrono::{Duration, Utc};
use packweir::{
    access::NugetOwnership,
    config::{Config, RepositoryKind},
    hosted::{self, CopyRequest, HostedError, StageState},
    model::{Artifact, Decision, Ecosystem, Evidence, Outcome, sha256},
    nuget::Coordinate,
    policy::PolicyRequirements,
    store::Store,
};
use serde_json::json;
use std::path::Path;
use uuid::Uuid;

fn config() -> Config {
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    let mut repository = config.repositories["nuget"].clone();
    repository.kind = RepositoryKind::Hosted;
    repository.upstream = None;
    repository.download_origins.clear();
    repository.token_env = None;
    repository.cache_max_age_seconds = None;
    repository.cargo_download_template = None;
    repository.retain = true;
    config
        .repositories
        .insert("nuget-local".into(), repository.clone());
    repository.policy = Some(PolicyRequirements {
        revision: "nuget-production-v1".into(),
        required: vec!["release_review".into()],
        deny_on_failure: vec!["release_review".into()],
        agent_escalation: None,
    });
    config.repositories.insert("nuget-prod".into(), repository);
    config.access.nuget_owners = vec![NugetOwnership {
        prefix: "packweir.private".into(),
        repository: "nuget-local".into(),
        additional_repositories: vec!["nuget-prod".into()],
    }];
    config.validate().unwrap();
    config
}

fn coordinate() -> Coordinate {
    Coordinate::new("Packweir.Private.Fixture", "01.0.0.0+build.1").unwrap()
}

fn artifact(config: &Config, repository: &str) -> (String, Artifact) {
    let coordinate = coordinate();
    let path = format!("flatcontainer/{}", coordinate.package_path());
    let bytes = b"original verified NuGet archive fixture";
    (
        path.clone(),
        Artifact {
            repository: repository.into(),
            origin: config
                .public_url
                .join(&format!("r/{repository}/{path}"))
                .unwrap()
                .into(),
            digest: sha256(bytes),
            size: bytes.len() as i64,
            filename: coordinate.filename(),
            content_type: "application/octet-stream".into(),
            package: Some(coordinate.package()),
        },
    )
}

async fn populated(store: &Store, config: &Config) -> (Uuid, String, Artifact) {
    let id = Uuid::new_v4();
    hosted::create_stage(
        store,
        id,
        "nuget-local",
        coordinate().package(),
        "publisher",
    )
    .await
    .unwrap();
    let (path, artifact) = artifact(config, "nuget-local");
    hosted::add_file(store, id, artifact.clone(), &path, "publisher")
        .await
        .unwrap();
    (id, path, artifact)
}

async fn approve_jobs(store: &Store, config: &Config) {
    while let Some(job) = store.lease(&config.fingerprint(), 60).await.unwrap() {
        let scope = store.job_scope(job.id).await.unwrap().unwrap();
        let now = Utc::now();
        let evidence: Vec<_> = config
            .effective_policy(&scope)
            .unwrap()
            .policy
            .required
            .iter()
            .map(|check| Evidence {
                subject: job.subject.clone(),
                configuration: job.configuration.clone(),
                check: check.clone(),
                tool_version: "nuget-store-fixture".into(),
                outcome: Outcome::Pass,
                created_at: now,
                expires_at: now + Duration::hours(1),
                details: json!({"repository":scope.repository}),
                references: vec![],
            })
            .collect();
        store.complete(&job, &evidence).await.unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_aliases_reserve_one_version_and_revoke_does_not_allow_replacement(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let canonical = coordinate().package();
    assert_eq!(canonical.name, "packweir.private.fixture");
    assert_eq!(canonical.version, "1.0.0");
    assert!(canonical.namespace.is_none());
    let id = Uuid::new_v4();
    hosted::create_stage(&store, id, "nuget-local", canonical.clone(), "publisher")
        .await
        .unwrap();
    for alias in ["1", "1.0", "1.0.0", "1.0.0.0", "0001.0000.0000+other"] {
        let package = Coordinate::new("PACKWEIR.PRIVATE.FIXTURE", alias)
            .unwrap()
            .package();
        assert_eq!(package, canonical);
        assert_eq!(
            hosted::create_stage(&store, id, "nuget-local", package.clone(), "publisher")
                .await
                .unwrap()
                .id,
            id
        );
        assert!(matches!(
            hosted::create_stage(&store, Uuid::new_v4(), "nuget-local", package, "publisher").await,
            Err(HostedError::Conflict(_))
        ));
    }
    let mut forged = canonical.clone();
    forged.version = "1.0.0.0".into();
    assert!(matches!(
        hosted::create_stage(&store, Uuid::new_v4(), "nuget-local", forged, "publisher").await,
        Err(HostedError::Invalid(_))
    ));
    let mut wrong_basis = canonical.clone();
    wrong_basis.basis = "registry_metadata_observed".into();
    assert!(matches!(
        hosted::create_stage(
            &store,
            Uuid::new_v4(),
            "nuget-local",
            wrong_basis,
            "publisher"
        )
        .await,
        Err(HostedError::Invalid(_))
    ));
    hosted::revoke(&store, id, "promoter").await.unwrap();
    assert!(matches!(
        hosted::create_stage(
            &store,
            Uuid::new_v4(),
            "nuget-local",
            canonical,
            "publisher"
        )
        .await,
        Err(HostedError::Conflict(_))
    ));
    let revised = Coordinate::new("Packweir.Private.Fixture", "1.0.0.7-RC.1")
        .unwrap()
        .package();
    assert_eq!(revised.version, "1.0.0.7-rc.1");
    hosted::create_stage(&store, Uuid::new_v4(), "nuget-local", revised, "publisher")
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn only_the_original_canonical_archive_can_be_bound_and_sealed(pool: sqlx::PgPool) {
    let store = Store { pool };
    let config = config();
    let id = Uuid::new_v4();
    hosted::create_stage(
        &store,
        id,
        "nuget-local",
        coordinate().package(),
        "publisher",
    )
    .await
    .unwrap();
    let (path, archive) = artifact(&config, "nuget-local");
    for alias in [
        "flatcontainer/Packweir.Private.Fixture/1.0.0/Packweir.Private.Fixture.1.0.0.nupkg",
        "flatcontainer/packweir.private.fixture/1.0.0.0/packweir.private.fixture.1.0.0.0.nupkg",
        "flatcontainer/packweir.private.fixture/1.0.0/packweir.private.fixture.nuspec",
        "flatcontainer/packweir.private.fixture/1.0.0/packweir.private.fixture.1.0.0.nupkg.sha512",
        "flatcontainer/packweir.private.fixture/index.json",
    ] {
        let mut sidecar = archive.clone();
        sidecar.filename = alias.rsplit('/').next().unwrap().into();
        sidecar.origin = config
            .public_url
            .join(&format!("r/nuget-local/{alias}"))
            .unwrap()
            .into();
        assert!(matches!(
            hosted::add_file(&store, id, sidecar, alias, "publisher").await,
            Err(HostedError::Invalid(_))
        ));
    }
    assert!(matches!(
        hosted::seal(&store, id, &config, "promoter").await,
        Err(HostedError::Invalid(_))
    ));
    assert!(matches!(
        hosted::add_file(&store, id, archive.clone(), &path, "other").await,
        Err(HostedError::Conflict(_))
    ));
    hosted::add_file(&store, id, archive.clone(), &path, "publisher")
        .await
        .unwrap();
    hosted::add_file(&store, id, archive.clone(), &path, "publisher")
        .await
        .unwrap();
    let mut replacement = archive.clone();
    replacement.digest = sha256(b"changed bytes");
    assert!(matches!(
        hosted::add_file(&store, id, replacement, &path, "publisher").await,
        Err(HostedError::Conflict(_))
    ));
    let sealed = hosted::seal(&store, id, &config, "promoter").await.unwrap();
    assert_eq!(sealed.manifest.files.len(), 1);
    assert_eq!(sealed.manifest.files[0].artifact.digest, archive.digest);
    assert_eq!(
        sealed.manifest_digest,
        sha256(&serde_json::to_vec(&sealed.manifest).unwrap())
    );
    let jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE scope->>'repository'='nuget-local'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(jobs, 1);
    assert!(matches!(
        hosted::promote(&store, id, &config, "promoter").await,
        Err(HostedError::NotApproved(_))
    ));
    approve_jobs(&store, &config).await;
    hosted::promote(&store, id, &config, "promoter")
        .await
        .unwrap();
    assert_eq!(
        hosted::published_versions(&store, "nuget-local", &coordinate().name)
            .await
            .unwrap(),
        vec!["1.0.0"]
    );
    assert_eq!(
        hosted::delivery(&store, "nuget-local", &path, &config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Approved
    );
    store.invalidate(&archive.digest).await.unwrap();
    assert!(matches!(
        hosted::delivery(&store, "nuget-local", &path, &config)
            .await
            .unwrap()
            .unwrap()
            .decision,
        Decision::Pending(_)
    ));
    hosted::revoke(&store, id, "promoter").await.unwrap();
    assert!(
        hosted::published_file(&store, "nuget-local", &path)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn copy_preserves_archive_and_lineage_but_requires_destination_policy_evidence(
    pool: sqlx::PgPool,
) {
    let store = Store { pool };
    let config = config();
    let (source, path, original) = populated(&store, &config).await;
    let sealed = hosted::seal(&store, source, &config, "promoter")
        .await
        .unwrap();
    approve_jobs(&store, &config).await;
    hosted::promote(&store, source, &config, "promoter")
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let request = CopyRequest {
        id: Uuid::new_v4(),
        destination_repository: "nuget-prod".into(),
        source_manifest_digest: sealed.manifest_digest,
    };
    let copied = hosted::copy_release(&store, source, &config, &request, "copier")
        .await
        .unwrap();
    assert_eq!(copied.destination.stage.state, StageState::Sealed);
    assert_eq!(copied.destination.manifest.files.len(), 1);
    let target = &copied.destination.manifest.files[0].artifact;
    assert_eq!(target.digest, original.digest);
    assert_eq!(target.package, original.package);
    assert_eq!(
        target.origin,
        config
            .public_url
            .join(&format!("r/nuget-prod/{path}"))
            .unwrap()
            .as_str()
    );
    assert_ne!(target.origin, original.origin);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(before, after, "copy inserts no evidence");
    let target_fingerprint = config.delivery_fingerprint(&target.scope()).unwrap();
    assert_ne!(
        target_fingerprint,
        config.delivery_fingerprint(&original.scope()).unwrap()
    );
    assert!(
        store
            .evidence(&target.digest, &target_fingerprint)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        copied.source_files[0]
            .evidence
            .iter()
            .all(|e| e["document"]["details"]["repository"] == "nuget-local")
    );
    assert!(matches!(
        hosted::promote(&store, request.id, &config, "promoter").await,
        Err(HostedError::NotApproved(_))
    ));
    approve_jobs(&store, &config).await;
    let published = hosted::promote(&store, request.id, &config, "promoter")
        .await
        .unwrap();
    assert!(
        published.files[0]
            .evidence
            .iter()
            .any(|e| e["document"]["check"] == "release_review")
    );
    assert!(
        published.files[0]
            .evidence
            .iter()
            .all(|e| e["document"]["details"]["repository"] == "nuget-prod")
    );
    hosted::revoke(&store, request.id, "promoter")
        .await
        .unwrap();
    assert_eq!(
        hosted::copy_release(&store, source, &config, &request, "copier")
            .await
            .unwrap()
            .destination
            .stage
            .state,
        StageState::Revoked
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_copy_and_invalid_repository_configuration_leave_no_destination(pool: sqlx::PgPool) {
    let store = Store { pool };
    let config = config();
    let (source, _, _) = populated(&store, &config).await;
    let sealed = hosted::seal(&store, source, &config, "promoter")
        .await
        .unwrap();
    approve_jobs(&store, &config).await;
    hosted::promote(&store, source, &config, "promoter")
        .await
        .unwrap();
    for changed in [
        {
            let mut c = config.clone();
            c.policy.revision = "changed-policy".into();
            c
        },
        {
            let mut c = config.clone();
            c.repositories.get_mut("nuget-prod").unwrap().ecosystem = Ecosystem::Maven;
            c
        },
        {
            let mut c = config.clone();
            c.access.nuget_owners[0].additional_repositories.clear();
            c
        },
    ] {
        let request = CopyRequest {
            id: Uuid::new_v4(),
            destination_repository: "nuget-prod".into(),
            source_manifest_digest: sealed.manifest_digest.clone(),
        };
        assert!(
            hosted::copy_release(&store, source, &changed, &request, "copier")
                .await
                .is_err()
        );
        assert!(matches!(
            hosted::stage(&store, request.id).await,
            Err(HostedError::NotFound)
        ));
        assert!(hosted::lineage(&store, request.id).await.unwrap().is_none());
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM jobs WHERE scope->>'repository'='nuget-prod'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    // Invalid final delivery bindings cannot be sealed into retained hosted storage.
    let other = Uuid::new_v4();
    let other_coordinate = Coordinate::new("Packweir.Private.Other", "1").unwrap();
    hosted::create_stage(
        &store,
        other,
        "nuget-local",
        other_coordinate.package(),
        "publisher",
    )
    .await
    .unwrap();
    let (_, mut wrong_origin) = artifact(&config, "nuget-local");
    wrong_origin.package = Some(other_coordinate.package());
    wrong_origin.filename = other_coordinate.filename();
    wrong_origin.origin = "https://attacker.invalid/substitute.nupkg".into();
    let path = format!("flatcontainer/{}", other_coordinate.package_path());
    hosted::add_file(&store, other, wrong_origin, &path, "publisher")
        .await
        .unwrap();
    assert!(matches!(
        hosted::seal(&store, other, &config, "promoter").await,
        Err(HostedError::Invalid(_))
    ));
    assert_eq!(
        hosted::stage(&store, other).await.unwrap().state,
        StageState::Open
    );
}
