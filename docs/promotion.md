# Promotion between hosted repositories

Packweir supports copying a published immutable Maven release or NuGet package into a sealed stage in another hosted repository of the same ecosystem. Original bytes and coordinates stay unchanged. The destination gets its own manifest, delivery identities, jobs, policy evaluation, and publication decision.

This extends the [hosted Maven](hosted.md) and [hosted NuGet](nuget.md) workflows. Other hosted ecosystems, remote/federated repository transfer, storage-provider migration, signing, and review/exception workflows remain unfinished.

## Configure explicit sources and permissions

Define both repositories, and add a stronger destination policy where appropriate:

```toml
[repositories.maven-dev]
kind = "hosted"
ecosystem = "maven"
retain = true

[repositories.maven-prod]
kind = "hosted"
ecosystem = "maven"
retain = true
[repositories.maven-prod.policy]
revision = "production-v1"
required = ["release_review"]

[[access.maven_owners]]
namespace = "com.acme"
repository = "maven-dev"
additional_repositories = ["maven-prod"]

[access.principals.copy]
token_env = "PACKWEIR_COPY_TOKEN"
[[access.principals.copy.grants]]
repository = "maven-dev"
namespace = "com.acme"
actions = ["read"]
[[access.principals.copy.grants]]
repository = "maven-prod"
namespace = "com.acme"
actions = ["write"]

[access.principals.production-release]
token_env = "PACKWEIR_PRODUCTION_RELEASE_TOKEN"
[[access.principals.production-release.grants]]
repository = "maven-prod"
namespace = "com.acme"
actions = ["promote"]
```

Configure a trusted `release_review` scanner, or replace it with the actual checks required by the destination. A missing or unsupported required check keeps the destination pending. The qualification fixture's review adapter is test code, not a production security or human-review integration.

Additional ownership repositories must be explicit hosted repositories of the same ecosystem. They do not create a repository group or enable fallback. The reserved group remains blocked in every other Maven repository, including public proxies. NuGet uses `access.nuget_owners` and canonical ID prefixes with the same explicit authoritative-set rule. Overlapping ownership rules must describe the same complete authoritative set. Scope boundaries and each principal's independent grants still apply. Up to 16 additional repositories are supported per ownership rule.

The copy service must have **read on the source and write on the destination** for the release's group. A source promotion permission alone does not authorize reading its bytes. Destination promotion is independent. Administrative credentials cannot implicitly copy. Configure consumer read grants and consider disabling global legacy read as explained in [hosted credentials](hosted.md).

## Copy, assess, and publish

First publish the source through normal staging, sealing, and promotion. Review its stage UUID and sealed manifest digest, then use a copy service credential:

```sh
export PACKWEIR_SERVICE_TOKEN="$PACKWEIR_COPY_TOKEN"
packweir hosted copy <source-stage-uuid> maven-prod \
  --source-manifest <source-manifest-sha256> \
  --id <new-destination-stage-uuid>
```

The HTTP equivalent is:

```http
POST /api/v1/staging/{source-id}/copy
Authorization: Bearer <copy-service-token>
Content-Type: application/json

{"id":"<destination-uuid>","destination_repository":"maven-prod","source_manifest_digest":"<source-sha256>"}
```

The source must be published and currently approved for every manifest member. Source revocation, changed context, expired evidence, a mismatched manifest, missing/corrupt bytes, or an unauthorized namespace prevents a new copy. Missing current source analysis queues reassessment; no destination is created on a rejected copy.

One database transaction reserves the destination coordinates, binds the complete copied file set, registers final delivery artifacts and scanner jobs, seals its manifest, and records lineage and audit evidence. Source assessment uses database time after lock waits. Conflicting coordinates or transaction failures leave no partial destination. The destination starts **sealed**, with no public download visibility. Its sealed coordinates remain immutable and cannot be abandoned through the open-stage abort operation.

The copy preserves package name, version, paths, file sizes, media types, and digests. Only repository and delivery origin change. OpenDAL retains shared content-addressed blobs; copying does not rewrite package archives or transfer bytes between storage systems.

No source security evidence becomes destination approval. Every copied file receives a new final-scope configuration and analysis job, including baseline checks and destination-specific requirements. Matching blob hashes, a successful source publication, or the copy receipt cannot satisfy missing destination evidence. Digest-bound external documents remain shared inputs; each destination verifier evaluates them against its own configured requirements and mappings.

Inspect the new stage and wait for required analysis, then use a separate destination promotion credential:

```sh
export PACKWEIR_SERVICE_TOKEN="$PACKWEIR_PRODUCTION_RELEASE_TOKEN"
packweir hosted status <destination-stage-uuid>
packweir hosted promote <destination-stage-uuid> \
  --manifest <reviewed-destination-manifest-sha256>
```

Destination promotion and every subsequent delivery use the same current, whole-release checks as an ordinary hosted publication. A stronger destination policy can reject bytes that the source permitted. Native consumers use only the intended destination endpoint, for example `/r/maven-prod/`.

## Retry and lineage evidence

Use a fixed destination UUID for automation. Exact retries bind the authenticated actor, source stage and manifest, destination repository, and destination UUID. They return the recorded copy result with the destination's current state. Changed requests conflict; retries do not add files, reset analysis, reopen stages, or republish a withdrawn release. A historical retry can succeed after source revocation because it reports an already completed operation. A new copy from that revoked source is rejected.

The copy receipt binds both manifests and preserves the source's assessment time, effective configurations, context revisions, and evidence IDs/documents/digests in database lineage and audit records. This records the source decision used at transfer time, rather than assuming its original publication receipt is still current.

Service callers receive a limited source view containing paths, subjects, configuration fingerprints, context revisions, evidence hashes, and evidence IDs. Source package read permission does not grant access to private scanner reports or source policy details. Destination stage inspection exposes the same limited copy lineage alongside its own manifest and promotion receipt.

Administrative auditors can retrieve the full, frozen source evidence snapshot:

```http
GET /api/v1/staging/{destination-id}/copy-evidence
Authorization: Bearer <admin-token>
```

This endpoint is administrative and returns `Cache-Control: no-store`. Service credentials cannot access it. It returns the captured copy evidence; current approval still requires live evaluation.

## Revocation and qualification

Source and destination publications are independent. Withdrawing the source after a successful transfer does not automatically withdraw an independently assessed destination. Withdraw each affected published release during incident response. Digest-wide rescans or external-document context changes still invalidate evidence for every delivery scope sharing that subject. These controls cannot recall bytes already downloaded by clients.

Tests cover source freshness and lock waits, atomic registration and rollback, immutable target collisions, idempotency, permission separation, report privacy, shared bytes, destination-specific check failures, and independent revocation. The filesystem/S3 matrix publishes with native Gradle, copies while workers are stopped to prove that destination approval is absent, then requires fresh destination review before Maven/Gradle consume from production. Reports retain distinct source/destination scope fingerprints and matching file digests. This qualifies the stated Maven workflow, not general repository-manager or framework conformance.
