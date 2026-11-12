# Hosted NuGet packages

Packweir 0.6.0 supports staged immutable NuGet packages, native `dotnet nuget push`, authenticated flat-container restore, and [cross-repository promotion](promotion.md). It preserves the original `.nupkg`, including author/repository signature bytes. Package signature trust is separate: Packweir does not implement a NuGet signature verifier or enforce `trustedSigners` on the server.

## Repositories and credentials

Add these sections to a working configuration, then provision distinct random service secrets of at least 32 characters:

```toml
[repositories.nuget-dev]
kind = "hosted"
ecosystem = "nuget"
retain = true

[repositories.nuget-prod]
kind = "hosted"
ecosystem = "nuget"
retain = true
[repositories.nuget-prod.policy]
revision = "production-v1"
required = ["release_review"]

[access]
legacy_read_enabled = false

[[access.nuget_owners]]
prefix = "acme.private"
repository = "nuget-dev"
additional_repositories = ["nuget-prod"]

[access.principals.build]
token_env = "PACKWEIR_BUILD_TOKEN"
[[access.principals.build.grants]]
repository = "nuget-dev"
namespace = "acme.private"
actions = ["write"]

[access.principals.release]
token_env = "PACKWEIR_RELEASE_TOKEN"
[[access.principals.release.grants]]
repository = "nuget-dev"
namespace = "acme.private"
actions = ["promote"]

[access.principals.consumer]
token_env = "PACKWEIR_CONSUMER_TOKEN"
[[access.principals.consumer.grants]]
repository = "nuget-prod"
namespace = "acme.private"
actions = ["read"]
```

Configure a trusted `release_review` adapter for the production requirement; this example does not provide one. Missing required checks keep delivery pending. Add source-read and destination-write grants for a copying principal and a separate destination-promote grant as shown in [promotion](promotion.md).

For NuGet, a grant's `namespace` is a lowercase package-ID prefix. `acme.private` includes `Acme.Private` and `Acme.Private.Tools`, and excludes `Acme.PrivateEvil`. IDs use the ASCII NuGet grammar, including underscores, with a 100-character limit. Ownership uses the same case-insensitive dot boundary across hosted repositories and public proxies, wrapped URLs, administrative prefetch, and redirect targets. Unknown or ambiguous resource/CDN paths fail closed when reservations apply. Explicit additional repositories authorize another hosted source; they do not create fallback or a repository group.

The compatibility legacy read credential can read every repository when enabled. Disable it for repository-specific access, then grant access to required proxy feeds too. See [credential rotation and expiry](hosted.md#configuration-and-credentials).

## Stage, push, and publish

Create a stage using a write service credential:

```sh
export PACKWEIR_SERVICE_TOKEN="$PACKWEIR_BUILD_TOKEN"
packweir hosted stage nuget-dev Acme.Private.Tools 1.0.0
```

The response includes an `id` and `upload_url`, such as `https://gateway/api/v1/staging/<uuid>/nuget/index.json`. Supply that exact URL to the native client:

```sh
dotnet nuget push Acme.Private.Tools.1.0.0.nupkg \
  --source '<upload_url>' --api-key "$PACKWEIR_BUILD_TOKEN"
packweir hosted seal <stage-uuid>
packweir hosted status <stage-uuid>
```

The staging discovery document is anonymous and contains only its opaque `PackagePublish/2.0.0` URL. Unknown stage UUIDs produce the same shape; it reveals no package coordinates, existence, state, or bytes. Native push uses `X-NuGet-ApiKey` only at the push endpoint. That header cannot authenticate read, seal, copy, promotion, or administrative requests. A key and Authorization header together are rejected. Control requests use a scoped Authorization credential.

The [native push protocol](https://learn.microsoft.com/en-us/nuget/api/package-publish-resource) places the original package in the first multipart item. Packweir ignores its filename and later items while enforcing body/time limits. Push returns `201` for a staged package; it does not publish it. The generic raw-upload API also accepts the canonical `flatcontainer/<id>/<version>/<id>.<version>.nupkg` path.

After required analysis passes, a separate promote credential publishes the reviewed manifest:

```sh
export PACKWEIR_SERVICE_TOKEN="$PACKWEIR_RELEASE_TOKEN"
packweir hosted promote <stage-uuid> --manifest <manifest-sha256>
```

Exactly one package belongs to a NuGet stage. Coordinates come from the validated root nuspec and must match the stage. [Normalized version identity](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#normalized-version-numbers) coalesces `1`, `1.0`, `1.0.0`, and `1.0.0.0`, removes build metadata and leading numeric zeros, and lowercases prerelease labels. Nonzero fourth components remain distinct. Each numeric component fits a nonnegative .NET Int32; numeric prerelease labels cannot have leading zeros. An alias cannot reserve a second release or replace the original bytes. Exact upload retries are allowed while open; changed bytes conflict. Sealed/published/revoked identities remain reserved.

Scanner coverage is independent of valid package syntax. Observed OSV checks receive the normalized identity. The current OSV driver holds nonzero four-part NuGet revisions as unsupported until its matcher is qualified for them; requiring that check keeps those releases pending.

Inspection bounds the package, expanded bytes, entry count, and XML structure. It rejects inconsistent ZIP headers/descriptors/CRCs, hidden local entries, duplicate/case/percent path aliases, traversal, links, file/directory conflicts, multiple or mismatched root nuspecs, DTDs, custom entities, and unsupported XML forms. Accepted nuspecs are UTF-8 XML with direct, unprefixed `package/metadata/id` and `version` fields; UTF-16 and arbitrary namespace/prefix forms are unsupported. Inspection never extracts or executes package code. Validated metadata and hosted coordinates remain publisher declarations; signature-shaped files do not establish trust.

## Restore, transfer, and revoke

Configure the consumer source as `https://gateway/r/nuget-prod/index.json` with HTTP Basic credentials whose password is the read service token. Keep credentials in the native client's credential mechanism. Packweir's hosted index advertises only `PackageBaseAddress/3.0.0`. Its [flat-container resource](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource) serves:

| Relative path | Content |
|---|---|
| `<id>/index.json` | Currently approved, published normalized versions |
| `<id>/<version>/<id>.<version>.nupkg` | Exact original archive |
| `<id>/<version>/<id>.nuspec` | Original nuspec bytes from that archive |
| `<id>/<version>/<id>.<version>.nupkg.sha512` | Base64-encoded raw SHA-512 of the original archive |

Every package, nuspec, hash, HEAD, and range request requires current approval and published membership. Quarantined and revoked versions are absent from discovery. Required evidence expiry or context changes hold the release again. Verified storage reads prevent substituted blobs from being served. Copying into production creates a sealed stage and fresh destination jobs; it transfers no source approval. Source and destination revocation are independent, and neither can recall already downloaded bytes.

The native qualification creates and signs a fresh local fixture, verifies it with `dotnet nuget verify`, pushes and copies it, then restores it under client-side `signatureValidationMode=require` with the exact test author fingerprint. Filesystem and S3 runs compare the delivered original bytes and hash sidecar. This qualifies byte preservation and the selected native flow; the fixture's trusted signer is not a production trust policy.

Search/registration resources, symbol publishing, delete/unlist/relist, server signature verification, native automatic provenance retrieval, general feed conformance, and repository groups remain unfinished. Publication and revocation use the explicit Packweir lifecycle instead of NuGet delete semantics. Control/read deadlines and recovery follow [hosted releases](hosted.md).
