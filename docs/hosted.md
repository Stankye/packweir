# Hosted Maven releases

Packweir 0.4.0 adds staged, immutable Maven-format releases. Gradle's native `maven-publish` plugin uploads into a stage; Maven and Gradle consume the published files through the normal authenticated package endpoint. Publishing for npm, PyPI, Cargo, NuGet, OCI, and Maven snapshot versions remains unfinished. The existing proxy adapters continue to support their documented inputs.

## Configuration and credentials

Add a hosted repository and explicit service principals to an existing configuration:

```toml
[repositories.maven-private]
kind = "hosted"
ecosystem = "maven"
retain = true

[access]
legacy_read_enabled = false

[[access.maven_owners]]
namespace = "com.acme"
repository = "maven-private"

[access.principals.build]
token_env = "PACKWEIR_BUILD_TOKEN"
[[access.principals.build.grants]]
repository = "maven-private"
namespace = "com.acme"
actions = ["write"]

[access.principals.release]
token_env = "PACKWEIR_RELEASE_TOKEN"
[[access.principals.release.grants]]
repository = "maven-private"
namespace = "com.acme"
actions = ["promote"]

[access.principals.consumer]
token_env = "PACKWEIR_CONSUMER_TOKEN"
[[access.principals.consumer.grants]]
repository = "maven-private"
namespace = "com.acme"
actions = ["read"]
```

Provision distinct random secrets of at least 32 characters in the gateway's environment, in addition to its administrative and legacy-read tokens. Credential environment names enter configuration fingerprints; secret values do not. Missing, short, duplicate, or administrative/read-equivalent service secrets prevent gateway startup. Workers and `validate` do not need these service secrets. Restart gateways to rotate credentials or change grants; gateways and workers still need matching security configuration.

The optional principal `expires_at` is an RFC 3339 timestamp. Expired principals cannot authenticate or authorize a new request. Permissions are checked when the request is authorized; an already accepted request can be in flight when credentials expire or a process is restarted.

Read, write, and promote permissions are independent. Publishing credentials can inspect their authorized stages, but staged download URLs never serve quarantined file contents. Service credentials cannot use administrative evidence/document/rescan APIs. Administrative tokens do not implicitly publish. Native clients can use HTTP Basic with the service token as password; bearer tokens are also accepted.

`legacy_read_enabled` defaults to `true` for compatibility: the existing read token can read **all repositories**, including hosted ones. Set it to `false` and add explicit consumer grants when access needs to differ by repository or Maven group. Disabling it also means adding grants for any proxy repositories those clients use. Namespace grants currently support Maven groups only; unscoped read grants support each existing proxy ecosystem. This is an operator-configured service-credential model; SSO, user management, delegated credential issuance, and general RBAC remain planned work.

## Ownership and routing

`com.acme` ownership covers that group and descendants such as `com.acme.tools`, with dot boundaries. It excludes `com.acmeevil`. Other Maven repositories reject requests under the reserved group before cache access, metadata fetching, or upstream contact. Wrapped download paths, directory aliases, redirects, and administrative prefetch use the same reservation. Unknown CDN targets cannot establish that they are outside a reserved group and are rejected where ownership applies.

A missing, quarantined, denied, or revoked hosted coordinate never falls through to a proxy. Ownership reserves a configured source; it does not authenticate a publisher or establish benign content. Package-manager bypasses outside Packweir still need deployment/client network policy. Repository groups, precedence for other ecosystems, and namespace ownership outside Maven remain unfinished.

## Publish and review

Use a publishing service credential for the CLI:

```sh
export PACKWEIR_SERVICE_TOKEN="$PACKWEIR_BUILD_TOKEN"
packweir hosted stage maven-private com.acme:library 1.0.0
```

The response contains a stage UUID and `upload_url`. The optional `--id <uuid>` makes stage creation retryable: the same actor and coordinates return the same reservation; changed content bound to that UUID conflicts. A stage reserves its repository/package/version against concurrent publishers.

Configure a Gradle Maven publishing repository with that `upload_url` and the publishing service token. Gradle's `maven-publish` plugin sends the POM, primary artifact, and transport checksums. The HTTP service checks each route against the reserved coordinates, validates direct POM declarations, and stores original bytes through OpenDAL. For a manual file upload:

```sh
packweir hosted upload <stage-uuid> com/acme/library/1.0.0/library-1.0.0.pom ./library.pom
packweir hosted upload <stage-uuid> com/acme/library/1.0.0/library-1.0.0.jar ./library.jar
packweir hosted seal <stage-uuid>
packweir hosted status <stage-uuid>
```

Uploads are bounded, coordinate-bound, and immutable within a stage. Identical retries are accepted; replacing an existing file conflicts. The primary POM must explicitly declare the reserved group, artifact, and version. Parent/property-derived coordinates and custom POM namespaces are unsupported. DTDs, custom entities, processing instructions, and CDATA are rejected; ordinary XML escapes and valid numeric character references are supported.

Sealing requires the primary artifact implied by POM packaging, or the POM alone for `pom` packaging. The supported mappings are `jar`, `maven-plugin`, and `bundle` to JAR; `war`, `ear`, and `aar` to their corresponding extensions. Every uploaded member, including optional classifiers or module metadata, enters the sealed manifest and required security checks. A stage is limited to 128 files and 512 MiB total; each file also obeys the configured download/inspection limits. Oversized or unsupported archive content cannot gain approval through publication.

Sealing freezes a sorted, SHA-256-bound manifest and atomically registers final delivery identities and scanner jobs. Review the manifest and evidence through the stage response and existing administrative inspection APIs. The supplied `manifest_digest` is required for promotion and published revocation:

```sh
export PACKWEIR_SERVICE_TOKEN="$PACKWEIR_RELEASE_TOKEN"
packweir hosted promote <stage-uuid> --manifest <reviewed-manifest-sha256>
```

Promotion locks the release and current evidence contexts, obtains database time after lock waits, and evaluates the current policy for every final delivery scope. Missing, expired, failed, or inconclusive required evidence prevents publication. Requests with missing evidence queue current-configuration analysis, so policy changes can be reassessed. Publication and its audit record commit together. The stored receipt records actor, time, manifest, policy layers, configurations, context revisions, and evidence IDs/documents/digests. `hosted status` retrieves it if a successful promotion response was lost; replaying promotion conflicts.

POM declarations and hosted coordinates remain publisher claims. The existing baseline inventory/archive policy is still a bootstrap policy; configure required signature, provenance, vulnerability, license, or other checks for the intended assurance. Native artifacts and publisher scripts are inspected without executing package code, subject to the documented scanner trust boundary.

## Consume, withdraw, and recover

Consumers use `https://your-gateway/r/maven-private/` as a Maven repository with a read service credential. Public discovery metadata derives from published records. Uploaded `maven-metadata.xml` is discarded; its contents never choose public versions. Uploaded transport checksums are compared to the staged primary bytes, then public MD5/SHA-1/SHA-256/SHA-512 checksums are generated from verified stored bytes. The security/storage identity remains SHA-256.

Every download, HEAD request, byte range, and checksum requires published membership and current approval for **all files in the sealed release**. A change to one member's evidence can hold the entire release again. Discovery lists only versions whose current release checks pass. Revoked and quarantined versions are absent. Blob integrity failures do not release substituted content. These checks cannot recall files already downloaded by clients.

```sh
packweir hosted revoke <stage-uuid> --manifest <reviewed-manifest-sha256>
```

Revocation is terminal and preserves the sealed coordinate reservation, original manifest, and audit history. An open stage can be abandoned with `hosted abort <stage-uuid>` by its original writer; its history remains, and a fresh stage UUID can reserve those never-sealed coordinates again. Sealed coordinates cannot be reused. Requests already authorized before a committed revocation may still be in flight.

Original delivery origins bind the configured `public_url` at sealing. Changing that origin requires an explicit hosted-data migration; the gateway fails closed on mismatched stored delivery origins. Security-policy changes at the same origin trigger fresh analysis. Blob/reference garbage collection, storage quotas, stage expiration, remote repository federation, release-signing workflows, and backup/restore qualification remain unfinished. Proxy delivery with `retain=false` preserves blobs referenced by any hosted stage.

Control requests have a 120-second deadline, uploaded bodies a 60-second deadline, and hosted reads a 30-second deadline. Large histories can exceed the current synchronous discovery budget; indexed aggregation/pagination is future work. Database/storage failures produce sanitized errors.

## Promotion to another repository

[Cross-repository promotion](promotion.md) copies a published release into a new sealed destination with its own evidence and policy evaluation. Namespace ownership can explicitly include additional hosted repositories; it never enables public fallback. Source read and destination write are required for copying, and destination publication retains a separate promote permission. The copy receipt preserves the source assessment while service responses limit source report visibility.

## API and qualification

| Method | Path | Permission |
|---|---|---|
| POST | `/api/v1/repositories/{repository}/staging` | Write to declared group |
| GET | `/api/v1/staging/{id}` | Write or promote for stage group |
| PUT | `/api/v1/staging/{id}/{path}` | Original writer; open stage |
| GET / HEAD | `/api/v1/staging/{id}/{path}` | Original writer; always returns no staged bytes |
| POST | `/api/v1/staging/{id}/seal` | Original writer |
| POST | `/api/v1/staging/{id}/abort` | Original writer; open stage only |
| POST | `/api/v1/staging/{id}/promote` | Promote for stage group and exact manifest |
| POST | `/api/v1/staging/{id}/revoke` | Promote for stage group and exact manifest |
| GET / HEAD | `/r/{repository}/{path}` | Read for release group; current security approval |

The container matrix exercises real Gradle publication, pending checks, role separation, immutable upload retries, generated checksums, namespace reservations, Maven/Gradle consumption, and revocation on filesystem and S3-compatible storage. It records manifests and file digests. This does not qualify `mvn deploy`, snapshot publishing, dependency/plugin policy semantics, universal POM compatibility, or other native publishing protocols.
