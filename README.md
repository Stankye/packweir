# Packweir

Control what flows into your software supply chain.

Packweir is an experimental package security gateway in Rust, licensed under MIT OR Apache-2.0. The name combines packages with a weir: a gate that regulates flow.

The product direction is an open-source artifact repository manager with supply-chain assurance, license compliance, and investigation workflows. Proxying and optional caching come first; hosted repositories, promotion, and OCI distribution follow. See the [product scope and assurance model](docs/product-scope.md) for the intended lifecycle, standards mapping, threat coverage, and acceptance criteria.

The repository contains the initial proxy, evidence, policy, storage, and worker implementation. **The full architecture roadmap is not implemented.** Windows and Linux checks cover PostgreSQL/HTTP integration and real security-tool drivers. A Docker matrix exercises real npm, pip, Cargo, Maven, Gradle, and NuGet clients against local fixtures with both filesystem and S3-compatible storage. This validates selected authenticated install flows, not full registry conformance. See [container qualification](docs/containers.md) for coverage and reproduction. This remains an experimental source release.

## Current implementation

- Five registry adapters: npm, PyPI, Cargo sparse index, Maven/Gradle repositories, and NuGet v3.
- Observed package coordinates/PURLs, additive repository and namespace/package policies, and isolated delivery approvals over shared blobs.
- `packweir explain` with policy layers, per-check freshness, scanner availability, job state, and next actions.
- Authenticated gateway and administrative API; separate administrative and package-read credentials.
- Bounded upstream downloads with exact-origin allowlists, redirect validation, DNS pinning, and private-address rejection.
- Content-addressed OpenDAL filesystem/S3 storage, verified reads, and optional post-delivery retention.
- PostgreSQL-backed artifacts, leased jobs, evidence, source-document revisions, decisions, and audit events.
- Fail-closed policy evaluation: a missing, unsupported, failed, expired, or inconclusive required check cannot approve delivery.
- Bounded archive inventory, native-binary identification, and observed CycloneDX 1.6/SPDX 2.3 file inventories.
- Attributable document ingestion/export, explicit unverified status, and invalidation of evidence when external documents or artifact identities change.
- A bounded command-adapter protocol for external scanners, provenance verifiers, and future agents.
- A Cosign-backed Sigstore blob-signature driver with exact signer/issuer policy and pinned executable/trust root; digest-pinned resource snapshots for custom adapters.
- Built-in SLSA Verifier, offline OSV-Scanner, and Hipcheck drivers with explicit source/package mappings, preserved findings, plugin pins, and database-bound evidence expiry.

The sample configuration requires inventory and archive-safety checks only. **This is a bootstrap policy, not malware detection or a provenance guarantee.** Configure trusted adapters and add their check names to `policy.required` before depending on those capabilities. Requiring an unavailable integration keeps the artifact pending.

## Run

Requires a current Rust toolchain and PostgreSQL 17. Cargo must be able to download dependencies. The committed `Cargo.lock` pins dependency resolution. On Windows, the GNU Rust toolchain also needs MinGW GCC/binutils (including `dlltool.exe`) on `PATH`; the MSVC Rust toolchain requires Visual Studio C++ Build Tools instead.

```sh
cargo build --locked
cargo run -- validate

export DATABASE_URL='postgres://packweir:password@localhost/packweir'
export PACKWEIR_ADMIN_TOKEN='<random-admin-secret-of-at-least-32-characters>'
export PACKWEIR_READ_TOKEN='<different-random-read-secret-of-at-least-32-characters>'
cargo run -- serve
# In another terminal, with the same configuration and DATABASE_URL:
cargo run -- worker
```

Use `$env:NAME='value'` in PowerShell. Schema migrations run automatically when the gateway or worker connects. The initial database account needs schema-creation privileges. A gateway and its workers must use identical security configuration and the same blob store.

For containers, copy `.env.example` to `.env`, replace the credentials, and run `docker compose up --build`. The database password must be URL-safe. `packweir.container.toml` binds inside the container to all interfaces, while Compose publishes the gateway on host loopback. Change `public_url` to the client-visible origin when using another hostname or a TLS reverse proxy.

`GET /health` is a liveness check. `GET /ready` checks database and blob-store connectivity, returning `503` when either is unavailable. Both endpoints are unauthenticated and omit dependency error details. `packweir health` probes readiness at the configured local listen address; the container health check uses this command. Readiness does not establish worker availability or security-policy coverage.

For a local artifact inventory without PostgreSQL:

```sh
cargo run -- inventory example.whl
cargo run -- inventory example.whl --format cyclonedx
cargo run -- inventory example.whl --format spdx
```

## Package endpoints

| Client | Endpoint | Authentication |
|---|---|---|
| npm | `http://127.0.0.1:8080/r/npm/` | Registry-scoped npm bearer token |
| pip / uv | `http://127.0.0.1:8080/r/pypi/` | HTTP Basic, password = read token |
| Cargo | `sparse+http://127.0.0.1:8080/r/cargo/` | Cargo registry credential provider/token |
| Maven / Gradle | `http://127.0.0.1:8080/r/maven/` | HTTP Basic or configured Authorization header |
| NuGet | `http://127.0.0.1:8080/r/nuget/index.json` | HTTP Basic, password = read token |

Use a dedicated native-client profile while testing. Do not put administrative credentials in package-manager configuration. Production deployments require TLS. Configuring clients to use Packweir does not prevent direct-registry, Git, URL, or local-file dependency bypasses; network and client policy must address those separately.

The first artifact request stages bytes and returns `503` with a digest and `Retry-After`. A worker analyzes the digest. Retry explicitly after the administrative inspection endpoint reports approval; some clients do not automatically retry long enough. Denied requests return `403`. Upstream error bodies are never forwarded as package bytes.

```sh
cargo run -- prefetch npm 'example/-/example-1.0.0.tgz'
cargo run -- inspect '<sha256-digest>'
cargo run -- explain '<sha256-digest>' --repository npm
```

Prefetch exits unsuccessfully until approved. It uses the same route, storage, and policy path as clients; it does not bypass checks.

See [package identities and scoped policies](docs/policies.md) for configuration and trust boundaries. Observed coordinates are not authenticated publisher/source identities. Scoped rules add requirements to the global baseline; unidentified packages remain pending where identity-based rules apply. Scoped npm/PyPI policies require discovery through the gateway before artifact approval.

## Administrative API

Every `/api/v1` request requires `Authorization: Bearer <admin-token>`.

| Method | Path | Behavior |
|---|---|---|
| GET | `/api/v1/capabilities` | Experimental capability status |
| GET | `/api/v1/artifacts/{digest}` | Per-delivery decisions/explanations, evidence, and documents; optional `repository`/`origin` filters |
| POST | `/api/v1/artifacts/{digest}/documents` | Preserve an external document, without asserting trust |
| GET | `/api/v1/artifacts/{digest}/documents/{blob}` | Retrieve a document linked to this artifact |
| POST | `/api/v1/artifacts/{digest}/rescan` | Expire current evidence and enqueue reanalysis |
| POST | `/api/v1/prefetch` | Stage a repository-relative package path |

Document ingestion accepts `{"kind":"sbom","origin":"publisher_declared","document":{...}}`. Kinds are `sbom`, `attestation`, `sigstore_bundle`, `vex`, and `lockfile`; external origins are `publisher_declared` and `client_resolved`. Ingested SBOMs receive envelope checks only, not full schema or semantic validation. Ingesting a signature or provenance statement does not verify it or approve an artifact. See [tool integrations](docs/integrations.md) to configure and require Sigstore verification.

The inspection response includes artifact `identities` for configuring exact mappings. See [native drivers](docs/native-drivers.md) for source-bound SLSA verification (including original-byte attestation ingestion), offline mapped-package vulnerability checks, and Hipcheck/custom-plugin policies.

## Verification and remaining work

```sh
cargo test --locked --test security
# PostgreSQL user must have CREATE DATABASE privilege for isolated sqlx tests:
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Dependency-free security primitives can be checked without Cargo downloads:

```sh
rustc --edition 2024 --test src/bounds.rs -o target/bounds-tests
./target/bounds-tests
```

The full suite includes policy, archive expansion/traversal, binary inventory, integrity substitution, metadata rewriting, blob tampering, real HTTP gating, lease ownership, readiness, and evidence-context invalidation tests. CI supplies PostgreSQL and separately qualifies pinned Cosign, SLSA Verifier, OSV-Scanner, and Hipcheck binaries. The container job runs six native clients with filesystem and S3-compatible storage:

```sh
python3 tests/e2e/run.py --storage both
```

This matrix covers preapproved local fixtures, scoped npm packages, hash-locked wheels, Cargo credential providers, Maven plugin/dependency resolution, Gradle dependency resolution, and NuGet restore. It also checks pending/denied delivery, byte ranges, offline retained bytes, corrupted blobs, credential isolation, and dependency outages. Logs, client versions, and image identities are saved under `target/e2e/`. See [coverage and limitations](docs/containers.md) before applying these results to a deployment.

The [initial source review](docs/initial-review.md) records corrected defects, completed validation, and remaining qualification gaps.

See [scanner protocol](docs/scanners.md) for the external-tool trust boundary, [tool integrations](docs/integrations.md) for Sigstore configuration and the Hipcheck/OSSGadget/Google tool plan, and [compatibility and roadmap](docs/compatibility.md) for explicit limitations. Specialized tools, native provenance retrieval and source/build trust verification, complete SBOM validation, application dependency resolution, OCI/ORAS transport, hosted publishing, repository groups, RBAC, promotion, a UI, and VM sandboxing remain unfinished.
