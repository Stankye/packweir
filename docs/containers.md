# Containers and native-client qualification

The production image builds the locked Rust dependency graph, runs as UID 10001, and defaults to `packweir.container.toml` installed as `/app/packweir.toml`. Its writable blob root is `/data`. BuildKit caches Cargo downloads and compilation between builds; the final image contains the executable, CA certificates, configuration, and project licenses.

For the example deployment, copy `.env.example` to `.env`, choose distinct credentials, and run:

```sh
docker compose up --build
```

Compose waits for PostgreSQL before starting the gateway and for gateway readiness before starting the worker. Its explicit health command uses the mounted configuration. The image's default health command is `packweir health`; custom gateway deployments using another configuration path must supply `packweir --config /path/to/config.toml health`. Workers do not expose HTTP endpoints, so both Compose stacks disable the inherited gateway health check on workers; custom worker containers need the same override or `--no-healthcheck`.

`/health` reports process liveness. `/ready` checks PostgreSQL with `SELECT 1` and checks blob storage through OpenDAL, within a three-second budget. Failures return `503` with `{"ready":false}`; success returns `200` with `{"ready":true}`. These unauthenticated responses expose no dependency error details. The CLI probes the configured listen address locally, converts wildcard binds to loopback, and ignores HTTP proxy environment variables.

OpenDAL's S3 connectivity check lists at most one entry beneath the configured root. Grant bucket-list permission scoped to that prefix, in addition to the object permissions needed by the application. Readiness does not test write capacity, worker progress, scanner configuration, evidence coverage, or an entire install transaction.

## Run the isolated matrix

Requires Docker with Linux containers, Compose supporting optional dependencies (`required: false`), and Python 3.10 or newer. Registry access is needed to pull/build images. Native-client package downloads use local fixtures only.

```sh
python3 tests/e2e/run.py --storage both
# Faster iteration after building the current source:
python3 tests/e2e/run.py --storage fs --skip-build
```

`--storage s3` selects RustFS 1.0.4 as a real S3-compatible HTTP service. It exercises OpenDAL's S3 backend; it does not establish compatibility with every S3 provider, AWS IAM configuration, or cloud failure mode. The harness creates its own bucket and uses fixed, public fixture credentials exclusively inside the test stack.

On Windows, the runner works with Windows Python and Docker Desktop. From WSL with Docker integration enabled, use the commands above. If only the Windows Docker CLI is available, this also works:

```sh
python3 tests/e2e/run.py --storage both \
  --docker '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
```

The runner converts bind paths with `wslpath` and exports its Compose variables through `WSLENV`. No Docker socket or host directory is exposed to package clients beyond the read-only test sources and fixture data. Each invocation uses a random Compose project, publishes no host ports, and removes that project's containers, networks, and volumes in a `finally` block. Interrupted host processes may need manual cleanup using the project name printed at startup; the cleanup command is recorded in the runner. Logs and reports remain under ignored `target/e2e/` directories.

## Coverage

The stack contains PostgreSQL, a gateway, a worker, a local multi-registry fixture server, and optional RustFS. Gateway and clients share an internal client network. The gateway also joins the backend network hosting the upstream, storage, worker, and privileged storage diagnostic. Native clients cannot join that backend network; the client probe asserts that the upstream name cannot resolve. There is no external-network route from package clients, so a rewritten link cannot silently fall back to a public registry.

Each client starts in a disposable container with an empty download cache. Artifacts are explicitly prefetched and approved before native installs; a separate probe requests a package before starting the worker to verify the pending gate.

| Client | Local version exercised | Qualified flow |
|---|---|---|
| npm | 11.19.1 | Bearer authentication, scoped and unscoped package install, preserved integrity, installed module contents; lifecycle scripts and audit disabled |
| pip / Python | pip 26.2.2 / Python 3.13.18 | Basic authentication, HTML simple index, visible wheel filename, SHA-256 `--require-hashes`, wheel installation and import |
| Cargo | 1.99.1 | Authenticated sparse registry, `cargo:token`, checksum-bound crate download, compilation and execution of a fixture dependent |
| Maven / Java | Maven 3.9.16 / Temurin 21.0.12.1 | Basic authentication, mirror configuration, custom plugin resolution, dependency/POM/JAR and checksum retrieval |
| Gradle | 8.14 release line / JDK 21; exact version in each report | Basic authentication, native Maven publication, dependency resolution, and JAR content verification |
| NuGet / .NET | SDK 10.0.403 | Basic-authenticated V3 proxy restore; native staged `dotnet nuget push` with an API key; signed hosted-package restore from production with a pinned test author; NuGet audit disabled |

These versions are observations from local qualification. Client images track the specified release lines. Each successful report records the actual version output, image IDs, registry digests where present, platform, and completion time; CI publishes these with logs as `container-client-qualification`. The locally built application image has an image ID but no registry digest.

Both storage modes qualify staged immutable Maven publication with real Gradle `maven-publish`, separate publisher/promoter credentials, no quarantined downloads, per-file checksums, reserved-group routing, Maven/Gradle consumption, and terminal revocation. The report records the manifest, file digests, and publisher version; see [hosted releases](hosted.md) for the supported POM and lifecycle boundaries. The promotion phase copies the published development release into a sealed production repository while workers are stopped. It verifies that source evidence does not approve production, requires a fresh destination-only fixture check and separate production promotion, then consumes from production after withdrawing the source. That check is a pinned test-owned protocol fixture, not a real security/human review. The report preserves matching file digests, different scope fingerprints, copy lineage, and production receipts. This does not qualify `mvn deploy` or snapshot publication.

The hosted NuGet flow uses an SDK-only `net10.0` project with every package source cleared. An offline fixture creates a short-lived, self-signed code-signing certificate in the disposable fixture volume and signs the native `dotnet pack` output with `dotnet nuget sign`. Private keys are never committed or exported to the host. Native `dotnet nuget push` uses the explicit staging V3 index at `/api/v1/staging/{id}/nuget/index.json` and discovers its `PackagePublish/2.0.0` endpoint. The API key authenticates the push through `X-NuGet-ApiKey`; it does not authenticate ordinary downloads or lifecycle API requests. The unauthenticated staging discovery document contains only the opaque publishing URL, without package coordinates or existence information.

Both storage modes exercise quarantine for the package, extracted nuspec, hash sidecar, and version index; malformed or mismatched nuspec rejection; immutable uploads; normalized duplicate-version rejection; and package-prefix reservation across other NuGet proxies, wrapped download routes, and redirects. A published development release is copied to production while the worker is stopped. Separate source and production promoters must approve their own manifest, and production remains hidden until its own stronger policy has fresh `fixture_review` evidence. The source is withdrawn before a fresh-cache `dotnet restore` configured with the production V3 feed as its only source. The original signed `.nupkg` bytes are compared after publication, copy, and restore. The existing unsigned NuGet proxy fixture remains in the six-client regression matrix. Withdrawing production hides its package and metadata as well.

The native restore client requires package signatures and pins the ephemeral test author's SHA-256 certificate fingerprint through `trustedSigners`, with `allowUntrustedRoot=true` for that self-signed fixture and revocation checks in offline mode. This qualifies the native client's explicit fixture trust configuration. Packweir preserves the signature bytes; it does not cryptographically verify NuGet signatures. The destination `fixture_review` adapter proves policy binding and scope separation only, and does not perform a security or human review.

The fixture also references the SDK's bundled `NuGet.Versioning.dll` without downloading a package and compares its normalized versions with staging API identities. Observed SDK 10.0.403 contains `NuGet.Versioning` 7.9.0.0. Cases cover omitted components, leading zeros, a zero fourth component, a nonzero revision, discarded build metadata, prerelease case, invalid numeric prerelease labels, and Int32 component bounds. The combined `target/e2e/report.json` records `hosted_nuget`; each run also writes `nuget-hosted-report.json`. Publisher and restore `version_output` fields record the actual SDK, while `source.normalization` and `source.normalization_reference` record the official assembly comparison. Logs include `nuget-publish.log` and `nuget-hosted-restore.log`.

Both storage modes also assert:

- Approved native downloads expose observed coordinates/PURLs and per-delivery explanations; the npm scope fixture exercises additive namespace requirements.
- A second gateway starts with the image's default configuration, health command, non-root user, and writable `/data`, without configuration or data mounts.
- Missing credentials cannot download packages, and read credentials cannot access the administrative API.
- Pending requests return `503` and `Retry-After`, including range requests; traversal and conflicting ZIP-header archives are denied with `403` after analysis.
- Approved artifacts retain their exact SHA-256 digest, and approved single-byte-range responses match the original bytes.
- Client authorization headers never reach the upstream fixture service.
- Approved retained bytes remain available after stopping the upstream; corrupting the underlying filesystem blob or S3 object prevents delivery, and restoring the original bytes restores access.
- Stopping PostgreSQL (filesystem mode) or object storage (S3 mode) makes readiness fail while liveness remains available.

Rewritten file links include their original filename for clients such as pip. The filename must match the URL embedded in the opaque route; changing it cannot select another target. Hash fragments remain both client-visible and bound to the encoded upstream URL. Directory-style discovery resources remain appendable for NuGet.

## Remaining qualification

This is a controlled core-flow matrix, not exhaustive protocol or production assurance. It does not cover public-registry availability, publishing outside the qualified immutable Maven/Gradle and staged NuGet flows, transitive dependency graphs at scale, every client/version, uv, Maven snapshots, NuGet search/audit, server-side NuGet signature verification or general certificate trust/revocation policy, conditional requests, multiple ranges, host TLS/reverse-proxy setup, multi-replica behavior, storage lifecycle/garbage collection, or large-artifact performance. First-request retry behavior still needs client-specific handling: approval can take longer than native retry budgets.

The matrix's required policy is inventory plus archive safety. Signature/provenance/vulnerability/source checks have separate Rust integration and real-tool qualification jobs; those integrations are not silently enabled by passing the container matrix. See [native drivers](native-drivers.md), [integration catalog](integrations.md), and [compatibility](compatibility.md) for the remaining boundaries.
