# Initial publication review

This is an experimental source release with a passing Windows build and test suite, not a validated production gateway. The implementation and capability gaps are described in the README and compatibility matrix.

## Source review

Reviewed registry routing and rewriting, authentication, upstream fetching, policy/evidence binding, archive inspection, scanner process execution, PostgreSQL jobs/migrations, OpenDAL storage, CLI, tests, container configuration, licenses, ignore rules, and CI.

Corrected issues during review:

- Preserve client-visible integrity fragments in rewritten PyPI/npm links while retaining expected digests inside routed targets.
- Match NuGet query and Maven/PyPI metadata routes precisely, avoiding artifact-name substring matches.
- Always gate Cargo's configured download template, regardless of filename, and validate sparse-index JSON before treating a response as metadata.
- Invalidate in-flight analysis when an operator requests a rescan.
- Transition exhausted expired worker leases to failed state instead of leaving staging permanently pinned by a running job.
- Bound DNS lookup time, scanner timeout configuration, and evidence TTL; reject public URL credentials and upstream base queries.
- Include the engine version in security configuration fingerprints and enable OpenDAL's Tokio executor explicitly.
- Inspect concatenated gzip members and TAR entries beyond zero padding; count directory entries toward inspection limits.
- Reject recognized unsupported archive compression instead of reporting archive-safety approval for opaque compressed bytes.
- Exclude environment and local configuration variants from Docker build context.

Regression tests cover these cases, including native client hash visibility, authentication separation, redirect path restrictions, archive coverage, lease exhaustion, and rescan invalidation.

## Validation status

Validated on 2026-10-27 using Rust 1.99.1 for Windows GNU, portable MinGW GCC/binutils, and PostgreSQL 17.11 bound to loopback:

- `cargo build --locked --all-targets` succeeds.
- `cargo test --locked --all-targets` passes all 30 tests: 6 bounds tests, 19 security tests, and 5 PostgreSQL/HTTP integration tests.
- `cargo fmt --all -- --check` passes.
- `cargo clippy --locked --all-targets -- -D warnings` passes.
- The CLI validates both checked-in configurations and reports version `0.1.0`.
- Dependency resolution is pinned in `Cargo.lock`; CI and Docker builds use `--locked`.

Network restrictions initially blocked validation; the results above were obtained after access was restored. Build-only portable tools and the isolated Cargo cache live under ignored `target/`, not in the published source.

Remaining qualification gaps:

- Native npm, pip/uv, Cargo, Maven/Gradle, and NuGet conformance tests remain unfinished.
- S3 integration and container execution have not been tested locally. CI provides a separate Linux/PostgreSQL check after publication.

## Known implementation limits

Tool-specific security adapters and built-in cryptographic provenance verification are not implemented. The sample policy only requires inventory/archive inspection. SBOM ingestion checks supported envelope shape, not full schemas or semantic completeness. Command adapters are trusted executables, not a sandbox. Deep analysis, conditional agent escalation, repository publishing/RBAC, OCI/ORAS, metrics, and safe garbage collection remain roadmap work.

Fetch deduplication is process-local. Shared-blob cleanup is not coordinated with staging across multiple gateway replicas. Retained mutable upstream artifact paths are not automatically revalidated. These availability/freshness limitations must be resolved before production or replicated deployment.
