# Compatibility and roadmap

All native adapters are experimental and require real-client conformance testing. The implementation preserves package bytes while rewriting discovery/download locations. It does not claim Nexus or Artifactory feature parity.

| Ecosystem | Implemented routing | Important limitations |
|---|---|---|
| npm | Packuments, tarball links with SHA-512/SHA-1 binding, JSON security-resource forwarding | No publish, vulnerability-audit POST API, namespace reservation, or automatic provenance retrieval/verification. Download URLs outside configured origins are rejected. |
| PyPI | HTML and JSON simple indexes, distribution/hash links, requires-python/yanked metadata | PEP 658 sidecar advertisement is disabled so clients download the gated distribution. JSON hashes use SHA-256 when supplied. Native attestation retrieval/verification is not implemented. Bzip2, XZ, Zstandard, RAR, and 7z archives are rejected until bounded inspection is implemented. |
| Cargo | Sparse index, generated authenticated config, checksum-bound crate download route | No Git index, publishing, owner/yank API, or client credential-provider conformance validation. |
| Maven / Gradle | Artifact paths, POMs, snapshots, metadata, checksum/signature sidecars | POMs and artifacts are gated individually; no publishing, native signature verifier, or snapshot-cache freshness policy. Retained artifact paths must be invalidated explicitly when upstream bytes are mutable. |
| NuGet | V3 service/discovery resource rewriting, package downloads, Basic authentication | No publishing/search conformance guarantee, trusted-signer policy integration, or built-in package signature verifier. Upstream signed package bytes remain unchanged. |

Single byte ranges are served only after complete artifact approval. Multiple ranges and conditional requests are not implemented. The gateway fetches complete bounded responses and does not promise streaming large-artifact performance. Client-provided credentials are never forwarded upstream. Configured upstream bearer secrets are origin-scoped; other upstream authentication schemes need adapters/configuration support.

Cache hits reuse retained original bytes and reevaluate current policy. They do not currently revalidate upstream mutable artifact URLs. With `retain=false`, approved bytes are deleted after delivery if no retaining repository or active analysis references them. Denied, abandoned, failed-analysis, and superseded blobs require future garbage collection; there is no automatic retention/TTL collector yet. Job fetch/scan deduplication is database-backed for scans and process-local for fetches. Requests can duplicate upstream work across multiple gateway replicas.

Current jobs are retried up to three times per queued run with lease recovery; exhausted expired leases become failed jobs. Evidence-context changes and manual rescans invalidate existing findings, and lease ownership/context checks prevent old workers from committing stale results. Adapters have wall-clock/output limits; full worker resource scheduling and isolation remain external responsibilities.

## Milestones

1. **Finish the initial evidence proxy:** Windows compilation and PostgreSQL tests pass; validate all five native clients and S3/container deployment; implement trusted scanner adapters, native provenance retrieval/verifiers, complete SBOM validation, metrics, safe garbage collection, mutable-artifact freshness, and namespace routing controls.
2. **Deep analysis and advanced clients:** add selective Ghidra/deobfuscation, automatic agent escalation, OpenSSF Package Analysis, audit APIs, a supported client/version matrix, and external OCI artifact/report storage.
3. **Hosted repositories:** add private publishing, repository groups, namespace ownership, permissions, quarantine, immutable releases, digest-bound promotion, signing workflows, and an administrative UI.
4. **OCI distribution:** add hosted/proxied OCI manifests, blobs, tags, referrers, authentication, and ORAS conformance tests.
5. **Specialized sandboxing:** integrate dedicated DRAKVUF-class workers and optional operator-provided THOR. Identify the proposed “asv4” integration before committing to its API or deployment needs.

Provenance claims, SBOM completeness, vulnerability absence, source posture, and malicious behavior are separate evidence categories. No overall score should silently substitute for an explicit required policy check.
