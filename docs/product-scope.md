# Product scope and assurance model

Packweir's intended product is an open-source artifact repository manager with supply-chain assurance, license compliance, and investigation workflows. It should support the repository operations expected of Nexus or Artifactory while making the evidence behind delivery decisions inspectable. This document describes planned behavior. The [README](../README.md) and [compatibility matrix](compatibility.md) describe what exists today.

## Artifact lifecycle

The target lifecycle is ingest, quarantine, collect and verify evidence, evaluate policy, review exceptions where permitted, promote, serve, and monitor for changed evidence. Proxying and optional caching come first for npm, PyPI, Cargo, Maven/Gradle, and NuGet. Hosted publishing and repository groups follow; OCI distribution and ORAS artifact exchange follow separately. OpenDAL provides blob storage, not registry protocol conformance.

Decisions must bind artifact bytes, registered coordinates, expected source/build identities, policy revision, evidence revision, and evaluation time. Identical bytes may appear under different coordinates with different trust expectations. Preserve original digests and apply explicit retention policies to original bytes and documents; transformations and generated reports become separate digest-linked objects. Optional package caching must not silently erase evidence needed to explain a retained decision. Publisher declarations, client-resolved dependency graphs, scanner observations, cryptographically verified statements, and human conclusions must remain distinguishable.

Approval is specific to configured checks and available evidence. A signed malicious release is still possible; valid provenance does not establish benign behavior. A file inventory is not necessarily a complete application dependency graph. Security approval and license approval need separate outcomes, with unresolved evidence visible in both.

## Threats and proposed controls

These are design requirements, not a claim that the current gateway detects or prevents every attack. The [OWASP supply-chain guidance](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) and [2025 supply-chain failure category](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) provide threat context.

| Threat or difficulty | Proposed controls and evidence | Boundary |
|---|---|---|
| Dependency confusion, typosquatting, namespace takeover | Explicit upstream/namespace ownership, private/public precedence, coordinate history, suspicious-name and new-release signals | Similar names and age are signals; a trusted route does not establish benign content. |
| Compromised maintainer or legitimate malicious release | Release/source diffs, install-hook analysis, source posture, publisher changes, behavioral findings, review escalation | Signatures and source popularity cannot replace content analysis. |
| Build tampering or substituted artifacts | Digest-bound signatures/provenance, expected builder and source policies, verification material, optional independent rebuild comparison | Builder/source assurance needs evidence outside the proxy and explicit trust roots. |
| Embedded binaries, obfuscation, staged payloads, environment-triggered behavior | Bounded inventory, selected Ghidra/deobfuscation helpers, Assemblyline services, isolated execution, agent investigation | Static and dynamic coverage is incomplete; absence of a finding does not prove absence of malicious behavior. |
| Hidden transitive/build dependencies and direct-download bypass | Client lockfiles/resolution evidence, CI consumption receipts, application SBOMs, controlled network egress | Download logs alone do not identify the dependency graph or everything executed by a build. |
| New advisories, changed intelligence, revoked trust | Versioned advisory data, scoped VEX assessment, freshness policy, rescans, decision revocation, downstream impact queries | Blocking future delivery cannot recall bytes already cached or installed by clients. |
| Adversarial package text and scanner output influencing an agent | Isolated tools, explicit tool allowlists and budgets, attributable traces, digest-bound evidence, non-overridable hard failures | Model conclusions remain a separate evidence category; an agent cannot confer missing cryptographic trust. |
| License ambiguity or incomplete redistribution materials | File-level license evidence, SPDX expressions, notices, reviewed obligations and use context | Package metadata alone cannot establish the obligations for every embedded component. |

## Standards and evidence mapping

Implement versioned control profiles with stable control identifiers, evidence requirements, applicability, freshness, and explicit states such as verified, claimed, manual review, unavailable, and failed. Record the framework revision and mapping revision in exported assessments. This is a proposed profile model, not an existing API. A framework mapping must not become an automatic certification claim.

| Reference | Intended Packweir support | Evidence boundary |
|---|---|---|
| [NIST SP 800-218, SSDF v1.1](https://csrc.nist.gov/pubs/sp/800/218/final) | Map repository protection, component verification, build evidence, and vulnerability response to relevant practices | Organizational preparation, secure development, personnel, and response processes need evidence beyond artifact scanning. |
| [SLSA v1.2](https://slsa.dev/spec/v1.2/) | Verify artifact provenance against expected subjects, builders, sources, and trust policy; preserve Build and Source Track assessments separately | Parsing a statement or finding a signature does not establish a SLSA level. Build/source platform properties require supporting evidence. |
| [OpenSSF S2C2F](https://openssf.org/blog/2022/11/16/openssf-expands-supply-chain-integrity-efforts-with-s2c2f/) | Organize dependency consumption controls, inventory, enforcement, monitoring, and improvement | Consumption controls complement producer assurance; they do not establish the producer's development practices. |
| [OpenSSF OSPS Baseline](https://baseline.openssf.org/) and tool-specific findings | Map source/project posture evidence with a pinned baseline version; retain Hipcheck and Scorecard findings independently | Public repository observations cannot verify every organizational or privileged control. A score is not certification. |
| [OWASP SCVS](https://scvs.owasp.org/scvs/using-scvs/) | Cover inventory, SBOM, build environment, package management, component analysis, and pedigree/provenance | The profile must state which controls are automated, externally evidenced, or require review. |
| [SPDX](https://spdx.dev/) and [CycloneDX](https://cyclonedx.org/guides/sbom/) | Exchange SBOM/license/component evidence with declared schema versions and lifecycle context | Schema validity does not establish truth, completeness, or trusted authorship. Current observed inventories use SPDX 2.3 and CycloneDX 1.6. |
| [OpenChain ISO/IEC 5230](https://openchainproject.org/license-compliance) | Support license compliance records, roles, review, and distribution materials | A compliance program includes responsibilities and processes outside the repository manager. |

SLSA's [working draft Dependency Track](https://slsa.dev/spec/draft/dependency-track) is relevant to dependency ingestion evidence. Treat it as a draft: any experimental export must pin a revision and remain separate from stable SLSA conformance claims. Other framework revisions must likewise be deliberately selected rather than silently following a mutable web page.

Further reading: Cassie Crossley's O'Reilly [Software Supply Chain Security](https://www.oreilly.com/library/view/software-supply-chain/9781098133696/) (2024). This document references its public publisher overview and contents for broader lifecycle context. Supplier, procurement, development, build, distribution, and organizational controls extend beyond the gateway.

## License compliance

License compliance needs an evidence and review workflow of its own. Planned requirements are:

- Preserve publisher-declared licenses, detected license text/expressions, and reviewer conclusions separately, with per-file/component digests and scanner versions. Track unknown, conflicting, vendored, generated, modified, and embedded native content explicitly.
- Parse SPDX expressions including `AND`, `OR`, `WITH`, and `LicenseRef` references. Preserve alternatives and exceptions; do not flatten them to a single permissive/restrictive label. Record which alternative was selected and by whom when a decision requires a choice.
- Collect copyright statements, license texts, attribution, NOTICE files, source references, and applicable distribution materials. Record evidence for obligations and unresolved gaps; do not assume a source URL establishes that all required source is available.
- Evaluate policy in a recorded use context, including internal use, redistribution, service deployment, modification, and linking where relevant. Automated detection assists the review; it does not determine every legal obligation.
- Generate reviewable attribution/notice bundles and obligation reports bound to the promoted release and its dependency graph. Link corrections to new report revisions while retaining prior decisions.
- Support authorized reviews and scoped, expiring exceptions with rationale, approver, affected artifacts/releases, and outstanding actions. Mandatory integrity and signature requirements remain separate from exceptionable policy rules.

Packweir currently has no complete license scanning, SPDX-expression evaluation, obligation engine, or compliance review workflow. Its observed file inventories and external-document storage are inputs to that future work.

## Investigation and analysis

MITRE Hipcheck, OpenSSF tools, Microsoft OSSGadget, custom checks, and vulnerability/license scanners provide different observations. Each adapter needs a coverage contract, normalized outcomes, pinned configuration, and qualification fixtures. Tools must not silently substitute for each other.

Assemblyline v4 (ASv4) is a planned external analysis integration. Its selected services should produce attributable findings and extracted-file relationships, not one universal approval score. Ghidra and deobfuscation may run through dedicated helpers or services where available. Preserve transformation chains; sandbox any execution. THOR and DRAKVUF-class execution remain specialized stretch integrations. See the [scanner protocol and Assemblyline design](scanners.md).

Agentic checks should be conditional escalation for bounded questions raised by earlier evidence, with an attributable model/prompt/toolset/trace and explicit cost, time, and data-sharing limits. Uncertainty and unsupported conclusions remain visible. Human review is required where policy demands it; an agent cannot override mandatory integrity or trust checks. Automatic escalation, provider integration, and isolated tool execution are not implemented.

## Repository operations and advanced clients

The target repository layer includes hosted/proxy/group repositories, private namespace routing, scoped permissions, short-lived service credentials, immutable releases, quarantine/release workflows, digest-bound promotion, and audit exports. Promotion must preserve original bytes and bind the evidence/policy used for the decision. UI, SSO/RBAC, repository administration, and review queues follow the evidence foundation.

Advanced-client work needs a documented version matrix and real npm, pip/uv, Cargo, Maven/Gradle, and NuGet tests. Qualify discovery, resolution, hashes, authentication, retries while scans are pending, metadata freshness, yanks/snapshots, signatures/attestations, applicable audit APIs, and sidecars. Unsupported behavior must be documented; forwarding a response is not a compatibility guarantee.

Application impact analysis needs project/build/release identities and client- or CI-supplied resolution/consumption evidence. Preserve disagreements between lockfiles, SBOMs, and observed downloads. Future webhooks and incident workflows should report affected releases and decision changes without claiming complete deployment visibility.

## Delivery and acceptance gates

These gates refine the [milestones](compatibility.md); they do not bring hosted publishing ahead of a qualified proxy.

| Gate | Required validation before claiming the capability |
|---|---|
| Qualified evidence proxy | All five real-client matrices; PostgreSQL recovery/concurrency; S3/container operation; authenticated namespace routing; bounded failure modes; safe retention/garbage collection; explicit mutable-artifact freshness. |
| Provenance trust policy | Valid and invalid cryptographic fixtures, wrong subject/source/builder/issuer, missing trust material, identity aliases, expired/revoked trust where applicable, and evidence/policy changes during verification. |
| SBOM and license evidence | Schema/semantic validation, nested/vendored/binary coverage gaps, contradictory documents, SPDX expressions and exceptions, missing notices/source materials, use-context changes, and reviewer attribution. |
| Deep analysis | Assemblyline integration fixtures described in the scanner document; isolated binary/deobfuscation helpers; partial analysis and transformation attribution; agent prompt-injection and budget/failure scenarios. |
| Governance and response | Scoped approval/exception permissions, digest-preserving promotion, reproducible decision exports, advisory updates, revocation, and impact queries from actual consumption evidence. |
| Hosted and OCI operations | Publish permissions, namespace precedence, immutable-release enforcement, group routing, OCI/ORAS authentication and referrer behavior, independent client conformance, and backup/recovery. |

The next implementation work should establish native provenance trust policy and license evidence models alongside client qualification and namespace controls. Deep-analysis backends can then attach to those evidence contracts. Every advertised capability should name its supported inputs, trust assumptions, failure behavior, and validation evidence.
