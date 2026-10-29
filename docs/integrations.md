# Security tool integrations

Packweir separates artifact identity, verified signatures/provenance, source posture, vulnerabilities, license evidence, and suspicious behavior. Each integration must preserve its own coverage and version information. Configuring a generic command does not install or qualify the tool behind it.

## Implemented foundation

In addition to the Sigstore driver below, [native SLSA, OSV, and Hipcheck drivers](native-drivers.md) now implement explicit source/package mappings, exact source-revision checks, pinned offline advisory snapshots, plugin-binary pins, and evidence expiry. Their documented coverage is narrower than each upstream tool's full feature set.

The built-in Sigstore driver invokes an operator-installed, SHA-256-pinned Cosign executable. It supports keyless **blob signatures in Sigstore v0.3 bundles**, with an exact certificate identity and OIDC issuer, a pinned local trust root, and a required transparency inclusion proof. Cosign performs the cryptographic verification. Qualification currently covers Cosign 3.1.4; other versions require validation.

The driver constructs arguments itself and accepts no extra arguments or environment variables. It never enables insecure verification flags. A successful result records the artifact, bundle, executable, trust-root, and evidence-bundle digests plus the signer policy. Missing/unsupported bundles, wrong subjects, and unsuccessful verification remain inconclusive. Process failures and pin mismatches become errors in worker evidence. Required checks cannot approve either outcome.

This is signature verification only. It does not establish source identity, expected build workflow, a SLSA level, benign behavior, license compliance, or package-manager-native attestation compatibility. Provenance remains a separate check; the configuration rejects labeling this driver `provenance` or `agent`. See [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/) and the [Cosign verification implementation](https://github.com/sigstore/cosign/blob/v3.1.4/cmd/cosign/cli/verify/verify_blob.go).

Add this configuration to an existing Packweir config, replacing paths, digests, and signer expectations with independently provisioned values:

```toml
[scanners.required_signature]
program = "/opt/packweir/tools/cosign"
program_sha256 = "<lowercase-sha256-of-executable>"
version = "3.1.4"
timeout_seconds = 120

[scanners.required_signature.driver]
kind = "sigstore"
certificate_identity = "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.0.0"
certificate_oidc_issuer = "https://token.actions.githubusercontent.com"
trusted_root = "root"

[scanners.required_signature.resources.root]
path = "/etc/packweir/trust/sigstore-trusted-root.json"
sha256 = "<lowercase-sha256-of-trust-root>"
```

Add `required_signature` to the existing `policy.required` list to enforce it. The default sample policy still requires inventory/archive checks only. Signer expectations currently apply globally to the configured check; repository/namespace-specific trust routing is future work. On Windows, use absolute executable/resource paths, for example TOML literal strings such as `'C:\Packweir\tools\cosign.exe'`.

The administrative document endpoint now accepts `kind="sigstore_bundle"`; submit the bundle JSON unchanged in the `document` field with `origin="publisher_declared"`. Ingestion records an unverified document and invalidates the previous evidence context. A subsequent request/rescan queues analysis. No registry-specific bundle discovery is implemented. The driver tries at most eight candidate documents within one configured execution budget; any one valid signature satisfying the configured signer policy is sufficient. More than eight candidates keep the check inconclusive. Document replacement/pruning is future work.

The first driver deliberately supports message signatures, not DSSE envelopes, legacy bundles, public-key-only verification, or certificate-chain bundle variants. Malformed or unsupported inputs cannot approve delivery. Trust roots are provisioned and updated by the operator; Packweir does not authenticate TUF updates or automatically refresh/revoke trust material. A digest pin detects substitution relative to configuration, not whether a trust root was obtained legitimately. Changing a pin or signer policy changes the configuration fingerprint and invalidates reuse under that configuration.

The local trust-root snapshot and bundle supply verification material without an implicit trust-root refresh. Network containment remains an operator responsibility, as does protecting executable files against replacement between hashing and process launch. The runner is not an OS sandbox. Deploy tools/resources immutably and isolate parsing or execution of untrusted content.

## Custom adapters and pinned resources

Protocol adapters can now declare `program_sha256` and named `resources`. Each resource requires an absolute path and SHA-256 pin. Packweir verifies and copies it into the per-check directory, then marks the snapshot read-only. Limits are 32 resources, 8 MiB per resource, and 32 MiB combined; executable hashing is bounded to 256 MiB. Resource paths and pins participate in the configuration fingerprint. Changes require updating the pins and deployment configuration together; editing a source file alone does not immediately revoke already issued evidence.

When resources are configured, stdin gains a `resources` object mapping each name to `{"path":"<snapshot>","sha256":"<pin>"}`. Requests without resources retain their prior shape. Adapters opting into resources must accept this extension and use the supplied paths. Packweir does not rewrite relative references within a policy file or snapshot undeclared dependency files.

For a Hipcheck wrapper, for example:

```toml
[scanners.source_posture]
program = "/opt/packweir/adapters/hipcheck-adapter"
program_sha256 = "<lowercase-sha256-of-adapter>"
version = "<adapter-and-hipcheck-version>"

[scanners.source_posture.resources.policy]
path = "/etc/packweir/hipcheck/policy.kdl"
sha256 = "<lowercase-sha256-of-policy>"

[scanners.source_posture.resources.plugin_manifest]
path = "/etc/packweir/hipcheck/custom-plugin.manifest"
sha256 = "<lowercase-sha256-of-manifest>"
```

This example configures an optional operator-owned protocol wrapper. A [built-in Hipcheck driver](native-drivers.md#hipcheck-policies-and-custom-plugins) is also available with pinned policy/manifest resources, plugin-binary pins, explicit source revisions, required analysis IDs, and preserved investigation/error results. Executables, plugins, auxiliary configuration, and external tools still need controlled deployment. See [Hipcheck policy files](https://hipcheck.mitre.org/docs/guide/config/policy-file/) and [creating plugins](https://hipcheck.mitre.org/docs/guide/making-plugins/creating-a-plugin/).

## Microsoft OSSGadget coverage

The integration plan covers the suite through independently named checks and helpers. Tool-specific wrappers are not yet bundled. This grouping is Packweir's proposed integration contract, based on the [upstream tool list](https://github.com/microsoft/OSSGadget).

| Tools | Planned evidence or helper role |
|---|---|
| `oss-characteristic`, `oss-detect-cryptography` | Content characteristics and cryptographic implementation observations, linked to inspected file digests. |
| `oss-defog`, `oss-detect-backdoor` | Deobfuscation leads and suspicious-code findings with uncertainty and original/transformed content references. |
| `oss-diff`, `oss-reproducible` | Version comparisons and source/package correspondence evidence, with explicit comparison inputs and coverage. |
| `oss-find-domain-squats`, `oss-find-squats` | Name/domain similarity signals for investigation. |
| `oss-find-source`, `oss-metadata`, `oss-health`, `oss-risk-calculator` | Candidate source mappings, metadata and posture signals with attributable sources and assessment versions. |
| `oss-download` | Acquisition helper only; downloaded/extracted bytes must enter the same digest, origin, inventory, and quarantine controls. |

OSSGadget's upstream README labels the project public preview and warns of backdoor-detection false positives. Qualification must pin the deployed revision and tool-specific semantics. Source mapping is a candidate until independently established. Similarity, health, and reproducibility heuristics must not silently satisfy signature or provenance requirements. Do not run an uncontrolled downloader/extractor inside the database-connected worker.

## Google and related ecosystem tooling

OSV-Scanner and SLSA Verifier have built-in drivers; the other integrations below remain planned. Explicitly configured SLSA/Hipcheck processes may contact public trust/source services. The native OSV driver uses pinned offline snapshots.

| Tool or service | Planned integration and boundaries |
|---|---|
| [OSV-Scanner](https://github.com/google/osv-scanner) | Implemented: offline advisory checks of explicitly mapped package versions across all five initial ecosystems, with database pins/expiry and normalized finding/error exits. Broader artifact/lockfile/application-graph coverage remains future work. |
| [OSV-SCALIBR](https://github.com/google/osv-scalibr) | A Go library for composition analysis, requiring a separately built helper. Preserve extractor/detector versions, discovered files/components, and unsupported coverage. It is not a drop-in executable protocol adapter. |
| [deps.dev / Open Source Insights](https://docs.deps.dev/) | Enrich package/dependency/source metadata through an explicit service adapter. Record query, retrieval time, service response provenance, and ecosystem coverage. Hosted lookups need configured egress and disclosure policy for package coordinates. |
| [SLSA Verifier](https://github.com/slsa-framework/slsa-verifier) | Implemented: selected GitHub artifact-provenance verification with exact builder, expected source and complete commit checks for every artifact alias. Registry discovery, additional builder/statement shapes, and native npm verification remain future work. |
| [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) | Behavioral investigation in an isolated execution environment, with install/runtime traces and bounded network/resource policy. |
| [GUAC](https://github.com/guacsec/guac) | Optional graph exchange for artifact, dependency, vulnerability, and attestation relationships. Retain statement origin and verification status; imported relationships do not confer trust. PostgreSQL remains Packweir's decision/job store. |

Next work should broaden automatic identity/provenance discovery, add individual OSSGadget checks and license evidence, and integrate Assemblyline, binary helpers, and agent escalation with the same attributable evidence. Each integration needs valid, invalid, unsupported, partial, stale, timeout, output-limit, and context-change fixtures before production enforcement.

## Validation

The standard scanner tests compile a small Rust subprocess fixture to exercise argument construction, resource snapshots, digest substitution, bundle selection, shared candidate budgets, output limits, and timeout handling. That fixture does not perform cryptography.

Separate `real_cosign` tests use an actual Cosign executable and public signed upstream release metadata. They check signatures, exact signer/issuer policy, tampered signature/proof/artifact rejection, and PostgreSQL/HTTP gating after bundle ingestion and trust-policy changes. Linux CI downloads a fixed Cosign 3.1.4 release, checks its pinned executable hash, and runs these tests explicitly. See the [fixture provenance and test commands](../tests/fixtures/sigstore/README.md). Native package-client attestation discovery and full SLSA provenance evaluation remain unqualified.
