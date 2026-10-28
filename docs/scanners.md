# Scanner adapter protocol v1

Scanner adapters are trusted operator-owned executables configured in TOML. Package content never selects an executable, shell string, arguments, or environment. Versions, arguments, resource pins, and configuration participate in the evidence fingerprint. The default driver uses the protocol below; the built-in Sigstore driver constructs a Cosign invocation instead. See [tool integrations](integrations.md) for driver configuration and tool coverage.

An adapter receives one JSON request on stdin:

```json
{
  "protocol_version": 1,
  "subject": "<artifact-sha256>",
  "configuration": "<security-configuration-sha256>",
  "context_revision": 1,
  "filename": "example.whl",
  "artifact_path": "/temporary-directory/artifact",
  "evidence_path": "/temporary-directory/evidence.json",
  "evidence_digest": "<bundle-sha256>"
}
```

The evidence bundle contains observed file inventory/SBOM documents, externally supplied documents, and all registered upstream identities for these bytes. An adapter must distinguish publisher claims, observed content, and client dependency graphs. Artifacts sharing bytes can have different source/identity expectations; provenance adapters must evaluate all supplied identities rather than approve only one alias.

Adapters with configured pinned resources receive an additional `resources` field, mapping names to read-only snapshot paths and SHA-256 digests. The field is omitted when no resources are configured. Adapters opting into this extension must use the supplied snapshots; see [resource configuration](integrations.md#custom-adapters-and-pinned-resources).

Return one JSON object on stdout:

```json
{
  "outcome": "inconclusive",
  "details": {"reason": "source mapping could not be established"},
  "references": []
}
```

Outcomes are `pass`, `fail`, `inconclusive`, `unsupported`, and `error`. A nonzero exit, malformed JSON, timeout, excessive output, or missing required bindings cannot approve a check. Stdout is bounded to 1 MiB and stderr to 64 KiB. The environment is cleared except configured variables and Windows loader variables. Input bytes are read-only. Use absolute executable paths and explicitly configured tool dependencies.

The command runner is **not an OS sandbox**. It does not enforce per-child CPU/memory quotas or contain grandchildren. Run untrusted package execution only through an operator-managed isolated runner, never directly inside the database-connected worker. The built-in inspector never executes package code. Deep binary parsers should also run behind an appropriate isolation boundary.

## Integration obligations

| Integration | Required adapter behavior |
|---|---|
| Hipcheck | Resolve and bind the source revision; preserve individual findings and source-mapping uncertainty. |
| OpenSSF Scorecard | Report repository posture independently of artifact maliciousness; version thresholds and source expectations. |
| OSV / vulnerability scanner | Bind package coordinates/version and advisory data revision; distinguish absent vulnerabilities from unsupported coverage. |
| OSSGadget | Normalize selected tools individually; preserve heuristic confidence instead of treating all observations as deny rules. |
| Syft / SBOM scanner | Preserve observations and coverage; do not label generated inventories as publisher attestations. |
| License scanner / obligation collector | Preserve declared, detected, and reviewed license conclusions separately; bind file-level evidence, notices, exceptions, and unresolved expressions to content digests. Policy decisions also need the intended use/distribution context. |
| Provenance / signature verifier | Verify cryptography and configured identity/build expectations; retain verification material. |
| Ghidra | Analyze selected binaries headlessly; report unsupported formats and partial analysis; link outputs to embedded-file digests. |
| Deobfuscator | Preserve original bytes and record transformation input/output digests. Runtime unpacking requires isolated execution. |
| Assemblyline v4 (ASv4) | Submit only to a configured instance; bind submission/result references and extracted files to original digests; preserve service versions, findings, errors, and incomplete coverage. A platform score alone does not satisfy individual required checks. |
| Agent | Produce a bounded investigation with evidence references, execution trace, and policy-compatible verdict. |

These protocol wrappers are not bundled yet. Sigstore blob signatures have a separate built-in Cosign driver; the other tool-specific integrations remain operator-provided or planned. A command returning a success code is not sufficient: it must translate the actual tool semantics to the protocol outcome. Unavailable required adapters remain pending.

`provenance` and `required_signature` passing results must include `verified_subject` equal to the requested digest and booleans `trusted_identity`, `signature_verified`, and `policy_matched`, all true. These are trusted-adapter reports, not cryptographic proofs checked by the gateway. A verifier must actually perform those checks before reporting them. Merely parsing SLSA JSON must return inconclusive.

## Planned Assemblyline v4 integration

Assemblyline v4 is an external analysis platform with an operator-selected set of services. The first integration can use an operator-owned protocol bridge. A later native asynchronous backend should submit work, persist its correlation state, and collect results without holding a gateway request or a scan lease open for the entire external analysis. This backend and its scheduling changes are not implemented.

The integration must retain the original artifact digest, submission identifier, selected service/configuration revisions, report references, and parent/child file relationships. Normalize service findings independently, preserving partial results, skipped services, errors, and timeouts. A successful submission or low aggregate score is not proof that every required check ran. Results must still match the active evidence context before affecting delivery.

Use a dedicated least-privilege instance credential and explicit upload/classification/retention policy. Uploading private packages, extracted binaries, or deobfuscated content requires an operator-configured destination and data-sharing policy. Packweir must not assume a remote instance includes Ghidra, dynamic execution, or any other optional service. Cache reuse must account for service configuration, signatures/rules revisions, and evidence freshness.

Qualification needs a controlled Assemblyline instance plus fixtures for completed analysis, partial service failure, timeout, duplicate submission, retry/restart recovery, digest mismatch, changed policy during analysis, and extracted-child attribution. See the upstream [ingestion model](https://cybercentrecanada.github.io/assemblyline4_docs/integration/ingestion_method/), [REST API](https://cybercentrecanada.github.io/assemblyline4_docs/integration/rest/), and [authentication guidance](https://cybercentrecanada.github.io/assemblyline4_docs/integration/authentication/).

## Agent escalation

An agent check must be explicitly required or otherwise included in policy and `trust_agent=true` to satisfy a required approval. Passing agent results require nonempty `model`, `prompt_digest`, `toolset_digest`, `evidence_digest`, and `trace_digest` fields. The declared evidence digest must match the supplied bundle. Model identifiers should pin revisions; prompt/toolset changes must update adapter configuration/version.

Agent output cannot override integrity, archive-safety, or required-signature failures. Package text and tool output may contain adversarial instructions. The adapter is responsible for tool allowlists, token/step budgets, provider data-sharing configuration, trace storage, and distinguishing unsupported conclusions from verified observations. No model provider is contacted by Packweir itself.

Automatic conditional escalation scheduling is not implemented: configured scanners currently run sequentially for every safe-to-inspect artifact. A future scheduler will choose deeper analysis from prior findings rather than requiring an agent on every download.
