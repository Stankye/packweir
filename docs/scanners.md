# Scanner adapter protocol v1

Scanner adapters are trusted operator-owned executables configured in TOML. Package content never selects an executable, shell string, arguments, or environment. Versions, arguments, and configuration participate in the evidence fingerprint.

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
| Provenance / signature verifier | Verify cryptography and configured identity/build expectations; retain verification material. |
| Ghidra | Analyze selected binaries headlessly; report unsupported formats and partial analysis; link outputs to embedded-file digests. |
| Deobfuscator | Preserve original bytes and record transformation input/output digests. Runtime unpacking requires isolated execution. |
| Agent | Produce a bounded investigation with evidence references, execution trace, and policy-compatible verdict. |

These tool-specific adapters are not bundled yet. A command returning a success code is not sufficient: it must translate the actual tool semantics to the protocol outcome. Unavailable required adapters remain pending.

`provenance` and `required_signature` passing results must include `verified_subject` equal to the requested digest and booleans `trusted_identity`, `signature_verified`, and `policy_matched`, all true. These are trusted-adapter reports, not cryptographic proofs checked by the gateway. A verifier must actually perform those checks before reporting them. Merely parsing SLSA JSON must return inconclusive.

## Agent escalation

An agent check must be explicitly required or otherwise included in policy and `trust_agent=true` to satisfy a required approval. Passing agent results require nonempty `model`, `prompt_digest`, `toolset_digest`, `evidence_digest`, and `trace_digest` fields. The declared evidence digest must match the supplied bundle. Model identifiers should pin revisions; prompt/toolset changes must update adapter configuration/version.

Agent output cannot override integrity, archive-safety, or required-signature failures. Package text and tool output may contain adversarial instructions. The adapter is responsible for tool allowlists, token/step budgets, provider data-sharing configuration, trace storage, and distinguishing unsupported conclusions from verified observations. No model provider is contacted by Packweir itself.

Automatic conditional escalation scheduling is not implemented: configured scanners currently run sequentially for every safe-to-inspect artifact. A future scheduler will choose deeper analysis from prior findings rather than requiring an agent on every download.
