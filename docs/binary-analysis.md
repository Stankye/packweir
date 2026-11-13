# Binary observations and transformation provenance

Packweir 0.11.0 adds a provider-neutral binary-analysis contract, an optional real Ghidra Assemblyline service, and immutable derived-output receipts. These are static observations with explicit coverage. Completing a decompile does not establish malware safety, source equivalence, license compliance, or a SLSA level.

The initial qualified service profile targets little-endian AMD64 ELF64 and AMD64 PE32+. It uses pinned Ghidra 12.2, Temurin JDK 25.0.5+8, trusted Java scripts, and Ghidra's actual native decompiler. Other formats and architectures remain unsupported by this profile. See the [helper and its limits](../tools/ghidra-helper/README.md) and [SDK bridge](../tools/assemblyline-ghidra/README.md). The worker does not launch Ghidra or package code in its database-connected process.

## Policy and execution identity

Extend an operator-qualified [Assemblyline profile](assemblyline.md) with the service and its exact observed identities. Keep a universal scanner and the appropriate extraction services selected: Ghidra alone does not cover archives, text, or every binary format.

```toml
[remote_scanners.behavior.policy.required_services.PackweirGhidra]
version = "4.7.0.1"
tool_version = "ghidra/12.2.identity/<qualified-producer-sha256>"
configuration_key = "<qualified-result-key-c-component>"
applies_to = ["executable/linux/", "executable/windows/"]

[remote_scanners.behavior.binary_analysis]
service = "PackweirGhidra"
identity_sha256 = "<same-qualified-producer-sha256>"
required_capabilities = ["decompile", "pcode", "decode_xor"]
candidate_kinds = ["elf", "pe"]
informational_warnings = []
```

The producer digest binds the engine/JDK archive digests, installed native decompiler, scripts, runtime driver, and exact profile. It is also bound to the pinned Assemblyline tool version. Deployment qualification checks the actual image and source bytes. Reports remain observations from the configured instance, not cryptographic service attestations.

Every locally observed candidate needs its own attributable manifest even when the remote classifier calls it text or unknown. The client requires the exact normalized result key, version/tool/configuration pin, freshness, and original service execution interval. Classification cannot waive these checks. Partial or dropped results remain incomplete; `.e` cache entries cannot establish execution. Result, manifest, upstream, and local scheduling expiry all constrain validity.

The contract rejects duplicate JSON keys, unknown fields, inconsistent counters, substituted input/output bytes, malformed ranges, and changed identities. Requested full decompile/p-code coverage requires distinct per-function outputs covering every discovered internal nonexternal nonthunk function. A missing output, failed function, timeout, unknown warning, or truncated export cannot supply complete coverage. Ghidra 12.2 can exit successfully after an analyzer throws or writes only its internal message log. A pre-analysis listener captures that log before the manager clears it; error events and explicit decompiler completion checks govern the result.

This Ghidra API does not expose every internal analyzer's Boolean return value. An analyzer returning false without any diagnostic remains an upstream observability limit. Coverage describes the requested exports of discovered functions; it cannot certify discovery of every possible function or success of every internal analyzer. The profile explicitly disables unrequested external PDB-symbol analysis; static symbols and exports still come from the input program.

The supplied profile bounds input size, functions, strings, output bytes, logs, process count, heap, and wall time. Larger libraries can produce useful partial observations while remaining inconclusive. Increase a trusted profile's limits only with new resource and failure qualification; its changed digest requires new pins. This version uses bounded inline outputs and does not retrieve arbitrary remote supplementary files.

## Warning acknowledgments

`informational_warnings` is empty by default. An operator can acknowledge exact reviewed warning strings under the pinned producer. Raw warnings and logs remain intact, and evidence records acknowledged and unacknowledged messages. Errors have no acknowledgment mechanism; other incomplete conditions remain effective.

The qualification profile explicitly acknowledges two Ghidra 12.2 diagnostics about leading underscores in its built-in PE no-return-name catalog. The analyzer strips those underscores and still adds the normalized names, as shown in the pinned [analyzer implementation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/NoReturnFunctionAnalyzer.java#L213) and [catalog](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn). They are retained in the report. The conservative profile without acknowledgments holds those PE inputs; unknown or altered diagnostics still hold delivery. Positive Assemblyline heuristics are separate from these warnings and cannot be acknowledged through this field.

## Derived bytes and archive closure

Trusted profiles can request bounded constant-XOR transformations of explicit original-file ranges. Each output records its input SHA256, source offset/length/hash, repeating key, operation/version, output size, and exact bytes/hash. The Rust engine independently recomputes the transform against its own bounded extraction of the package's original or embedded bytes. The bundled named-section frame is a separate harmless qualification convention, not a general unpacker.

Decoded outputs become actual SDK extracted children, so other selected services analyze them. Equal byte content shares CAS storage. Duplicate decoded bytes from one input share one SDK child edge; distinct parent inputs retain their own edges. Source ranges, functions, kinds, and parent inputs retain distinct derivation descriptors.

The engine also inspects independently verified decoded archives using its own bounded parser. All observed nonempty descendants must appear in the remote analysis graph, and native descendants need qualified binary manifests. A remote classifier cannot skip extraction and hide an embedded member. Zero-byte members require the same explicit `allow_empty_files` content exception as original archives. Unsupported, malformed, unsafe, or oversized decoded archives remain incomplete. Global transformation/file/byte limits prevent each decoded stage from resetting its budget.

Source-span verification and exact XOR recomputation are separate from decompiler observations. Receipt metadata records `source_spans_verified`, `xor_recomputed`, and `semantic_equivalence_verified=false`. Decompiled C and p-code do not inherit the original program's identity or approval.

## Storage and administrative access

Migration `0008_analysis_outputs.sql` creates a separate immutable output history. Receipts bind the producing evidence and job, original subject, delivery configuration, context revision, input and producer identities, manifest digest, output digest, and derivation. Bytes use OpenDAL CAS. Digest locks coordinate registration with non-retaining package deletion; an output reference retains its actual bytes.

Evidence and output references commit together under the current context and live worker lease. A context change, expired lease, or failed storage step cannot commit either. A rolled-back CAS write can leave an unreferenced orphan for future garbage collection. Historical receipts remain inspectable after rescans; their context and evidence do not become current again.

| Method | Path | Behavior |
|---|---|---|
| GET | `/api/v1/artifacts/{digest}/analysis-outputs` | Bounded complete metadata history, including producing context and validation |
| GET | `/api/v1/artifacts/{digest}/analysis-outputs/{id}` | Exact hash-verified bytes, as an attachment with `no-store` and `nosniff` |

Both endpoints require the administrative credential. Package-read and repository service credentials cannot retrieve them. Missing, oversized, or corrupt CAS bytes are unavailable. The list rejects more than 1,024 receipts or 8 MiB metadata; pagination and retention/GC policies remain future work.

Outputs are not registered as packages or input documents, do not increment the document context, and do not feed future source bundles. An explicitly configured same-job agent investigation receives ordinary findings, including these untrusted observations, under the existing [agent binding and disclosure model](agent-escalation.md). Importing OCI claims still cannot create local findings or derived-output approvals.

## Qualification

The real engine/SDK smoke suite distinguishes successful execution from malformed/unsupported input, analyzer errors with exit zero, actual deadline kills, missing native decompiler, oversized inputs, and malformed transformation profiles. Rust contract tests separately reject oversized outputs. The full qualification uses freshly compiled harmless ELF/PE bytes, source/data wheels, and a native pip client. It checks decoded-child YARA findings, original-byte delivery, warning review, context/receipt fencing, cache reuse after service restart, and unfinished analysis. See the [reproduction harness](../tests/ghidra/README.md).

These results cover the declared profile and fixtures. Additional processors, production detection rules, automatic unpacking/deobfuscation, larger exports, dynamic execution, and additional storage providers require their own qualification.
