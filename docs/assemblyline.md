# Assemblyline v4 remote analysis

Packweir 0.9.0 adds an experimental native Assemblyline v4 client with durable submission correlation and deferred polling. Assemblyline is an operator-managed analysis platform; the installed services determine what it can analyze. This integration does not install Assemblyline, Ghidra, a deobfuscator, or a VM sandbox.

The worker uploads the original package to one explicitly configured instance. A passing check requires complete, fresh results for every pinned service on the original file and every extracted descendant. A low platform score, successful upload, completed submission, or missing finding alone cannot pass a check.

The implementation is tested against controlled HTTP responses shaped by pinned upstream ODMs, plus database and actual worker-CLI tests. It has not been qualified against a live Assemblyline deployment. The [wire-contract fixtures and source pins](../tests/assemblyline/README.md) identify the reviewed upstream versions and distinguish generated compatibility examples from captured execution.

## Configuration

Remote checks have their own configuration map; they do not need a local executable. Give the check a unique ordinary analysis name. Remote services cannot impersonate `agent`, `provenance`, `required_signature`, or built-in integrity/inventory checks.

```toml
[policy]
revision = "assemblyline-qualified-profile-v1"
required = ["inventory", "archive_safety", "behavior"]

[remote_scanners.behavior]
kind = "assemblyline"
endpoint = "https://assemblyline.internal/"
server_version = "4.7.4.stable11"
user_env = "PACKWEIR_AL_USER"
api_key_env = "PACKWEIR_AL_KEY"
allow_upload = true
allow_private_network = true
classification = "<classification valid on your instance>"
retention_days = 7
profile_revision = "<your qualified profile revision>"
submission_profile = "<your configured submission profile>"
request_timeout_seconds = 30
analysis_timeout_seconds = 3600
poll_interval_seconds = 15
max_poll_failures = 3

[remote_scanners.behavior.service_spec.YARA]
# Exact service-specific options qualified on this instance.

[remote_scanners.behavior.policy]
max_result_age_seconds = 86400

[remote_scanners.behavior.policy.required_services.YARA]
version = "<exact service version>"
tool_version = "<exact engine/rules revision>"
configuration_key = "<exact result-key c component, without the leading c>"
```

Replace the placeholders using a qualified submission on your own instance. `tool_version` omitted means the upstream tool version must be null; it is not a wildcard. The result's `c` component binds Assemblyline's effective service configuration, relevant task parameters, and tool version. Do not calculate it from `service_spec` alone. It is an identity check against the trusted instance's report, not a cryptographic service attestation.

Use exact service names and a dedicated credential with the required submission-create and submission-view roles. A configured profile is mandatory without submission-customize permission. Profile/user/server defaults can constrain or expand processing, so qualify them before authorizing uploads. The client checks accepted parameters, original digest, selected services, server version, and echoed correlation, then checks them again when polling.

`allow_upload=true` explicitly authorizes disclosure of package bytes to that destination. Classification is instance-specific; TTL is a positive number of days, bounded to 30 and accepted only when the server's effective value is no greater. The credential values are read from the worker's environment and are not serialized into configuration, evidence, or diagnostics.

HTTPS certificate verification stays enabled. A private network requires `allow_private_network=true`; development HTTP additionally requires `allow_insecure_http=true`. An optional `[remote_scanners.behavior.ca_certificate]` accepts a pinned `path` and `sha256` for a private PEM trust root. Requests use validated DNS addresses, ignore ambient proxies, and never follow redirects. The endpoint must be an origin URL without credentials, path prefixes, queries, or fragments.

Before upload, visible service inventory must show each exact version enabled. External and privileged services require separate `allow_external_services=true` or `allow_privileged_services=true`. Inventory flags do not describe every service's possible network or disclosure behavior; the operator remains responsible for the instance, profile, and service configuration. The client does not request URL/hash-based retrieval or fetch extracted files.

## Findings and coverage

The normalizer retains raw report/tree data, per-service identities and heuristics, extracted parent/child digests, error attribution, coverage reasons, and absolute result validity. Reports include the instance, pinned server version, local correlation, request/profile/evidence digests, and canonical submission report references.

An explicitly configured deny rule can convert an attributed heuristic into `fail`:

```toml
[[remote_scanners.behavior.policy.deny_rules]]
service = "YARA"
heuristic_id = "<exact heuristic ID>"
signature = "<optional exact signature name>"
```

Other heuristic findings require investigation. Errors, partial/filtered/truncated trees, missing files/results, dropped files, absent service coverage, unknown state, stale/future evidence, and unqualified versions remain inconclusive or errors. Explicit deny rules do not turn incomplete coverage into a passing assessment. The platform score remains a separate observation.

This first profile conservatively requires every selected service on every original/extracted file. Choose services that cover those types; specialized Ghidra-only pipelines can remain pending on unsupported archive/text nodes. Synthetic `.e` empty-cache results lack enough original execution attribution and are inconclusive. They are not silently treated as clean runs. Qualify the instance's cache behavior and result retention against `max_result_age_seconds`; stale cached results cannot acquire a new TTL merely by being returned again.

Raw report plus tree is limited to 1 MiB, 256 distinct files including the original, and 1,024 service results. Uploads request at most 255 extracted files and 64 supplementary files. Supplementary references remain observations; their bytes are not downloaded or executed. Scanner input documents are a complete set of at most 256 references and 8 MiB combined raw bytes. Oversized sets fail rather than being silently truncated.

## Durable scheduling and recovery

Migration `0007_remote_analysis.sql` adds an immutable-binding ledger, result generations, a delayed queue timestamp, and ordinary-analysis checkpoints. The worker saves local findings before beginning remote work. A successful scheduling step releases its lease, sets the next poll time, and does not consume a worker-failure retry. Later workers reuse the same submission ID and unexpired local findings. Expired local findings are rerun before final evaluation.

The original evidence bundle stays fixed within that job's context, including the original SBOM document IDs and creation fields. Refreshing ordinary findings does not manufacture a different request digest or accumulate regenerated SBOMs. A new document context clears the checkpoint and establishes new inputs.

The ledger persists submission intent before POST. Assemblyline generates the SID and does not provide a client idempotency key. A lost response or interruption after intent is ambiguous; the worker never blindly repeats that upload. Known SIDs resume safe GET polling. Context changes, changed request/profile bindings, and replaced/expired leases prevent stale mutation or evidence completion; clocks are checked after lock waits.

```sh
packweir remote list '<package-sha256>'
packweir remote inspect '<package-sha256>' '<correlation-uuid>'
```

These administrative commands require `PACKWEIR_ADMIN_TOKEN`. Find an ambiguous submission in the configured instance using the recorded `packweir_run_id` and `packweir_request_digest` metadata. After independently identifying its SID:

```sh
packweir remote reconcile '<package-sha256>' '<correlation-uuid>' \
  --submission '<recovered-submission-id>'
```

Reconciliation only queues a current, non-running ambiguous request under the same configuration and deadline. It does not approve an artifact. The next worker still verifies the SID, package digest, original correlation, effective parameters, tree, and service results. An arbitrary SID cannot provide a shortcut to approval. Expired, failed, or mismatched requests require a deliberate rescan and new context.

Completed passing/failing results keep their absolute validity; expiry can create a fresh generation with a new correlation while preserving the old receipt. Inconclusive, failed, and ambiguous records require review/rescan rather than an upload loop. Final local evidence commits atomically after all configured analyses finish, followed by any applicable [agent investigation](agent-escalation.md). Imported OCI claims never enter this flow.

Version 0.9.0 changes delivery fingerprints. Upgrade workers and gateways together and obtain fresh analysis for prior approvals.

## Administrative API and tests

All endpoints require the administrative bearer credential. Read/publish/promote service credentials cannot access them; responses omit submission/lease tokens.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/artifacts/{digest}/remote-analysis` | Bounded ledger summaries, including historical contexts/generations |
| GET | `/api/v1/artifacts/{digest}/remote-analysis/{id}` | One stored record and its normalized output |
| POST | `/api/v1/artifacts/{digest}/remote-analysis/{id}/reconcile` | Attach recovered SID using `{"submission_id":"..."}` and queue verification |

The summary endpoint rejects more than 256 records; pagination and automated remote submission search are future work. OCI exports include current-context ledger summaries; operational tokens, temporary checkpoints, and duplicate ledger output bodies are omitted. Committed Assemblyline findings remain ordinary local evidence.

```sh
cargo test --locked --test assemblyline --test remote_config
DATABASE_URL=postgres://... cargo test --locked --test remote_analysis --test assemblyline_http
```

Tests cover actual upstream schema examples, pinned identities, result/cache freshness, extracted children, malformed/partial/error cases, strict configuration, concurrent submission permits, retry/restart correlation, ambiguous recovery, queue deferral, checkpoint reuse, context/lease changes, and real worker-CLI HTTP behavior. A real deployment still needs service-specific benign/malicious/unsupported fixtures, instance authentication/profile/cache checks, and operational resource/isolation qualification.
