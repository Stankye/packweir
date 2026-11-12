# Cache freshness and operational visibility

Packweir 0.3.0 adds per-repository freshness checks and administrative database observations. These complement digest, policy, evidence, and readiness checks.

## Retained artifact freshness

An optional repository setting controls the maximum age of a successful, complete upstream artifact validation:

```toml
[repositories.maven]
ecosystem = "maven"
upstream = "https://repo.maven.apache.org/maven2/"
retain = true
cache_max_age_seconds = 900
```

Omitting `cache_max_age_seconds` preserves the existing retained-byte behavior. Values from `0` through `31536000` are supported; zero revalidates on every artifact request. Registry discovery metadata continues to be fetched normally. Revalidation currently downloads complete bounded responses; ETag/Last-Modified conditional revalidation remains future work.

Freshness and analysis validity are independent:

- Before the deadline, retained bytes still undergo stored-digest verification and current policy evaluation.
- At the deadline, or when the timestamp is absent or in the future, the gateway fetches and verifies the entire upstream response.
- Identical bytes keep their current delivery approval and evidence expiry. A successful network request does not renew scanner findings.
- Changed bytes require fresh delivery analysis. Reverting to an earlier digest also invalidates its old approval context.
- Failed fetches, disallowed redirects, or integrity-fragment mismatches cannot extend the timestamp or release stale retained bytes. A configured freshness check depends on upstream availability when due.
- Cached reads and identity updates do not extend network freshness. Timestamp updates are guarded by the registered digest to detect cross-replica mapping changes.

Migration 0003 adds nullable `last_validated_at` metadata. Existing artifacts are stale on the first request with a configured maximum age; original blobs remain unchanged. Changing a freshness setting changes the configuration fingerprint, so gateway and worker configuration must match. With `retain=false`, delivery continues to fetch upstream bytes.

## Administrative status

```sh
packweir status
curl -H "Authorization: Bearer <admin-token>" http://127.0.0.1:8080/api/v1/operations
curl -H "Authorization: Bearer <admin-token>" http://127.0.0.1:8080/metrics
```

Both endpoints require the administrative bearer token; package-read tokens cannot access them. `status` uses the configured `public_url`, reads `PACKWEIR_ADMIN_TOKEN`, and prints JSON. Production access requires the deployment's normal TLS configuration.

One PostgreSQL statement produces a consistent database/time observation covering queue states and expired/exhausted leases, current/time-valid/context-invalidated evidence, recorded artifact/digest sizes, document references, historical decisions, audit events, and conflicting discovery claims.

Observations cover **all recorded configurations**. They do not prove worker liveness, current policy approval, or physical blob presence. Historical decisions remain historical records. Recorded digest bytes deduplicate metadata; they are not disk-usage or billing measurements. JSON explicitly reports these coverage boundaries.

`/metrics` returns Prometheus text with fixed label values for queue states, evidence outcomes/states, document origins, and decision states. Package names, URLs, digests, tokens, and scanner output are excluded from labels. These are snapshot gauges; process counters, histograms, worker heartbeats, and physical-storage telemetry remain future work. Database failure or a five-second snapshot timeout produces a sanitized `503` response.

For large histories, measure the database cost and choose an appropriate scrape interval. Retention/garbage collection and background aggregation remain separate planned work.

## Hosted lifecycle observations

Version 0.5.0 adds `hosted` and `hosted_jobs` to the same consistent snapshot. Hosted state counts distinguish open, sealed, published, revoked, and aborted stages. File-reference counts, distinct recorded file digests, and recorded bytes describe metadata; shared blobs can have several references, and recorded reference bytes are not deduplicated physical storage usage.

Copy counts derive from persisted [promotion lineage](promotion.md). `copies_with_revoked_source` reports a historical relationship to a currently revoked source. It does not assert that a destination is approved, unsafe, or automatically withdrawn. Source and destination publication decisions remain independent.

Hosted job counts match the complete recorded delivery scope and subject to a hosted file. Duplicate references do not multiply a job, and malformed or mismatched scopes are excluded. These counts cover all configurations and do not establish that current workers will lease every recorded job. The fixed state labels never contain repositories, coordinates, actors, digests, or report text.

Workers validate lease ownership and the actual database clock after acquiring both context and job locks before committing evidence. Waiting behind release assessment cannot silently extend an expired lease. Exhausted leases retain the existing retry/failure handling.

Version 0.7.0 counts `skipped` separately from `pass`, `fail`, `inconclusive`, `unsupported`, and `error`. An intentionally skipped investigation is not passing security evidence. Policy and explanation reads retain current findings plus all newest-timestamp records, including expired/future results and ties. A newer expired trigger or investigation cannot revive an older pass. These reads fail closed above 1,024 selected records or 32 MiB; they do not silently truncate results. See [conditional investigations](agent-escalation.md) for generation bindings and scoped scheduling.
