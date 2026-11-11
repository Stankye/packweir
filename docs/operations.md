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
