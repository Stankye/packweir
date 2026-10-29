# SLSA, OSV, and Hipcheck drivers

These built-in drivers invoke operator-installed tools with constructed arguments, a pinned executable SHA-256, bounded output/time, and explicit input mappings. They run through the same worker, evidence context, and delivery policy as other checks. Qualification uses SLSA Verifier 2.7.1, OSV-Scanner 2.7.0, and Hipcheck 3.15.0. They are experimental integrations with the coverage below.

| Driver | What a passing result establishes | Remaining coverage |
|---|---|---|
| `slsa` | The trusted verifier accepted the artifact provenance, and the printed verified statement matches the artifact digest, exact builder, expected GitHub source, and complete commit SHA-1 | Selected supported GitHub builders and SLSA provenance v0.2/v1 statement shapes; no universal SLSA-level claim, automatic registry discovery, or npm-specific verification command |
| `osv` | All mapped package versions were included in an offline scan, with no reported findings in the pinned database snapshots | Direct mapped versions; no transitive graph, embedded component, reachability, or license-compliance claim |
| `hipcheck` | All explicitly required analyses passed for every mapped source revision, with a passing recommendation and no errored analyses | Source posture according to the configured plugins and policy; no signature, provenance, or artifact-maliciousness guarantee |

## Identity mappings

`GET /api/v1/artifacts/{digest}` now includes `identities`, each with `repository`, `origin`, and `filename`. Copy the exact canonical `repository` and `origin` strings when configuring mappings, including any query/fragment. Every registered alias must have a mapping; an unknown alias, empty identity list, or more than 32 aliases keeps a check inconclusive. Each driver supports up to 1024 configured mappings.

Mappings are operator policy. Package metadata, README text, and unverified attestations cannot choose a trusted source, commit, builder, or package identity. Source URIs currently use canonical `https://github.com/owner/repository` URLs, without `.git`, refs, credentials, or query strings. Source revisions are full lowercase 40-character commits. Package mappings use explicit versions, not ranges/tags. Use canonical ecosystem package names; Maven names are `group:artifact`, and scoped npm names retain their scope.

All paths, digests, mappings, plugin pins, and database validity metadata participate in the configuration fingerprint. A change requires analysis under the new configuration; previously approved evidence cannot silently satisfy it. Changing an input document or adding an artifact alias also invalidates the evidence context. Required checks must be added to the existing `policy.required` list; merely configuring a driver does not make it required.

## Source-bound SLSA verification

Add this to an existing config and replace all example identities, revisions, paths, and pins:

```toml
[scanners.provenance]
program = "/opt/packweir/tools/slsa-verifier"
program_sha256 = "<lowercase-executable-sha256>"
version = "2.7.1"
timeout_seconds = 180

[scanners.provenance.driver]
kind = "slsa"
builder_id = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.0.0"

[[scanners.provenance.driver.sources]]
repository = "npm"
origin = "https://registry.example.test/example/-/example-1.0.0.tgz"
source_uri = "https://github.com/example/project"
source_revision = "<full-lowercase-commit-sha1>"
```

The driver uses `verify-artifact --print-provenance`. After verifier success, Packweir checks the printed statement's subject, builder, and source commit. For v0.2 it checks `invocation.configSource`; for v1 it requires one matching source in `buildDefinition.resolvedDependencies`. Arbitrary materials containing the expected commit cannot substitute for that source. Retain the verified statement and input-document digest with the result. See the [upstream verification interface](https://github.com/slsa-framework/slsa-verifier/blob/v2.7.1/cli/slsa-verifier/verify/verify_artifact.go).

Submit provenance through the existing document endpoint as `kind="attestation"`, `origin="publisher_declared"`. Use `document={"raw_base64":"<base64-of-original-attestation-file-bytes>"}` to preserve original JSON/JSONL bytes. This wrapper must contain only `raw_base64`. It is necessary for the qualified upstream release fixtures: reserializing their outer envelope can prevent transparency-log lookup even though the signed payload is unchanged. Plain JSON documents remain accepted as candidates, with compatibility depending on the verifier/input format. Ingestion itself never asserts trust.

At most eight candidate attestations are tried for each mapped alias within one shared execution budget and combined 1 MiB stdout limit. A successful proof must satisfy every expected alias. Failed/unsupported verifications remain inconclusive; malformed output, pin mismatches, limits, or timeouts cannot approve a required check. The verifier may retrieve authenticated trust material and contact public transparency services. It uses its supported builder/trust model; independently provision its executable and restrict worker egress appropriately. This integration does not yet provide a Packweir-managed offline SLSA trust store.

## Offline OSV package checks

```toml
[scanners.vulnerabilities]
program = "/opt/packweir/tools/osv-scanner"
program_sha256 = "<lowercase-executable-sha256>"
version = "2.7.0"

[scanners.vulnerabilities.driver]
kind = "osv"

[[scanners.vulnerabilities.driver.packages]]
repository = "npm"
origin = "https://registry.example.test/example/-/example-1.0.0.tgz"
ecosystem = "npm"
name = "example"
version = "1.0.0"

[scanners.vulnerabilities.driver.databases.npm]
path = "/srv/packweir/advisories/npm-all.zip"
sha256 = "<lowercase-database-sha256>"
revision = "<snapshot-identifier>"
published_at = "<RFC3339-publication-time>"
expires_at = "<RFC3339-expiration-time>"
```

Supported mapped ecosystems are `npm`, `PyPI`, `crates.io`, `Maven`, and `NuGet`. Each needs a pinned OSV `all.zip` snapshot. Packweir constructs a temporary CycloneDX document from these operator mappings and asks OSV to scan it with `--offline`, `--all-packages`, `--all-vulns`, no dependency resolution, and Go/Rust call analysis disabled. Publisher-provided SBOM completeness cannot silently turn into approval.

For OSV-Scanner 2.7.0, the driver provisions `OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY` and its `osv-scalibr/<ecosystem>/all.zip` layout. This follows the [pinned SCALIBR implementation](https://github.com/google/osv-scalibr/blob/5be78a00e3c2/enricher/vulnmatch/osvlocal/matcher.go); older documentation/tool versions use a different scanner cache location. Database acquisition and authenticity are operator responsibilities; there is no automatic download, refresh, or network lookup in this driver.

Exit `0` passes only with complete matching package coverage and no findings. Exit `1` with findings becomes a policy failure; `128` is unsupported coverage; other operational exits are errors. Missing identities, inconsistent reports/exits, or stale/not-yet-valid snapshots remain inconclusive. Advisory IDs and the full bounded report are retained. See [OSV output and exit semantics](https://google.github.io/osv-scanner/output/).

Snapshot metadata is an operator assertion, not a cryptographic freshness proof. Evidence expires at the earlier of its configured TTL and every used snapshot's `expires_at`. Files are hash-checked and copied into a private analysis directory. Limits are 256 MiB per ZIP, 512 MiB combined, 200,000 entries, 16 MiB per expanded entry, and 1 GiB declared expansion per ZIP; unsafe paths and empty archives are rejected. The external parser still needs appropriate process isolation.

## Hipcheck policies and custom plugins

```toml
[scanners.source_posture]
program = "/opt/packweir/tools/hc"
program_sha256 = "<lowercase-executable-sha256>"
version = "3.15.0"
timeout_seconds = 180

[scanners.source_posture.environment]
PATH = "/usr/bin:/bin:/opt/packweir/plugins"

[scanners.source_posture.driver]
kind = "hipcheck"
policy = "policy"
execution = "execution"
required_analyses = ["example/custom"]

[[scanners.source_posture.driver.sources]]
repository = "npm"
origin = "https://registry.example.test/example/-/example-1.0.0.tgz"
source_uri = "https://github.com/example/project"
source_revision = "<full-lowercase-commit-sha1>"

[scanners.source_posture.driver.plugins."example/custom"]
path = "/opt/packweir/plugins/custom"
sha256 = "<lowercase-plugin-executable-sha256>"

[scanners.source_posture.resources.policy]
path = "/etc/packweir/hipcheck/policy.kdl"
sha256 = "<lowercase-policy-sha256>"

[scanners.source_posture.resources.execution]
path = "/etc/packweir/hipcheck/Exec.kdl"
sha256 = "<lowercase-execution-config-sha256>"

[scanners.source_posture.resources.custom_manifest]
path = "/etc/packweir/hipcheck/custom-plugin.kdl"
sha256 = "<lowercase-manifest-sha256>"
```

Custom SDK plugins use Hipcheck's normal publisher/plugin IDs. A policy can refer to `manifest="./resource-custom_manifest"`, the named snapshot copied beside the policy. Refer to dependency manifests the same way, declare their resources, and pin their binary paths in `driver.plugins`. The manifest entrypoint must identify the corresponding immutable deployed executable; Packweir verifies declared binary pins, but does not statically prove that arbitrary KDL/interpreter commands use exactly those binaries or that the plugin dependency list is complete. Protect the deployment and review these connections. Plugin executables are checked with a 256 MiB size bound and remain at their deployed paths; policy/manifest snapshots use the standard resource limits.

The driver supplies explicit policy, execution config, cache, repository target, full revision, and debug JSON output flags. It preserves individual plugin values, concerns, errors, policies, and recommendations. Report owner/name/commit must match the configured source. Required failing analyses become failures. Missing/errored analyses or an `Investigate` recommendation remain inconclusive for escalation; an empty report or overall score alone cannot pass. The source checkout and plugin services must run in an appropriate isolation boundary. Conditional agent escalation is still future scheduling work. See [Hipcheck commands](https://hipcheck.mitre.org/docs/guide/cli/hc-check/) and [custom plugins](https://hipcheck.mitre.org/docs/guide/making-plugins/creating-a-plugin/).

All built-in drivers construct their own arguments. SLSA and OSV also control their environments. Hipcheck accepts explicitly configured variables for Git/interpreters/services; inherited database credentials are not forwarded. Windows executable discovery receives a controlled `PATHEXT`. Native stderr is bounded and available only in opt-in `packweir::drivers` debug logging; treat debug logs as tool-produced analysis data.

## Qualification

Normal tests use an explicit subprocess double for adversarial reports, mappings, pins, expiry, and failure handling. The PostgreSQL/HTTP test requires all three checks before delivery and verifies that vulnerability evidence expires with its database. Separate real-tool tests verify upstream SLSA release provenance and wrong source/commit rejection, offline vulnerable/fixed versions across all five ecosystems (including scoped npm), and a real Hipcheck plugin run with local pinned manifests/binaries. Their setup and fixture provenance are in [the fixture notes](../tests/fixtures/README.md).

These checks do not qualify all package-manager clients, every SLSA builder or predicate variant, application SBOM completeness, or every third-party custom plugin. The CLI tools are installed by the operator, not bundled into the default container.
