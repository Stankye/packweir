# Package identities, policy scopes, and explanations

Packweir 0.2.0 evaluates each delivery using its repository, canonical upstream URL (including integrity fragment), observed package coordinates, artifact filename, content digest, configuration, and shared document revision. Identical bytes share one blob but do not share approvals across delivery contexts. The decision log preserves the selected scope and effective policy alongside each result.

## Observed identities

The gateway records ecosystem, normalized name, version, namespace where applicable, and a package URL (PURL). These are **registry observations**: `basis="registry_path_observed"` for supported download routes, or `basis="registry_metadata_observed"` when bound to npm/PyPI discovery. They do not authenticate the publisher, establish source identity, verify a package's embedded manifest, prove provenance, or prevent dependency confusion. Trusted source and signer expectations remain separately provisioned scanner policy.

| Ecosystem | Recognized input | Normalization / limits |
|---|---|---|
| npm | Conventional `[scope/]name/-/name-version.tgz` URLs; package/version discovery binds rewritten tarballs to the requested package | Lowercase names; npm `@scope` is the namespace. Discovery-bound identities support tarballs hosted under another filename/namespace. |
| PyPI | Wheel filenames and conventional `.tar.gz` source distribution filenames | Names follow [PyPA name normalization](https://packaging.python.org/en/latest/specifications/name-normalization/). Wheel name/version fields follow the [wheel filename structure](https://packaging.python.org/en/latest/specifications/binary-distribution-format/). Unsupported or ambiguous layouts remain unidentified. |
| Cargo | Gateway `_cargo/{crate}/{version}/download` route | Coordinates come from the checksum-bound sparse-registry download flow. Arbitrary direct download URLs remain unidentified. |
| Maven / Gradle | Canonical group/artifact/version paths under the configured repository root | Name is `group:artifact`; group is the namespace. Timestamped snapshot filenames and custom layouts may remain unidentified. |
| NuGet | Conventional flat-container `id/version/id.version.nupkg` paths | Package IDs are lowercase; custom download layouts may remain unidentified. |

PURLs identify the observed package/version. Maven classifiers, artifact types, and repository qualifiers are not included in the generated PURL; the delivery URL, filename, and SHA-256 distinguish the actual file. PURL equality alone cannot authorize delivery or establish that bytes from different repositories are interchangeable. See the [PURL specification](https://github.com/package-url/purl-spec).

## Additive policy selection

The effective policy combines the global baseline, optional repository additions, and **all** matching scope additions. Check lists are unions; declaration order does not provide overrides. A narrower scope cannot remove global requirements or waive hard failures. `trust_agent` remains a global opt-in; scoped policies cannot turn it on.

Add these sections to an existing configuration as needed:

```toml
[repositories.npm.policy]
revision = "npm-consumption-v1"
required = ["vulnerabilities"]
deny_on_failure = []

[[policy_scopes]]
name = "acme-publisher"
repository = "npm"
namespace = "@acme"
[policy_scopes.policy]
revision = "acme-signature-v1"
required = ["acme_signature"]

[[policy_scopes]]
name = "internal-java"
repository = "maven"
namespace = "com.acme"
[policy_scopes.policy]
revision = "java-source-v1"
required = ["provenance"]

[[policy_scopes]]
name = "sensitive-python-package"
repository = "pypi"
package = "example-package"
[policy_scopes.policy]
revision = "python-review-v1"
required = ["source_posture"]
```

These examples add requirements; they do not install/configure scanners. Configure each required check through the [integration catalog](integrations.md) and [native drivers](native-drivers.md). For example, a Sigstore driver named `acme_signature` can carry a specific signer/issuer expectation while the `acme-publisher` scope requires that check. Unavailable checks remain pending and are identified as unavailable in explanations.

Each rule selects exactly one namespace or package name in an existing repository. npm namespaces match exactly: `@acme` does not match `@acme-evil`. Maven group prefixes include descendants at a dot boundary: `com.acme` matches `com.acme.tools`, not `com.acmeevil`. PyPI, Cargo, and NuGet use package selectors rather than invented namespace conventions. Cargo selectors conservatively equate `-`/`_` spellings to prevent alias-based policy bypass, following the collision restrictions described in the [Cargo registry guidance](https://doc.rust-lang.org/cargo/reference/registry-index.html#name-restrictions); custom registries that distinguish those names receive the union of those requirements. Selectors must already be canonical; invalid, duplicate-named, unsupported, or unknown-repository rules are rejected at configuration validation.

If a repository has any identity-based rules, every artifact in it additionally requires the built-in `package_identity` check. For npm and PyPI this requires the native discovery observation: fetch the npm packument or PyPI project index through the gateway before prefetching the artifact. Filename guesses alone cannot satisfy these scoped policies. Discovery claims are tied to the exact rewritten artifact URL, including its integrity fragment. npm uses the requested package name and version entry, so a stricter namespace cannot be skipped by hosting its tarball under another name. Mismatched npm manifest names/versions are rejected; incompatible PyPI distribution claims or multiple different coordinates for one URL remain unidentified and pending. Conflicting claims are retained conservatively; automatic claim reconciliation/removal is future work.

An unidentified package stays pending because applicable scoped requirements cannot be selected safely. Repositories without identity-based rules may continue using repository/global policy on opaque artifact URLs; explanations still show missing coordinates. These observations do not establish the consuming application's aliases or full dependency graph. Do not infer trusted source or signer expectations from an observed name or unverified package text.

## Explain a decision

Stage the package through a client or `packweir prefetch`, then use its SHA-256 digest:

```sh
packweir explain '<sha256>'
packweir explain '<sha256>' --repository npm
packweir explain '<sha256>' --repository npm --origin '<exact-canonical-upstream-url>'
packweir explain '<sha256>' --repository npm --json
```

Use `--config /path/to/config.toml` for another configuration. `PACKWEIR_ADMIN_TOKEN` is required; package-read credentials cannot inspect decisions. `--origin` requires `--repository`, and preserves URL queries/fragments through query encoding. Copy the exact origin from the inspection response when selecting a native download containing an integrity fragment.

The human report lists package PURL, repository/origin, effective policy layers, delivery configuration fingerprint, decision, job state/attempt count, and each check's required status, evidence age, expiration, tool version, reason, and next action. JSON additionally preserves the selected evidence and provider (`builtin`, `configured_adapter`, or `unavailable`). Missing, expired, future-dated, failed, unsupported, errored, and inconclusive evidence remain distinguishable. Missing evidence also covers findings invalidated by a shared document revision or rescan.

The CLI uses the existing read-only inspection API:

```text
GET /api/v1/artifacts/{digest}?repository=npm&origin=...
```

The response includes `scopes`, each with its own `scope`, `configuration`, `policy`, `decision`, `job`, and `checks`. The top-level decision aggregates the selected contexts conservatively: any denial makes it denied, otherwise any pending context makes it pending. An individual download uses only its own context's decision. Top-level `configuration` is populated for one selected context and is `null` for multiple contexts; `engine_configuration` identifies the shared deployment configuration. Existing `identities`, `documents`, and current `evidence` fields remain available. Unknown digests and unmatched filters return `404`; malformed digests and origin-without-repository filters return `400`.

`explain` does not download packages, enqueue scans, or change approvals. Its successful exit status means the report was retrieved, including when the policy decision is denied/pending; automation must inspect the JSON decision. Policy approval does not assert that retained bytes or an upstream are currently available.

## Worker and upgrade behavior

Workers lease delivery jobs using the deployment fingerprint and verify the job's scope/configuration against the current artifact record before analysis. Scanner bundles contain only that delivery's identity, so another alias cannot supply a missing source/package mapping or contaminate its approval. Direct scanner-protocol callers supplying multiple identities still need complete mapping coverage for their entire supplied bundle.

External documents remain digest-linked and shared: each verifier independently checks them against its delivery's trust expectations. A newly registered alias gets its own approval without invalidating unrelated alias approvals. Changing an existing mapping/filename/identity, ingesting an external document, or requesting a digest rescan invalidates relevant findings through the shared revision. A digest rescan queues all currently configured delivery contexts. Completed decisions and older evidence are retained; automatic garbage collection remains future work.

The additive SQL migration preserves existing artifacts and adds observed identities, discovery claims, and scoped-job metadata. Existing rows acquire coordinates on the next package fetch/cache request. Upgrade gateways and workers together. The engine version changes to 0.2.0, so 0.1.1 approvals cannot satisfy the new fingerprints; packages need fresh analysis. Changing a repository's ecosystem in place is unsupported once discovery claims exist; use a new repository name. Mismatched stored coordinates are rejected. Inspection/rescan currently supports up to 256 aliases per digest; each discovery response permits at most 10,000 claims. Pagination, claim reconciliation, and finer document scoping remain future work.
