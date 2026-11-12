# OCI evidence exchange

Packweir 0.8.0 exports local security snapshots and archives foreign snapshots as standalone OCI artifacts. OpenDAL remains the internal filesystem/S3 content store. The CLI reads and writes local OCI layouts; an operator can use ORAS to transport them. Packweir does not yet serve OCI Distribution endpoints, tags, referrers, or registry authentication.

Imported claims never approve a package. Digest integrity establishes which bytes were transferred; it does not authenticate the exporter or verify its findings, signatures, provenance, policy, or document origins. Every import receipt states `verified: false`, `trust_status: "unverified"`, and `approval_effect: "none"`.

## CLI workflow

Use the administrative token for online operations. Package-read and hosted service credentials cannot export, import, or inspect these archives. Exported snapshots can contain private repository URLs, source documents, and scanner findings; choose their destination accordingly.

```sh
export PACKWEIR_ADMIN_TOKEN='<administrative token>'
packweir evidence export '<package-sha256>' --layout ./assessment
```

The output includes the immutable `manifest_digest`. The destination must be a new directory with an existing parent. Packweir stages and validates a complete layout before an atomic rename; it refuses to replace an existing file or directory. This write operation currently supports Windows and Linux.

Local validation needs no configuration, token, database, gateway, or network:

```sh
packweir evidence validate --layout ./assessment --manifest 'sha256:<manifest-sha256>'
```

The caller must explicitly select a manifest digest; a mutable tag is never accepted as the import identity. An export also records a convenience `packweir` tag in `index.json`. For example, [ORAS supports copying between layouts and registries](https://oras.land/docs/commands/oras_cp/):

```sh
oras cp --from-oci-layout --to-oci-layout \
  './assessment@sha256:<manifest-sha256>' ./copied:review

# Optional operator-managed upload to an external registry:
oras cp --from-oci-layout \
  './assessment@sha256:<manifest-sha256>' registry.example/team/evidence:review

# Retrieve and select the independently recorded immutable digest:
oras cp --to-oci-layout \
  'registry.example/team/evidence@sha256:<manifest-sha256>' ./received:review
```

Registry credentials and upload authorization remain the operator's responsibility. Packweir itself does not invoke ORAS, follow descriptor URLs, or download missing layout blobs.

The target package must already be registered in the receiving gateway:

```sh
packweir evidence import '<package-sha256>' \
  --layout ./received --manifest 'sha256:<manifest-sha256>'
packweir evidence imports '<package-sha256>'

# Reexport the exact original manifest, envelope, and document bytes:
packweir evidence export '<package-sha256>' \
  --import-id '<receipt-uuid>' --layout ./archived-copy
```

Repeated imports of the same package and manifest return the same receipt. Reexporting an import preserves its original source claims; exporting a fresh local snapshot excludes foreign imports. CLI administrative requests have a response bound and timeout, and do not follow redirects.

## Format and captured claims

The profile uses the [OCI image layout](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md) and [image manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md) specifications, with:

- Artifact type `application/vnd.packweir.evidence.v1`.
- An empty `{}` config with media type `application/vnd.oci.empty.v1+json`.
- A first layer of type `application/vnd.packweir.evidence-envelope.v1+json`, containing `schema_version: 1`, `subject`, `source`, `snapshot`, and `documents`.
- Subsequent `application/json` layers with their original document bytes. Envelope descriptors bind their SHA-256 digests, sizes, and media types; source document references retain kinds and origins inside the snapshot.

The envelope's `subject` is the raw lowercase SHA-256 of the package. It is deliberately separate from the OCI manifest's `subject` relationship: the package digest identifies package bytes, whereas OCI subject descriptors refer to manifests. This standalone format rejects an OCI manifest `subject` field.

A local export captures a repeatable-read database snapshot: the database clock, current evidence-context revision, engine configuration, artifact scopes, configured repository/policy explanations, current-context evidence across configurations, document references, latest recorded decisions, and jobs without lease tokens. Removed repository scopes remain visible with an explicit explanation omission. The envelope lists its omissions, including original package bytes, prior evidence contexts, full decision history, and foreign imports.

After the metadata snapshot, each document's raw CAS bytes are read with a byte limit and SHA-256 verification. JSON whitespace and ordering remain unchanged. Multiple metadata references may point to one content layer. A corrupt, missing, unsupported, or oversized document makes export fail; the response does not silently become a partial assessment. An export describes a historical snapshot, not a durable promise of current delivery approval.

## Import isolation and storage

Imports use separate `external_imports` and `external_import_blobs` tables with immutable content references and an audit event. They do not insert local evidence, decisions, documents, package identities, or jobs; they do not change the local evidence-context revision. Even a foreign `pass`, `approved` decision, current-looking configuration, or claimed `artifact_observed` origin has no local authority. Imports are not automatically supplied to scanners or agents. Explicit materialization and independent verification would be separate future features.

Imported manifests, envelopes, configs, and document layers are retained through actual CAS references. Merely naming a package subject does not retain that package's original bytes. A database advisory lock coordinates import registration with `retain=false` deletion, including when a document and a package happen to share a content digest. A failed import can leave unreferenced CAS writes; automatic orphan garbage collection and import deletion are not implemented.

Migration `0006_external_evidence.sql` adds the import archive and reference tables. Version 0.8.0 also changes the engine version in delivery fingerprints, so existing approvals require fresh analysis. Upgrade gateways and workers together.

## Limits and qualification

This is a bounded evidence profile, not a general OCI image reader. It supports SHA-256 only, at most 256 JSON document layers, 8 MiB per document, 32 MiB combined documents, and 1 MiB each for index, manifest, and envelope. HTTP transfers are limited to 48 MiB with a 60-second handler timeout. Oversized complete sets are rejected rather than truncated; the receipt listing currently rejects more than 1,024 imports for one subject. There is no pagination yet.

Validation rejects digest/size mismatches, duplicate JSON keys and layer descriptors, unreferenced transfer blobs, compressed layers, nested indexes, unsupported media types, descriptor URLs, traversal, and symbolic links/reparse points in consumed paths. Annotations never select filesystem paths. Filesystem owners must not concurrently replace ancestor directories during layout access.

```sh
# PostgreSQL-backed HTTP isolation and retention checks:
cargo test --locked --test exchange_http
cargo test --locked --test oci --test evidence_cli

# Authenticates the pinned upstream executable, builds the actual CLI,
# then runs real ORAS interoperability with networking disabled:
python3 tests/oras/run.py
```

The [ORAS qualification harness](../tests/oras/README.md) uses pinned ORAS 1.3.6, upstream checksum/signing-identity verification, and source/image/executable records. It exercises manifest/blob fetches, layout copy preserving the root digest, an independently ORAS-authored artifact, configless CLI validation, and tamper rejection. HTTP tests independently establish that forged approvals cannot change local decisions. Registry pushes, registry authentication, cryptographic trust in imported reports, referrer graphs, and OCI package serving remain unqualified.
