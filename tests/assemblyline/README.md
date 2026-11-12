# Assemblyline upstream wire contract

These examples pin the real Assemblyline v4 REST implementation and ODM, rather
than defining a Packweir-shaped protocol for an imagined server. Source revisions
are recorded in [upstream.lock.json](upstream.lock.json). The reviewed stable UI
and base tags are `v4.7.4.stable11`, from August 24, 2026; the reference Python
client is `v4.10.1`. This pins a compatibility target, not a claim that every
Assemblyline 4 deployment has identical behavior or installed services.

The fixtures were generated with the pinned upstream `Submission`, submission
message, `Result`, `Error`, and `File` models and their actual `as_primitives()`
serialization. The full-response transformation follows the pinned endpoint.
They are **schema compatibility examples, not captures from a running server**.
Service/configuration values are controlled test inputs. They cannot establish
that an operator's service performs a particular check or that a deployment is
qualified. No credentials, private samples, or external instance were used.

The separate [live qualification suite](live/README.md) starts the real pinned
appliance and services and preserves authenticated captures. Its installed UI
reports `4.7.4.11` for the reviewed `4.7.4.stable11` image. Configure the version
actually returned by your instance; the tag spelling is not the wire version.

## Requests, envelopes, and credentials

Use an operator-configured HTTPS destination with `X-USER`, `X-APIKEY`, and
`Accept: application/json`. API keys identify each request directly; session
login and XSRF handling are unnecessary for that mode. Preserve the trailing `/`
on every route. JSON endpoints use JSON content type; the HTTP client must supply
the multipart boundary for file uploads. These conventions are documented in
the official [REST guide](https://cybercentrecanada.github.io/assemblyline4_docs/integration/rest/)
and implemented by the pinned [API authentication and response builder](https://github.com/CybercentreCanada/assemblyline-ui/blob/844ccb3f2d53214c8822a46e782b06bc3ef2581d/assemblyline_ui/api/base.py).

Successful and failed JSON responses have the same outer object:

```json
{"api_response": {}, "api_error_message": "", "api_server_version": "4.7.4.stable11", "api_status_code": 200}
```

Check HTTP status, `api_status_code`, and `api_error_message` before using data.
`api_server_version` is the UI package version; it does not identify service or
rules revisions. It is not a substitute for service result identity checks.

| Operation | Method and path | Actual `api_response` |
| --- | --- | --- |
| Upload exactly one local artifact | `POST /api/v4/submit/` | Submission message object with top-level `sid`, `files`, `params`, and `metadata` |
| Inspect durable submission state | `GET /api/v4/submission/{sid}/` | Stored Submission ODM; `results` and `errors` are key lists |
| Check completion | `GET /api/v4/submission/is_completed/{sid}/` | JSON boolean |
| Collect expanded evidence | `GET /api/v4/submission/full/{sid}/?get_full_tree=true` | Stored Submission ODM with expanded result/error dictionaries and file information |
| Check tree completeness/access filtering | `GET /api/v4/submission/tree/{sid}/?get_full_tree=true` | `{tree, classification, partial, filtered, supplementary}` |
| Discover visible service inventory | `GET /api/v4/service/all/` | Array of service summaries including `name`, `version`, `enabled`, `accepts`, `rejects`, `is_external`, and `privileged` |
| Read effective service config | `GET /api/v4/service/{name}/?version={version}` | Service configuration with operator deltas; requires `administration` role |
| Read version defaults | `GET /api/v4/service/{name}/{version}/` | Stored version defaults, not necessarily effective configuration; requires `administration` role |

The route implementations are the authority: [submit](https://github.com/CybercentreCanada/assemblyline-ui/blob/844ccb3f2d53214c8822a46e782b06bc3ef2581d/assemblyline_ui/api/v4/submit.py),
[submission](https://github.com/CybercentreCanada/assemblyline-ui/blob/844ccb3f2d53214c8822a46e782b06bc3ef2581d/assemblyline_ui/api/v4/submission.py),
and [service](https://github.com/CybercentreCanada/assemblyline-ui/blob/844ccb3f2d53214c8822a46e782b06bc3ef2581d/assemblyline_ui/api/v4/service.py).
Some endpoint docstring examples retain obsolete nesting and array shapes.
Upstream's [submission tests](https://github.com/CybercentreCanada/assemblyline-ui/blob/844ccb3f2d53214c8822a46e782b06bc3ef2581d/test/test_submission.py)
explicitly assert that expanded `results`, `errors`, `file_tree`, and `file_infos`
are dictionaries.

The submit endpoint starts work immediately but completion is collected later.
It avoids the ingest endpoint's sampling behavior; see the official
[ingestion comparison](https://cybercentrecanada.github.io/assemblyline4_docs/integration/ingestion_method/).
An upstream submission state can be `submitted`, `completed`, or `failed`.
`is_completed` only checks equality with `completed`, so polling it alone cannot
distinguish an unfinished submission from a failed one. Use state plus a bounded
deadline. A 404 can also mean inaccessible classification.

## Explicit submission policy

POST multipart parts are `json`, containing a JSON string, and `bin`, containing
the exact local bytes and a filename. A representative JSON part is:

```json
{
  "name": "artifact.bin",
  "submission_profile": "packweir-static",
  "metadata": {
    "packweir_run_id": "00000000-0000-4000-8000-000000000002",
    "packweir_request_digest": "<digest of bound request context>"
  },
  "params": {
    "classification": "<operator-approved classification>",
    "ttl": 7,
    "description": "Packweir artifact analysis",
    "services": {"selected": ["Extract"], "excluded": [], "rescan": [], "resubmit": []},
    "service_spec": {"Extract": {}},
    "ignore_cache": false,
    "deep_scan": false,
    "ignore_recursion_prevention": false,
    "ignore_filtering": false,
    "ignore_size": false,
    "max_extracted": 255,
    "max_supplementary": 64,
    "generate_alert": false,
    "auto_archive": false,
    "delete_after_archive": false,
    "use_archive_alternate_dtl": false
  }
}
```

`submission_profile` is top-level. Without `submission_customize`, a valid named
profile is mandatory and profile restrictions constrain overrides. A key with
that role may omit the profile; server/user defaults still exist. Submit and
view roles are separately required by their routes. Full service configuration
is privileged, so the ordinary runtime credential must not be represented as
attesting all service configuration. These rules and default merging are in
the pinned [submission helper](https://github.com/CybercentreCanada/assemblyline-ui/blob/844ccb3f2d53214c8822a46e782b06bc3ef2581d/assemblyline_ui/helper/submission.py).

Use exact selected service names rather than categories, and validate effective
returned params and service identity. Selecting a service does not prove it ran
or that a file was applicable to it. Reject disabled or unavailable required
services and require operator approval for external or privileged services.
The inventory alone cannot reveal every service's data-sharing behavior; the
operator must qualify the selected services and configuration. `ttl` is days;
server `max_dtl` caps it and can replace zero with its maximum. Explicit positive
retention is preferable to relying on defaults. Classification names are local
to the operator's configuration and must not be hardcoded from these fixtures.

The safe local-upload path never supplies `url`, `sha256` fetch input, or any
external retrieval method. Setting `default_external_sources: []` does **not**
override nonempty user defaults in the pinned helper, because it uses an `or`
fallback. Do not treat that empty list as an external-sharing guarantee.

## Correlation and retry semantics

Persist artifact SHA256, destination identity, selected service/configuration
pins, exact submission params, active evidence context, and a unique correlation
ID before beginning POST. Echoed metadata is at `api_response.metadata` in both
the accepted submission and full result. Submitted file records are objects
`{name, sha256, size}` at `api_response.files`; validate exact single-root identity
and the echoed SID before using results.

The pinned submit API generates the SID server-side and provides no idempotency
key mechanism. A timeout, lost reply, or crash after sending POST can leave a
real submission running. Mark that state ambiguous and retain the correlation;
do not replay POST automatically. Safe GET polling can resume for a persisted
SID. Reconciliation must identify exactly one submission with the same metadata
and subject before attaching it; an operator can resolve ambiguity when that
cannot be proven. Do not interpret every 5xx as proof the upload was rejected.

## Expanded results and independently required observations

The full response retains Submission fields at its top level, including `sid`,
`state`, `classification`, `params`, `metadata`, `files`, and `times`. It replaces
`results` with `{result_key: Result}` and `errors` with `{error_key: Error}`, and
adds `file_tree`, `file_infos`, `missing_result_keys`, `missing_error_keys`, and
`missing_file_keys`. Validate every missing-key list. A completed submission can
still contain errors, missing services, partial results, or filtered data.

Each Result has its own `sha256`, `created`, `partial`, `drop_file`,
`response.service_name`, `response.service_version`, optional
`response.service_tool_version`, execution milestones, extracted/supplementary
file references, and `result.sections`. Heuristics use `heur_id`, `name`, `score`,
and `signature: [{name, frequency, safe}]`. Preserve service-specific heuristic
and signature identifiers; an aggregate score is never proof that required
services succeeded or a universal approval rule. Actual fields are defined in
the pinned [Result model](https://github.com/CybercentreCanada/assemblyline-base/blob/abb23625186247802c1f0376a5c79a567120f78d/assemblyline/odm/models/result.py).

Each Error independently binds a file and service/version, carries a message,
`severity`, and `response.status` of `FAIL_RECOVERABLE` or `FAIL_NONRECOVERABLE`.
Types include `MAX RETRY REACHED`, `MAX DEPTH REACHED`, `MAX FILES REACHED`,
`SERVICE BUSY`, and `SERVICE DOWN`; a timeout is not necessarily represented by a
dedicated timeout type. Do not discard an error because a result or a zero score
also exists. The pinned [Error model](https://github.com/CybercentreCanada/assemblyline-base/blob/abb23625186247802c1f0376a5c79a567120f78d/assemblyline/odm/models/error.py)
contains the exact enum values.

Result cache keys have
`sha256.service.v<version-with-underscores>.c<configuration-token>[.e]`.
The actual [configuration-key function](https://github.com/CybercentreCanada/assemblyline-base/blob/abb23625186247802c1f0376a5c79a567120f78d/assemblyline/common/caching.py)
hashes tool version, effective task service configuration, and selected task
parameters. `ignore_cache` and partial results introduce random salt; exact
prequalified `c`-token matching requires `ignore_cache=false`. `service_spec`
alone is insufficient to reproduce a production token. The token is an opaque
cache identity, not cryptographic service attestation. Require qualified pins
and freshness for each required service/file observation.

Keys ending in `.e` are special. The
[datastore helper](https://github.com/CybercentreCanada/assemblyline-base/blob/abb23625186247802c1f0376a5c79a567120f78d/assemblyline/datastore/helper.py)
reconstructs an empty Result from the key, generating current timestamps and
omitting the original tool version. It leaves underscores in the reconstructed
service version. These synthetic times cannot establish execution freshness;
treat them as inconclusive for a required positive service observation.

## Extracted-child attribution

Build edges from every `Result.response.extracted` reference: the result's file
SHA256 is the parent, the reference SHA256 is the child, and the producing result
key/service/version supplies attribution. Keep `name`, `description`, and
`parent_relation`; a relation can be `EXTRACTED`, `INFORMATION`, `DYNAMIC`,
`MEMDUMP`, or `DOWNLOADED`. These references are paths/names from untrusted
analysis and are never local paths to open or execute.

Tree nodes contain `{name: [...], type, sha256, size, children: {...}, truncated,
score}`. Request the full tree and verify all `truncated` flags. The full endpoint
copies only the tree map and discards the helper's `partial` and `filtered`
flags. Fetch the separate tree endpoint to retain those flags; require both
false. The two reads are not atomic, so disagreement stays incomplete.

Bind every result/error/key/file-info digest to the single submitted root or a
reachable extracted descendant and cross-check extracted edges against the tree.
Missing required service observations on children remain incomplete. Supplementary
files are separately listed evidence and are not analyzed children: the tree
envelope lists supplementary hashes, while full `file_infos` is fetched only for
the flattened analysis tree. Do not require supplementary files to appear there,
and do not equate `file_count` with supplementary count.

## Regenerating examples

Clone the base repository, check out the exact locked commit, and run from the
Packweir checkout (replace the final path with that clone):

```powershell
uv --no-config run --python 3.12 --with arrow==1.4.0 --with pyyaml==6.0.3 --with elastic-apm==6.26.2 --with hauntedhouse==0.1.10 --with python-baseconv==1.2.2 --with chardet==7.7.0 python tests/assemblyline/generate_upstream_fixtures.py C:/path/to/assemblyline-base
```

The generator checks the base commit, constructs and validates upstream ODM
objects, uses upstream cache-key construction, and emits deterministic JSON.
It does not import or call the Packweir normalizer. Cargo compatibility tests can
then consume the committed fixtures. Live qualification separately needs a
controlled instance and real service executions, including partial failure,
timeouts, rejected uploads, unknown POST outcomes, restart recovery, service
configuration changes, and extracted children.
