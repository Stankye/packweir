# Real Assemblyline qualification

This opt-in suite starts an isolated, actual Assemblyline v4 appliance and sends
harmless bytes through the **real Packweir gateway and worker executable**. It
uses upstream UI, dispatcher, service API, Redis, Elasticsearch, filestore, and
the official Extract image. It does not implement Assemblyline endpoints or
replace the services with a fixture server.

The additional [PackweirYARA service](../../../tools/assemblyline-yara/README.md)
runs the actual pinned YARA engine against a bounded harmless marker rule. Its
always-present execution section preserves the engine/rule identity for clean
files. Its tool identity includes the engine, binding, rule hash, and exact
driver-code hash; the suite checks these against both execution metadata and
the running container's files/native module. This is a qualification check for one harmless rule, not a general
malware-detection claim. Official empty cached results (`.e`) remain insufficient
to establish tool identity or execution freshness.

Upstream source revisions and immutable images are in
[stack.lock.json](stack.lock.json). The service rule, SDK/base image, dependencies,
and expected heuristic identifiers have their own pins under
[tools/assemblyline-yara](../../../tools/assemblyline-yara).

## Run

Requirements are Docker with Compose, Python 3.11+, Rust/Cargo, and enough free
resources for the limits recorded by the stack lock. On this Windows workspace:

```powershell
uv --no-config run --offline python tests/assemblyline/live/run.py
```

The runner adds `target/tools/winlibs/mingw64/bin` to the Windows compiler PATH,
uses `target/cargo-home`, and bounds Cargo to two compiler processes. It builds
the current product executable and ignored capture replay test with `--locked`
and the explicit `stable-x86_64-pc-windows-gnu` Rust toolchain on Windows. The
report records that selection.
An offline `uv` invocation only selects Python; Docker still acquires the exact
upstream images if they are absent locally.

To prepare configuration without downloading images, starting services, or running tests:

```powershell
uv --no-config run --offline python tests/assemblyline/live/run.py --prepare-only
```

A prepared state can be reused with `--state <path-to-stack-state.json>`.
`--skip-build` requires a prior build proof matching both every current source
input and the current executable SHA256. `--keep-stack` retains this suite's
Assemblyline containers for diagnosis; the product gateway and PostgreSQL are
still stopped. Explicit cleanup is:

```powershell
uv --no-config run --offline python tests/assemblyline/live/stack.py down --state <path-to-stack-state.json>
```

Linux uses `python3` with the same arguments. States containing platform-specific
paths must be exported for that platform before reuse.

## Assertions

The fixture HTTP server supplies only local package downloads. No real malware,
private package, URL fetch, or public analysis instance is involved. The three
mandatory cases are:

| Input | Actual service observation | Required product behavior |
| --- | --- | --- |
| Plain benign text | Attributable clean YARA execution; Extract explicitly inapplicable | Pending before evidence, then pass and exact original bytes |
| Harmless marker text | Actual YARA rule match and exact service heuristic/signature | Fail under the explicit deny mapping; bytes withheld |
| ZIP containing marker text and an empty `__init__.py` | Official Extract records the marker child; YARA scans that child | Complete applicable nonempty child coverage, explicit known-empty policy, and mapped failure; original ZIP withheld |

Before those product submissions, separate real calibration submissions discover
the exact service version, tool revision, and upstream result configuration key.
Those values become fixed configuration pins. Effective service configurations,
inventory, and all calibration results are retained; calibration does not grant
approval to a product artifact.
Each run adds a recorded public nonce to the harmless input bytes. Initial
calibration therefore executes those inputs afresh; product submissions then
exercise reuse of the same nonempty, identity-pinned upstream result cache.

Each product case persists a real server SID, restarts the worker without its
credential, and proves that work remains queued without spending retries or
changing the persisted SID. A later new worker process resumes safe polling.
Authenticated server search must find exactly one actual submission for that
durable correlation.

The suite also injects a different known real SID into its own database and
requires the real worker to reject the returned subject/correlation. The
gateway restarts with the empty-file opt-in omitted. The same archive
must remain inconclusive and withheld: an empty member omitted by the upstream
SDK remains visible in Packweir's independent native inventory. Every applicable
remote service must still have complete pinned coverage, with the empty member
as the sole incomplete-coverage reason.

A final case stops only its owned YARA service, captures the real unfinished
submission, proves pending delivery, shortens the local deadline, and requires
a fail-closed terminal result. YARA is restarted in a `finally` block. No new
submissions follow that restart: the [SDK initially advertises a blank tool revision](https://github.com/CybercentreCanada/assemblyline-service-client/blob/0dad0340ec19d23b9dbe599b745f2ef0b4c46f0b/assemblyline_service_client/task_handler.py#L124),
and an existing-result [dispatcher conflict can salt the configuration key](https://github.com/CybercentreCanada/assemblyline-rust/blob/09acf16e049f2b09dd0ddc62d665e329e95550ba/assemblyline-server/src/dispatcher/client.rs#L109).
That salted key correctly fails the earlier exact configuration pin.

The ignored Rust replay test consumes those original authenticated captures and
checks altered subject, service/tool/configuration pins, missing records, missing
results, and partial/filtered trees. Mutations affect copies only and are
explicitly replay checks; no mutated body is called a server capture.

## Evidence and isolation

Every attempt writes `target/assemblyline-live/<unique-run>/report.json`, even
when acquisition, startup, compilation, or a live assertion fails. A failed or
prepared report never claims successful qualification. Live reports bind to the
complete source hash list, product binary SHA256, upstream lock, running image
IDs/digests, CPU/memory limits, service/configuration identities, original sample
hashes, complete server responses, product HTTP captures, database snapshots,
and command logs. Response captures include authentication metadata with secret
header values redacted; known credential values are removed from saved bodies.

Generated `.env`, API key, service configuration, state, and private Docker
inspection files stay under ignored `target/`. They are needed to operate or
diagnose the local stack and must not be included when sharing evidence. Use
the sanitized report's positive `artifacts` allowlist rather than publishing an
entire stack run directory. Appliance state, `.env`, rendered secret config,
private Docker inspections, and the blob-store directory are excluded.

Docker projects and the product database have unique ownership names/labels.
The suite neither prunes Docker nor touches an existing database or unrelated
container. Published listeners bind explicitly to `127.0.0.1`; service workers
use the stack's internal network. The product PostgreSQL has a 256 MiB memory
limit and 0.5 CPU limit. Assemblyline containers have per-service limits, with
the aggregate and bootstrap peak recorded in the lock and verified in the
runtime identity. The entire test is bounded by startup, command, submission,
and worker deadlines. Cleanup targets only resources owned by this run.
