# Actual Ghidra qualification

This optional profile runs the pinned Assemblyline core/UI, official Extract,
real YARA SDK worker, and real Ghidra 12.2/JDK 25 headless SDK worker. It qualifies
bounded static observations and attributed transformations. A completed analysis
does not establish malware safety or semantic equivalence of decompiled code.
The existing `tests/assemblyline/live/run.py` profile remains independent.

Run from the repository root with Docker Compose, Python 3.12+, and stable Rust:

```sh
python3 tests/ghidra/run.py --output target/ghidra-live/local
```

Windows can use `uv --no-config run --offline python` with Docker Desktop Linux
containers and the repository's existing GNU Rust toolchain. `--prepare-only`
renders private configuration without downloading images or starting services.
`--keep-stack` retains only this run's appliance for diagnosis; the gateway and
its PostgreSQL still stop. Otherwise cleanup removes this run's labelled
containers, networks, and volumes. No global prune or other container stop runs.
Ports bind to IPv4 loopback. Analysis workers receive only service API credentials
in their environment and mount no core configuration, datastore, or filestore
secrets. They have no Docker socket and use the internal service API network.
API privileges and disclosure remain the instance operator's responsibility;
the official privileged Extract service is explicitly opted into this profile.

The complete runtime profile has 8960 MiB of container memory limits, plus 256 MiB
for PostgreSQL: 9 GiB total under the explicit 10 GiB qualification budget on a 16 GiB
host. Ghidra gets 4 GiB, 2 CPUs, 256 PIDs and a 1536 MiB Java heap. Compiler/Rust/image
builds precede runtime startup. Actual prototype calibration measured 745308160
bytes peak Ghidra process-group RSS (about 711 MiB). Limits remain conservative;
this observation is specific to the small fixtures. CI has a 55 minute job bound,
40 minute execution bound, disk preflight, and sanitized evidence upload. Disk
preflight is an availability check, not a claim that every hosted runner image
will have enough storage. No preinstalled directories are deleted.

`compiler.lock.json` pins the official Zig 0.15.2 archive, binary hash, source
commit, and a digest-pinned compiler container base. The generator uses the real
C compiler/linker to produce AMD64 ELF64 and PE32+ freestanding files with three
exported/noinline witness functions. It records compiler identity and commands,
parses the output headers/sections independently, and never executes generated
binaries. A per-run nonce appears in static data. Encoded variants contain a
nonexecutable `.pw_xor` section with a little-endian length and bytes XORed with
`5a`; the harmless YARA marker is absent from the original binary and archive.
The decoder's actual p-code contains `INT_XOR`. A repeated same-nonce compiler
smoke produced byte-identical ELF/PE files.

The primary cases are clean and encoded ELF/PE, a clean data wheel, an encoded
data wheel, and a minimal review wheel. Genuine Ghidra reports must contain all
three functions, decompiled C, p-code, and independently recomputable XOR spans.
The encoded cases require the exact YARA finding on the real decoded child,
original YARA score zero, and complete service and local byte coverage. Both
native parents in the wheel must retain their edges and separate immutable
output receipts when their decoded bytes share one CAS digest.

Full Extract stays enabled. Contextual data/source wheels have more than five
nonempty files. The additional minimal wheel intentionally retains Extract's
unacknowledged `EXTRACT.16` launchable-content finding and must be Inconclusive
and withheld. No heuristic is suppressed to make the clean case pass. Official
Extract may also emit file-backed PE sections; calibration checks their bytes
independently against local PE section spans.

Two exact Ghidra 12.2 PE catalog name-format warnings remain in raw reports. The
qualified operator policy explicitly acknowledges only those strings. A prior
conservative context with an empty warning policy must withhold the same clean
PE solely because those warnings are unacknowledged. Errors and unknown warnings
are never acknowledged by this profile.

`client.lock.json` pins the official pip 26.3 wheel. The real native pip client
uses an authenticated loopback simple index with rewritten SHA256 links,
`--isolated`, `--no-deps`, `--only-binary=:all:`, `--require-hashes`,
`--no-compile`, and a new `--target`. Only the trusted pip wheel is imported;
fixture package code and native files never execute. Successful clean installs
must contain the exact compiled native bytes. Encoded and review wheels must
leave the target empty. The short-lived NETRC credential is private and removed.

After restarting only this run's YARA and Ghidra workers, a new local context
must get a new real submission ID, reuse exact old service cache keys and full
record creation times, install the clean wheel again, and retain old receipts
beside new context-bound receipts. UI-synthesized empty Extract records cannot
prove execution freshness and are explicitly excluded from timestamp claims.

Eight additional actual-worker helper probes cover unsupported input, malformed
ELF/PE preflight, a truncated ELF reaching the real importer, a thrown analyzer
exception despite headless exit zero, a real deadline/process-group kill, and
missing native execute permission, and a stock analyzer's message-log-only
failure despite headless exit zero and complete function exports. The permission
faults change only the owned worker's decompiler or exact NoReturn catalog mode
and restore each original mode and hash in `finally`.
The production SDK accepts no fault-mode parameter. A final gateway case stops
the required owned Ghidra service for a never-calibrated native SHA, observes a
genuine unfinished submission, then shortens only its local ledger deadline;
the package remains withheld and receives no derived outputs.

Admin-only analysis-output APIs must return the exact hash-bound bytes with
attachment/nosniff headers. Receipts preserve subject/configuration/input/tool
identity and `approval_effect=none`, plus independent span/XOR validation;
decompiler semantic equivalence remains explicitly false. Ordinary read tokens
cannot fetch those outputs.

`report.json` positively lists shareable artifacts and SHA256 values. Appliance
configuration, credentials, blob storage, pip targets, and stack state are
excluded. `stage_evidence.py` validates all paths, rejects symlinks, verifies
every listed hash and byte bound, scans known appliance credentials, and copies
nothing from the report until validation succeeds. Complete upstream top-level
notices are retained for Assemblyline, YARA, its Python binding, Zig, pip,
Ghidra, and Temurin's core license/assembly exception/additional license info.
Engine distributions are not published as evidence.
