# Bounded Ghidra observations

This helper runs the real Ghidra 12.2 headless importer, analyzers, and native
decompiler on Linux AMD64. It exports observations and derived bytes. Completion
means that the requested, bounded static analysis finished with the recorded
coverage; it is not a malware-safety verdict. The input program is never launched,
emulated, imported into Python, installed as a package, or evaluated as a script.

`binary-analysis.schema.json` is the provider-independent contract. The first
profile supports little-endian AMD64 ELF64 and AMD64 PE32+; other inputs produce
an explicit unsupported result. Headers, memory sections, symbols, ASCII strings,
function entries, decompiled C, and high-function p-code come from the actual
imported program. All discovered internal, nonexternal, nonthunk functions count
toward coverage. More than 32 functions, bounded export truncation, analyzer
errors, or any failed decompile keep the result incomplete.
The profile explicitly disables only the `PDB Universal` analyzer: external PDB
debug-symbol retrieval is unrequested and outside this input snapshot. The
selected analysis options appear in the observations and are profile-hash bound.
Reported symbols come from the imported program, rather than fetched PDBs.

## Trusted XOR profiles

An operator can replace `profile.json` before building the image. Its exact bytes
are bound into the producer identity. `xor_regions` specifies at most eight
original-file ranges, each with an integer offset, a positive length of at most
4096 bytes, and a repeating 1..32-byte lowercase hexadecimal key:

```json
"xor_regions": [{"offset": 1024, "length": 64, "key_hex": "1327"}]
```

This deterministic primitive uses those original bytes, records their exact
offset/length/SHA256, and returns the XOR result inline with its own SHA256. Bad
bounds, malformed keys, fractional offsets, overlapping selectors, and more than
eight regions make the analysis incomplete. A different valid key defines a
different transformation; the helper does not infer an operator's intended
plaintext. The independent Rust contract verifies the source span and result
against local input bytes.

`qualification_xor_frame` is a separate fixture feature, enabled by the supplied
profile. It finds the named `.pw_xor` non-executable, initialized Ghidra memory
block, independently maps it to the original file, and reads a little-endian u32
length followed by encoded bytes. This frame supports the harmless end-to-end
qualification; it is not a general automatic unpacker. Set it to `null` for an
operator-only region profile. Explicit regions and discovered frames share the
eight-region, overlap, and output limits.
Equal byte sequences retain separate descriptors for each operation, function,
or source span. Content deduplication does not discard transformation provenance;
the SDK adds one extracted-child edge for each distinct decoded SHA256.

## Acquisition and build

Run from the repository root with Python 3.11 or newer:

```text
uv --no-config run --offline python tools/ghidra-helper/provision.py
docker build --file tools/assemblyline-ghidra/Dockerfile --build-context ghidra_assets=target/ghidra/upstream-assets --tag packweir/assemblyline-ghidra:local .
```

Provisioning downloads only the exact official release assets in
`upstream.lock.json`, verifies their names, sizes, HTTPS release metadata, and
SHA256, and retains acquisition receipts below ignored `target/`. It claims no
detached vendor signature. The build verifies both archives again and installs
their full distributions, including licenses and notices. Archives are BuildKit
named-context mounts and are not copied into image layers.

The pins are [Ghidra 12.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build)
(569,712,708-byte archive), [Temurin JDK 25.0.5+8](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8)
(141,341,188-byte archive), and the immutable Assemblyline SDK base recorded in
the lock. Ghidra 12.2 requires JDK 25; see the official
[getting-started instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md)
and [headless launcher documentation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md).
Ghidra's Apache 2.0 license, notices, and separately licensed components remain
inside `/opt/ghidra`; the JDK's license and legal directory remain inside
`/opt/ghidra-jdk`. This directory does not redistribute their archives in Git.

## Execution and identity

`runtime.analyze(path, expected_sha256)` hashes at most 16 MiB, verifies the
expected SDK subject, copies it read-only into a private temporary workspace, and
runs only the installed headless launcher and trusted Java scripts. Java receives
a small environment whitelist with private HOME/cache/settings/temp paths; SDK
credentials are not inherited. Headless analysis has two CPUs, a 1536 MiB heap,
60 seconds of automatic analysis, five seconds per decompile, and a 120-second
whole-process deadline. The enclosing service has a 150-second timeout. Run its
container with the stack's 4 GiB memory and 256-PID limits and isolated analysis
network. The runtime kills the complete process group on every exit path and
waits up to the profile's additional two-second cleanup bound for asynchronous
descendant death. It records the observed wait and any live members remaining;
remaining members keep the result incomplete. Reaping the launcher alone is not
treated as proof that every descendant has stopped.

Limits are 1 MiB diagnostic files combined while running, 256 KiB total inline
derived bytes, 512 KiB serialized manifest, 256 outputs, and at most eight decoded
children. Exceeding a bound does not establish complete coverage. No remote
supplementary-file fetch is needed for this version.

Producer identity binds the authenticated engine and JDK archive SHA256 values,
actual native decompiler bytes, exact profile, Java scripts, runtime driver, and
SDK bridge. Script and driver hashes use sorted filename records, each encoded
as UTF-8 name, NUL, unsigned eight-byte big-endian byte length, and exact file
bytes. `identity_sha256` hashes compact UTF-8 JSON of all other producer fields
with sorted keys and no whitespace. The deployment qualification separately
binds this identity to the actual immutable container image and current sources.

The pre-analysis script captures actual Ghidra `Msg` errors, including analyzer
exceptions which [Ghidra 12.2 can log while exiting zero](https://github.com/NationalSecurityAgency/ghidra/issues/9647).
It also installs an analysis-ended listener which captures the internal
`MessageLog` and status before Ghidra clears them. Nonempty internal diagnostics
and cancellation fail closed as errors; the warning acknowledgment policy cannot
waive them. Reading that log only from a post-script would miss these messages.
Startup/runtime ERROR/FATAL lines, missing post-script reports, nonzero exits,
deadline expiry, failed native decompiler startup, and actual `DecompileResults`
errors/timeouts all keep the result incomplete. Exit code zero alone is never
completion evidence.

Ghidra 12.2 does not expose a reliable aggregate of internal analyzer return
values. A false return with no log message or exception is not independently
observable here. Completion is limited to the declared exports from discovered
functions and captured diagnostics; it does not prove every internal analyzer
succeeded or every possible function was discovered.

## Real qualification

`smoke.py` runs one compiled fixture through the installed engine and retains raw
bounded diagnostics plus the original manifest. `test_runtime.py` runs inside a
disposable owned container: a real execute-permission failure of the native
decompiler is restored in `finally`, and analysis still runs as the unprivileged
Assemblyline account. It also tests nonframed operator ranges and invalid
profiles. `tools/assemblyline-ghidra/test_service.py` exercises actual SDK tasks,
both ELF64/PE32+ families, C/p-code and XOR outputs, decoded child edges,
unsupported inputs, oversize rejection, a real scheduled analyzer exception
with exit zero, and a two-second qualification deadline that kills the real
process group. Test instrumentation is trusted local code, absent from SDK
submission parameters. These tests do not replace the live Assemblyline
qualification in `tests/ghidra/`.
The tests also cover a real analyzer returning false with only a `MessageLog`
failure, and a stock PE no-return analyzer failing to read its catalog after an
actual read-permission fault; both must remain incomplete despite exit zero.
