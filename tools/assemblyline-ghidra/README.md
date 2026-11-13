# PackweirGhidra Assemblyline service

This is a real Assemblyline v4 SDK bridge to the pinned Ghidra headless helper in
[`../ghidra-helper`](../ghidra-helper/README.md). The service is named
`PackweirGhidra`, version `4.7.0.1`, with tool version
`ghidra/12.2.identity/<producer identity SHA256>`.
The build computes this value from the installed resources and writes the SDK's
supported `tool_version` manifest field. The service recomputes and checks it at
startup. The real service client can therefore advertise the correct cache tool
identity before its first task, including after a worker restart. The generated
manifest is outside the driver hash to avoid a self-referential identity.

Its first plain result section is exactly `Packweir binary analysis manifest v1`.
The JSON body carries subject, producer, scoped coverage, diagnostics, and inline
derivation bytes. Unsupported or incomplete analysis calls the actual SDK's
`request.partial()`; actual invocation/protocol failures produce SDK errors.
Neither case establishes successful coverage. A complete result asserts bounded
analysis completeness, not malware safety.

Verified `decoded_bytes` outputs are also passed to the real SDK's
`request.add_extracted`, with SHA256-derived filenames, inherited classification,
the default `EXTRACTED` parent relation, and dynamic recursion disabled. There
are at most eight. Their exact bytes and source-span provenance remain inline in
the manifest. A refused child keeps the result partial. The product independently
checks these derived hashes against the result's extracted edges and remote file
graph, verifies the XOR transform using original local bytes, and stores derived
outputs separately from package/document content.
Multiple derivations yielding identical bytes keep all their manifest descriptors
and share one SDK extracted-child edge. Equal C/p-code/decoded content also keeps
its distinct kinds and provenance.

The optional qualified profile retains official Extract and the existing real
YARA service. Extract handles the parent archive, Ghidra analyzes applicable
native children, and YARA analyzes the decoded text. The helper does not launch
any analyzed native file or package code. Its static profile is built into the
image; users cannot submit arbitrary scripts, command arguments, keys, or file
regions through service parameters.

Build from the repository root using the helper's authenticated named asset
context. `SERVICE_BASE` defaults to the immutable SDK image in
`../ghidra-helper/upstream.lock.json`. The full stack builds before runtime and
pins the resulting image ID. Use the isolated optional stack rather than
publishing this service port. The container budget is 4 GiB, two CPUs, and 256
PIDs; the helper separately enforces its heap, time, file, diagnostic, and output
bounds.

`test_service.py` runs the actual SDK offline against genuine compiled fixtures.
It is mounted only for qualification and is not copied into the service image.
It makes no claim that a dispatcher or server took part; live end-to-end evidence
comes from the separate `tests/ghidra/` qualification.
