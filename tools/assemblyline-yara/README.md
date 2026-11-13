This service uses the real Assemblyline v4 SDK and VirusTotal's native YARA
engine through the official `yara-python` 4.5.4 package. It scans a bounded byte
snapshot and emits the actual matching rule identifiers. The bundled rule
recognizes only a harmless integration marker. A no-match result establishes
completion for that rule resource; it does not establish malware detection
coverage or certify a package as safe.

Every successful scan emits a plain execution section containing the input and
rules SHA256, engine and binding versions, size, and actual matching rule names.
Tool identity and execution metadata also bind the driver source. Its SHA256 is
computed over `__init__.py`, then `service.py`: each UTF-8 filename is followed by
a NUL byte, an unsigned 8-byte big-endian content length, and the exact file
bytes. A wrapper source change therefore changes the actual upstream cache
configuration key even when the manifest version is unchanged. Qualification
compares this reported digest with the runtime image and current source bytes;
it is an integrity observation, not cryptographic service attestation.
The image build computes this identity from its installed native engine and
exact runtime files and writes the SDK's supported `tool_version` field into
the image manifest. The constructor recomputes and checks that value before
accepting tasks. The generated manifest is excluded from the framed driver
hash to avoid a self-reference. The raw service client can therefore send the
correct tool identity on its first task request after a restart, rather than
learning it from the first uploaded result. The source manifest intentionally
has no generated identity; registration must use the manifest extracted from
the built image. This uses the upstream client lifecycle without an SDK patch.
The SDK supplies execution milestones. This nonempty result survives the real
Assemblyline datastore without the synthetic timestamps and lost tool revision
of `.e` empty cached results. Exceptions, size overflow, and YARA timeout produce
service errors rather than successful no-match evidence.

Build with a digest-pinned Assemblyline service base, qualified with the pinned
SDK source `f30da537e3adbee7c5c46e694a1ee15c4dc1cb87` (`v4.7.4.stable11`):

```sh
docker build --build-arg SERVICE_BASE=cccs/assemblyline-v4-service-base@sha256:<qualified-image-digest> -t packweir/assemblyline-yara:qualification-v1 tools/assemblyline-yara
```

The base retains its real task process handler; configure `SERVICE_API_HOST`,
`SERVICE_API_KEY`, and the instance classification file as for any ordinary
SDK service. Runtime network access is limited by the qualification deployment.
No updater, rule downloads, package manager, or package code runs during scans.
YARA supports a 10 second scan timeout and inputs are limited to 16 MiB. The
hash-locked Linux x86_64 wheels statically include upstream YARA; other platforms
require separately reviewed wheel hashes.

`licenses/` retains the official yara-python Apache 2.0 license and the native
YARA BSD license. The Docker image includes these notices with the service.

The three SDK and engine smoke cases use actual `ServiceTask` objects, the SDK
task lifecycle, native matching, execution metadata, and the oversize error
path. An additional identity case rejects missing or substituted baked values;
the real raw service client also loads the baked identity before any request.
Run the tests against the rebuilt image. The `/source` mount compares source
hashes and supplies the test file; it does not replace the installed driver or
the baked manifest:

```sh
docker run --rm --network none --mount type=bind,source=<absolute-tools/assemblyline-yara>,target=/source,readonly --mount type=bind,source=<qualified-classification.yml>,target=/etc/assemblyline/classification.yml,readonly --entrypoint python packweir/assemblyline-yara:qualification-v1 /source/test_service.py
```

The official sources are [YARA Python 4.5.4](https://github.com/VirusTotal/yara-python/tree/v4.5.4),
[PyPI release metadata](https://pypi.org/pypi/yara-python/4.5.4/json), and the
[Assemblyline SDK](https://github.com/CybercentreCanada/assemblyline-v4-service/tree/f30da537e3adbee7c5c46e694a1ee15c4dc1cb87).
The initial manifest tool identity is consumed by the pinned
[upstream raw service client](https://github.com/CybercentreCanada/assemblyline-service-client/blob/0dad0340ec19d23b9dbe599b745f2ef0b4c46f0b/assemblyline_service_client/task_handler.py#L121).
`qualification.json` provides harmless inputs and explicit observation policy
for pairing this service with official Extract. Its values do not establish
that a live deployment has been tested; the live harness must record image,
rule, source, configuration, and observed result identities.
