# Native adapter qualification fixtures

`slsa/` contains the original `.intoto.jsonl` provenance assets for [SLSA Verifier v2.7.1](https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.7.1), an Apache-2.0 project. Tests verify the actual matching Windows/Linux x64 executable as the subject. Expected source commit: `ea584f4502babc6f60d9bc799dbbb13c1caa9ee6`; builder: `builder_go_slsa3.yml@refs/tags/v2.0.0` in `slsa-framework/slsa-github-generator`. Git preserves original metadata bytes; tests submit them using `raw_base64`.

`osv/PACKWEIR-TEST-0001.json` is synthetic Packweir test data, not a real advisory. Native tests generate pinned offline snapshots with vulnerable/fixed versions for npm (including a scope), PyPI, Cargo, Maven, and NuGet. This proves adapter/extractor/exit behavior, not coverage of real vulnerability databases.

`hipcheck/` contains a transport qualification policy and execution settings for [Hipcheck 3.15.0](https://github.com/mitre/hipcheck/releases/tag/hipcheck-v3.15.0) (Apache-2.0). The fixture policy deliberately uses a constant passing expression to test the real plugin invocation and report transport; it is not a recommended security policy. Tests generate local manifests for `mitre/identity` and its `mitre/git` dependency (both 0.6.0), pin/check their binaries, and analyze the public Packweir source at `1e24fe620318a49ae829a498108b24d3291a8a8f`.

Set these absolute executable paths and run `cargo test --locked --test native_tools -- --ignored`:

- `PACKWEIR_TEST_SLSA`: SLSA Verifier 2.7.1.
- `PACKWEIR_TEST_OSV`: OSV-Scanner 2.7.0.
- `PACKWEIR_TEST_HIPCHECK`: Hipcheck 3.15.0.
- `PACKWEIR_TEST_HIPCHECK_IDENTITY`: identity plugin 0.6.0.
- `PACKWEIR_TEST_HIPCHECK_GIT`: git plugin 0.6.0.

Tests are qualified for Windows/Linux x64. SLSA needs public transparency/trust-service connectivity; Hipcheck needs the public source repository. OSV uses only generated local snapshots. The CI workflow downloads fixed release assets, checks pinned SHA-256 values, and runs these tests explicitly. These executable paths never select production tools automatically.

[Sigstore fixtures and commands](sigstore/README.md) cover the separate Cosign blob-signature driver. Normal subprocess doubles in `tests/support/` perform no cryptography or third-party analysis.
