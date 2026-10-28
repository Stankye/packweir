# Sigstore verification fixtures

Public release metadata from [Sigstore Cosign v3.1.4](https://github.com/sigstore/cosign/releases/tag/v3.1.4):

- `cosign_checksums.txt`: exact signed artifact bytes, SHA-256 `e70e59b328d52949b3a9ae3e0d04721ea8f380c4e91c28197aa91df02afbf4c0`.
- `cosign_checksums.txt.sigstore.json`: upstream signature bundle, SHA-256 `8fc87b5562359b0414655ee281b80eb3752f58c4e137d5f0e4881f095bc26309`.
- `trusted_root.json`: public trust-root snapshot from [sigstore/root-signing](https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json), retrieved 2026-10-27, SHA-256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.

Sigstore's upstream projects are Apache-2.0 licensed. These public verification fixtures contain no private keys or credentials. The root snapshot is a test input, not an automatically maintained production trust store. Git attributes preserve signed fixture bytes on Windows checkouts.

The ignored `real_cosign` tests exercise actual cryptographic verification with Cosign 3.1.4: correct signature, wrong signer/issuer, modified signature/proof/artifact, and PostgreSQL/HTTP delivery gating. Set `PACKWEIR_TEST_COSIGN` to the absolute executable path and run `cargo test --locked -- real_cosign --ignored` with `DATABASE_URL` configured (or use `cargo test --locked --test scanners real_cosign -- --ignored` without PostgreSQL).

The normal adapter tests compile `tests/support/scanner_fixture.rs` using the installed Rust compiler. That subprocess is a test double for invocation and failure handling; it performs no cryptographic verification. It is never included as a production scanner.
