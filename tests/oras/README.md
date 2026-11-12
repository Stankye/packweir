# Actual ORAS qualification

Run `python3 tests/oras/run.py` with Docker and GPG installed. Python 3 standard
library modules suffice. `--prepare-only` authenticates upstream inputs without
claiming qualification. `--archive` accepts an already downloaded official Linux
AMD64 archive; its hash and signing identity are still verified. `--skip-build`
accepts only an image built from the complete current recorded source snapshot.

The runner pins ORAS 1.3.6, its release archive SHA-256, its checksums file SHA-256,
and the ORAS Project Release Signing fingerprint. It imports the release tag's
KEYS into a temporary isolated keyring and requires a matching valid GPG checksum
signature before extracting anything. When an authenticated GitHub CLI is already
available, it additionally requires successful release-tag provenance verification.
No account, registry, or registry credentials are needed for the qualification.

The Rust test uses the actual upstream ORAS executable to fetch a Packweir-written
manifest and each layer, copy the artifact between OCI layouts, and independently
push a correctly typed envelope and exact JSON documents. Packweir validates the
copied and independently authored layouts through both its reader and its actual
CLI. The CLI runs without a configuration file or database environment. The test
checks raw manifest root digest preservation, exact document bytes, unverified
trust status, no approval effect, and rejection of a tampered document.

This fixture tests standalone evidence artifacts. The package's raw SHA-256 is an
envelope field, never OCI `manifest.subject`. It does not claim distribution API,
registry transport, referrers, signature verification, or imported evidence trust.
The database/HTTP exchange tests separately prove import authentication and that
an imported pass does not approve a package.

Dependencies may be acquired during provisioning and Cargo fetch. Compilation then
runs offline. The final Linux AMD64 container runs as UID/GID 10001, with networking
disabled, all capabilities dropped, no new privileges, two CPUs, 4 GiB of memory,
and a 256-process limit. Cleanup addresses only this run's uniquely named container.

`target/oras/<run>/report.json` binds the qualification to the image ID, the complete
source-file SHA-256 snapshot, upstream signature/provenance result, archive member
hashes, extracted executable hash, observed tool versions, and case proof. Explicit
CI uploads retain reports/logs and the upstream Apache-2.0 license. They exclude
the downloaded archive, extracted upstream executable, and build inputs.

Primary references checked on 2026-11-11:

- [ORAS 1.3.6 release](https://github.com/oras-project/oras/releases/tag/v1.3.6)
- [Official binary verification](https://oras.land/docs/how_to_guides/verifying_binaries/)
- [ORAS push](https://oras.land/docs/commands/oras_push/)
- [ORAS copy](https://oras.land/docs/commands/oras_cp/)
