# Real ScanCode qualification

This runs the Packweir license driver against the official **ScanCode Toolkit 32.5.0** Linux/Python 3.13 release. The archive SHA-256 is pinned in the runner and verified again during the image build. ScanCode configures itself without network access using the release's bundled wheels, rather than resolving current dependencies from PyPI.

```sh
python3 tests/scancode/run.py
```

From WSL with only the Windows Docker CLI available:

```sh
python3 tests/scancode/run.py \
  --docker '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
```

Requires Docker with Linux AMD64 containers and BuildKit named build contexts. Network access is needed to download the 234 MB upstream release and build images. The runtime test is an unprivileged container with no network, no host mounts, dropped Linux capabilities, and CPU/memory/process limits. The image retains writable ScanCode caches; this is a qualification harness using fixed local fixtures, not a production worker sandbox.

The ignored Rust test checks that detected MIT text and an archive containing an MIT-licensed leaf pass, an unlicensed fixture stays inconclusive, and a GPL-3.0-only fixture fails the configured license policy. The driver additionally validates the report's tool version, expected scan options, complete leaf-file coverage, digests, scan errors, and SPDX evidence. Passing these fixtures does not establish legal obligations or general license-detection completeness.

The release is cached under ignored `target/tools/scancode/`. Logs and a success report with the archive digest and application image ID are preserved under `target/scancode/packweir-scancode-*/`. The runner resolves and runs the immutable image ID and attempts cleanup of only its own randomly named container, including on failure. For iteration with an already built current image, use `--skip-build`; that option makes the caller responsible for the image's source version.

Upstream: [release](https://github.com/aboutcode-org/scancode-toolkit/releases/tag/v32.5.0), [bundled configuration script](https://github.com/aboutcode-org/scancode-toolkit/blob/v32.5.0/configure).
