# Real OSSGadget qualification

Run with Python 3 and Docker using Linux AMD64 containers:

```sh
python3 tests/ossgadget/run.py
```

Windows Python works with Docker Desktop. From WSL with only the Windows Docker CLI available:

```sh
python3 tests/ossgadget/run.py \
  --docker '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
```

The runner calls the existing [provisioning script](../../tools/ossgadget-helper/provision.py), which checks the official Microsoft OSSGadget CLI **0.2.49** NuGet package SHA-256 and each backdoor rule at revision `4063457b40211c25b41d56465d41783f2d42c5c1`. The helper uses those verified DLLs directly. No scanner outputs are mocked. Custom-rule cases use harmless, test-owned marker rules.

Provisioning downloads upstream files, container images, build dependencies, and Python. Helper publishing and Rust compilation then run without networking. The final unprivileged container has no network, host mounts, or Linux capabilities and has explicit CPU, memory, and process limits. It runs both the fourteen-case helper qualification and the ignored Rust `ossgadget::real_helper_driver_qualification` test. Success requires proof from the Rust driver as well as the helper, with matching deployment manifest digests.

This qualifies the selected engine modes, rule extension path, coverage handling, and deployment/input binding against fixed local fixtures. It does not qualify downloaded package execution or establish that a package is free of malicious code. The container is a qualification harness, not a production worker sandbox.

Logs, source hashes, image metadata, deployment proof, and actual case results remain under ignored `target/ossgadget/packweir-ossgadget-*/`. The runner resolves the built image to its immutable image ID and cleans up only its own randomly named container. `--skip-build` reuses an image only when its source and upstream-pin labels match the current inputs. `--prepare-only` downloads and verifies upstream files without building or running tests; `--package` and `--rules-directory` pass previously acquired inputs to the same provisioning script.
