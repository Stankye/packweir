#!/usr/bin/env python3
"""Qualify the pinned Microsoft engine, .NET helper, and native Rust driver offline."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools" / "ossgadget-helper"
VERSION = "0.2.49"
PACKAGE_SHA256 = "0f139a32ecf35538d44cf0be7781be6194a395bc331d4084240f77f1c5b8aded"
RULE_REVISION = "4063457b40211c25b41d56465d41783f2d42c5c1"
SDK_IMAGE = "mcr.microsoft.com/dotnet/sdk@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b"
RUST_IMAGE = "rust:1-bookworm"
TEST = "real_helper_driver_qualification"

DOCKERFILE = r"""# Generated qualification image; inputs are trusted local test fixtures.
FROM {rust_image} AS tests
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo fetch --locked
RUN --network=none \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    if ! cargo test --release --locked --offline --test ossgadget --no-run --message-format=json > /tmp/test-build.jsonl; then \
      python3 -c 'import json; rows=[json.loads(line) for line in open("/tmp/test-build.jsonl")]; [print(r["message"].get("rendered","")) for r in rows if r.get("reason")=="compiler-message"]'; exit 1; fi \
    && python3 -c 'import json,shutil; rows=[json.loads(line) for line in open("/tmp/test-build.jsonl")]; paths=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{{}}).get("name")=="ossgadget" and r.get("executable")]; assert len(paths)==1,paths; shutil.copy2(paths[0],"/ossgadget-tests")' \
    && rustc --version > /rust-version.txt

FROM {sdk_image} AS helper
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
# Provision Python while networking is allowed; publishing and every scan run offline.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/helper
COPY tools/ossgadget-helper/*.cs tools/ossgadget-helper/*.csproj \
     tools/ossgadget-helper/*.Config tools/ossgadget-helper/*.py \
     tools/ossgadget-helper/*.json ./
COPY --from=qualification_assets /upstream /opt/ossgadget/upstream
RUN --network=none dotnet publish Packweir.OssGadget.Helper.csproj -c Release \
    -p:OssgadgetRoot=/opt/ossgadget/upstream --configfile NuGet.Config \
    -o /opt/ossgadget/publish \
    && python3 deployment_manifest.py /opt/ossgadget/publish

FROM helper AS runtime
LABEL io.packweir.ossgadget-version="{version}" \
      io.packweir.ossgadget-package-sha256="{package_sha256}" \
      io.packweir.ossgadget-rule-revision="{rule_revision}" \
      io.packweir.ossgadget-source-sha256="{source_sha256}"
COPY --from=tests --chmod=0555 /ossgadget-tests /usr/local/bin/packweir-ossgadget-tests
COPY --from=tests /rust-version.txt /opt/ossgadget/rust-version.txt
COPY --from=qualification_assets /runtime.py /opt/ossgadget/runtime.py
COPY packweir.toml /qualification/packweir.toml
RUN mkdir -p /qualification && chown -R 10001:10001 /qualification
ENV PACKWEIR_TEST_OSSGADGET_DOTNET=/usr/share/dotnet/dotnet \
    PACKWEIR_TEST_OSSGADGET_ROOT=/opt/ossgadget/publish \
    PACKWEIR_TEST_OSSGADGET_MANIFEST=/opt/ossgadget/publish/deployment-manifest.json \
    DOTNET_CLI_HOME=/tmp/dotnet
USER 10001:10001
WORKDIR /qualification
ENTRYPOINT ["python3", "/opt/ossgadget/runtime.py"]
"""

RUNTIME = r'''"""Runs only fixed harmless qualification cases, with container networking disabled."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

OUTPUT = Path("/qualification")
DEPLOYMENT = Path(os.environ["PACKWEIR_TEST_OSSGADGET_ROOT"])
DOTNET = os.environ["PACKWEIR_TEST_OSSGADGET_DOTNET"]
TEST = "real_helper_driver_qualification"


def invoke(command, name, timeout):
    path = OUTPUT / name
    with path.open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    content = path.read_text(encoding="utf-8", errors="replace")
    if result.returncode:
        print(content[-12000:], flush=True)
        raise RuntimeError(f"{name} failed with exit {result.returncode}")
    return content


def main():
    report = {"status": "failed", "network": "none", "test": TEST}
    try:
        manifest_bytes = Path(os.environ["PACKWEIR_TEST_OSSGADGET_MANIFEST"]).read_bytes()
        manifest = json.loads(manifest_bytes)
        report["deployment_manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        report["deployment_files"] = len(manifest["files"])
        report["deployment_bytes"] = sum((DEPLOYMENT / name).stat().st_size for name in manifest["files"])
        report["dotnet_sdk"] = invoke([DOTNET, "--version"], "dotnet-version.log", 60).strip()
        report["rust_version"] = Path("/opt/ossgadget/rust-version.txt").read_text().strip()
        helper_text = invoke([
            "python3", "/build/helper/qualify.py", "--inputs", str(OUTPUT / "fixtures"),
            "--scan-root", str(OUTPUT / "fixtures"), "--command", DOTNET, "exec",
            "--runtimeconfig", str(DEPLOYMENT / "packweir-ossgadget-helper.runtimeconfig.json"),
            "--depsfile", str(DEPLOYMENT / "packweir-ossgadget-helper.deps.json"),
            str(DEPLOYMENT / "packweir-ossgadget-helper.dll")
        ], "helper.log", 600)
        helper = json.loads(helper_text)
        if helper.get("qualified") is not True or len(helper.get("cases", [])) != 14:
            raise RuntimeError("all fourteen real-helper qualification cases must execute")
        (OUTPUT / "helper-qualification.json").write_text(json.dumps(helper, indent=2))
        report["helper"] = helper
        driver_text = invoke([
            "/usr/local/bin/packweir-ossgadget-tests", "--exact", TEST, "--ignored", "--nocapture"
        ], "driver.log", 600)
        if "running 1 test" not in driver_text or "1 passed; 0 failed" not in driver_text:
            raise RuntimeError("the requested real Rust driver test must execute exactly once")
        matches = re.findall(r"PACKWEIR_OSSGADGET_PROOF=(\{[^\r\n]*\})", driver_text)
        if len(matches) != 1:
            raise RuntimeError("real Rust driver test did not emit exactly one qualification proof")
        driver = json.loads(matches[0])
        if (driver.get("qualified") is not True
                or driver.get("deployment_manifest_sha256") != report["deployment_manifest_sha256"]
                or len(driver.get("cases", [])) < 7):
            raise RuntimeError("real Rust driver proof is incomplete or uses another deployment")
        expected = {
            "backdoor_clear": "pass", "backdoor_finding": "inconclusive",
            "explicit_denial": "fail", "characteristic_finding": "inconclusive",
            "custom_clear": "pass", "custom_finding": "inconclusive",
            "binary_partial": "inconclusive", "mixed_binary_partial": "inconclusive",
            "malformed_rules": "error", "deployment_pin_rejected": "error",
            "subject_digest_rejected": "error",
        }
        cases = driver["cases"]
        actual = {case["case"]: case["outcome"] for case in cases}
        if len(actual) != len(cases) or any(actual.get(name) != outcome for name, outcome in expected.items()):
            raise RuntimeError("real Rust driver proof is missing a required case or expected outcome")
        (OUTPUT / "driver-qualification.json").write_text(json.dumps(driver, indent=2))
        report["driver"] = driver
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUTPUT / "runtime.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
'''


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def source_proof():
    """Bind a reusable image to the code and fixed test inputs actually built."""
    files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "build.rs", "packweir.toml")]
    for directory in ("src", "migrations", "tests"):
        files.extend(path for path in (ROOT / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    files.extend(path for path in HELPER.iterdir() if path.is_file() and path.suffix != ".md")
    pins = {path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(set(files))}
    content = json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(content).hexdigest(), "files": pins}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", help="Docker executable; a Windows docker.exe path also works from WSL")
    parser.add_argument("--image", default="packweir:ossgadget-qualification")
    parser.add_argument("--skip-build", action="store_true", help="reuse an image built from the exact current qualification sources")
    parser.add_argument("--prepare-only", action="store_true", help="provision verified upstream files without building or running tests")
    parser.add_argument("--package", type=Path, help="pass a previously acquired nupkg to the existing provisioning script")
    parser.add_argument("--rules-directory", type=Path, help="pass previously acquired rule files to the existing provisioning script")
    options = parser.parse_args()
    if options.skip_build and options.prepare_only:
        parser.error("--skip-build and --prepare-only cannot be combined")
    docker = options.docker or shutil.which("docker")
    if not docker and not options.prepare_only:
        raise SystemExit("Docker executable not found; use --docker with its path")

    def native_path(path):
        if os.name != "nt" and str(docker).lower().endswith(".exe"):
            return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        return str(path)

    identifier = "packweir-ossgadget-" + uuid.uuid4().hex[:12]
    output = ROOT / "target" / "ossgadget" / identifier
    assets = output / "build-assets"
    assets.mkdir(parents=True)
    report = {
        "status": "failed", "test": TEST, "ossgadget_version": VERSION,
        "package_sha256": PACKAGE_SHA256, "backdoor_rules_revision": RULE_REVISION,
        "sdk_base_image": SDK_IMAGE, "rust_builder_image": RUST_IMAGE,
        "skip_build": options.skip_build, "prepare_only": options.prepare_only,
        "runtime_network": "none", "runtime_user": "10001:10001", "cpu_limit": 2,
        "memory_limit": "4g", "pids_limit": 256,
    }
    container_started = False

    def command(argv, log_name, timeout, check=True):
        log = output / log_name
        with log.open("w", encoding="utf-8") as stream:
            result = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        text = log.read_text(encoding="utf-8", errors="replace")
        if check and result.returncode:
            print(text[-12000:], flush=True)
            raise RuntimeError(f"command failed with exit {result.returncode}; see {log}")
        return result.returncode, text

    def cleanup():
        if not container_started:
            return
        try:
            subprocess.run([docker, "rm", "--force", identifier], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"Cleanup warning for test container {identifier}: {error}", file=sys.stderr)

    print(f"Starting OSSGadget {VERSION} qualification ({identifier})", flush=True)
    try:
        lock = json.loads((HELPER / "provision.lock.json").read_text(encoding="utf-8"))
        if (lock["package_version"] != VERSION or lock["package_sha256"] != PACKAGE_SHA256
                or lock["source_revision"] != RULE_REVISION):
            raise RuntimeError("qualification runner and upstream provision lock disagree")
        proof = source_proof()
        report["source_sha256"] = proof["sha256"]
        (output / "source.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
        (output / "provision.lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
        if not options.skip_build:
            provisioning = [sys.executable, str(HELPER / "provision.py"), str(assets / "upstream")]
            if options.package:
                provisioning.extend(["--package", str(options.package.resolve(strict=True))])
            if options.rules_directory:
                provisioning.extend(["--rules-directory", str(options.rules_directory.resolve(strict=True))])
            command(provisioning, "provision.log", 900)
            (assets / "runtime.py").write_text(RUNTIME, encoding="utf-8")
            dockerfile = output / "Dockerfile"
            dockerfile.write_text(DOCKERFILE.format(
                rust_image=RUST_IMAGE, sdk_image=SDK_IMAGE, version=VERSION,
                package_sha256=PACKAGE_SHA256, rule_revision=RULE_REVISION,
                source_sha256=proof["sha256"],
            ), encoding="utf-8")
            if options.prepare_only:
                report["status"] = "prepared"
                print(f"Verified upstream provisioned; no tests executed. Files: {output}", flush=True)
                return
            print("Verified upstream provisioned; building offline helper and Rust driver", flush=True)
            command([
                docker, "build", "--platform", "linux/amd64", "--file", native_path(dockerfile),
                "--build-context", "qualification_assets=" + native_path(assets),
                "--tag", options.image, native_path(ROOT),
            ], "build.log", 1800)

        metadata = json.loads(subprocess.check_output([docker, "image", "inspect", options.image], text=True))[0]
        (output / "image.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        if source_proof()["sha256"] != proof["sha256"]:
            raise RuntimeError("qualification sources changed during image preparation; rebuild the current source")
        if metadata["Os"] != "linux" or metadata["Architecture"] != "amd64":
            raise RuntimeError("OSSGadget qualification requires a Linux AMD64 image")
        labels = metadata["Config"].get("Labels") or {}
        if (labels.get("io.packweir.ossgadget-source-sha256") != proof["sha256"]
                or labels.get("io.packweir.ossgadget-package-sha256") != PACKAGE_SHA256
                or labels.get("io.packweir.ossgadget-rule-revision") != RULE_REVISION):
            raise RuntimeError("qualification image does not match the current source and upstream pins")
        report.update(image_id=metadata["Id"], image_tags=metadata.get("RepoTags"),
                      image_user=metadata["Config"]["User"], platform="linux/amd64")
        print("Running real helper and native Rust driver with network access disabled", flush=True)
        container_started = True
        run_error = None
        try:
            code, _ = command([
                docker, "run", "--name", identifier, "--network", "none", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", "10001:10001", "--cpus", "2",
                "--memory", "4g", "--pids-limit", "256", metadata["Id"],
            ], "run.log", 1200, check=False)
            if code:
                run_error = RuntimeError(f"real-tool container failed with exit {code}; see {output / 'run.log'}")
        except (OSError, subprocess.TimeoutExpired) as error:
            run_error = error
            subprocess.run([docker, "stop", "--time", "10", identifier], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)
        runtime = output / "runtime"
        runtime.mkdir()
        command([docker, "cp", f"{identifier}:/qualification/.", native_path(runtime)], "collect.log", 60)
        if run_error:
            raise run_error
        result = json.loads((runtime / "runtime.json").read_text(encoding="utf-8"))
        if result.get("status") != "passed" or not result.get("helper") or not result.get("driver"):
            raise RuntimeError("both real-helper and native Rust-driver qualification must pass")
        report["qualification"] = result
        report["status"] = "passed"
        print(f"Real OSSGadget helper and Rust driver passed. Report: {output / 'report.json'}", flush=True)
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = str(error)
        raise
    finally:
        cleanup()
        report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
