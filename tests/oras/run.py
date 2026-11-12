#!/usr/bin/env python3
"""Qualify real ORAS interoperability and the actual Packweir CLI offline in Docker."""
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

from provision import provision

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TEST = "real_oras_roundtrip_and_cli_qualification"


def source_proof():
    """Record every source/test input admitted by the build, including this runner."""
    files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "build.rs")]
    for name in ("src", "migrations", "tests"):
        files.extend(path for path in (ROOT / name).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    pins = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}
    encoded = json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "files": pins}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", help="Docker executable; docker.exe also works from WSL")
    parser.add_argument("--image", default="packweir:oras-qualification")
    parser.add_argument("--skip-build", action="store_true", help="reuse an image of exactly the current sources")
    parser.add_argument("--prepare-only", action="store_true", help="authenticate upstream assets without building or testing")
    parser.add_argument("--archive", type=Path, help="previously downloaded official Linux AMD64 release archive")
    parser.add_argument("--gpg", help="GPG executable used to authenticate upstream checksum signatures")
    options = parser.parse_args()
    if options.prepare_only and options.skip_build:
        parser.error("--prepare-only and --skip-build cannot be combined")
    docker = options.docker or shutil.which("docker")
    if not docker and not options.prepare_only:
        raise SystemExit("Docker executable not found; use --docker with its path")

    def native_path(path):
        if os.name != "nt" and str(docker).lower().endswith(".exe"):
            return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        return str(path)

    identifier = "packweir-oras-" + uuid.uuid4().hex[:12]
    output = ROOT / "target" / "oras" / identifier
    assets = output / "build-assets"
    output.mkdir(parents=True)
    lock = json.loads((HERE / "provision.lock.json").read_text(encoding="utf-8"))
    report = {
        "status": "failed", "test": TEST, "oras_version": lock["version"],
        "archive_sha256": lock["archive_sha256"], "skip_build": options.skip_build,
        "prepare_only": options.prepare_only, "runtime_network": "none",
        "runtime_user": "10001:10001", "cpu_limit": 2, "memory_limit": "4g", "pids_limit": 256,
        "builder_image": "rust:1-bookworm", "runtime_image": "python:3.13-slim-bookworm",
    }
    container_started = False

    def command(argv, log_name, timeout, check=True):
        log_path = output / log_name
        with log_path.open("w", encoding="utf-8") as log:
            result = subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        content = log_path.read_text(encoding="utf-8", errors="replace")
        if check and result.returncode:
            print(content[-12000:], flush=True)
            raise RuntimeError(f"command failed with exit {result.returncode}; see {log_path}")
        return result.returncode, content

    print(f"Starting ORAS {lock['version']} qualification ({identifier})", flush=True)
    try:
        proof = source_proof()
        report["source_sha256"] = proof["sha256"]
        (output / "source.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
        upstream = provision(assets, options.archive, options.gpg)
        report["upstream"] = upstream
        for name in ("provision.json", "upstream-authentication.log", "upstream-attestation.log"):
            if (assets / name).is_file():
                shutil.copy2(assets / name, output / name)
        if options.prepare_only:
            report["status"] = "prepared"
            print(f"Authenticated upstream prepared; no tests executed. Report: {output / 'report.json'}", flush=True)
            return
        if not options.skip_build:
            print("Building real product CLI and qualification test from the recorded source", flush=True)
            command([
                docker, "build", "--platform", "linux/amd64", "--file", native_path(HERE / "Dockerfile"),
                "--build-context", "qualification_assets=" + native_path(assets),
                "--build-arg", "SOURCE_SHA256=" + proof["sha256"],
                "--build-arg", "ORAS_EXECUTABLE_SHA256=" + upstream["executable_sha256"],
                "--tag", options.image, native_path(ROOT),
            ], "build.log", 1800)
        metadata = json.loads(subprocess.check_output([docker, "image", "inspect", options.image], text=True))[0]
        (output / "image.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        if source_proof()["sha256"] != proof["sha256"]:
            raise RuntimeError("qualification source changed while the image was prepared; rebuild current source")
        labels = metadata["Config"].get("Labels") or {}
        if (metadata["Os"] != "linux" or metadata["Architecture"] != "amd64"
                or metadata["Config"]["User"] != "10001:10001"
                or labels.get("io.packweir.oras-source-sha256") != proof["sha256"]
                or labels.get("io.packweir.oras-archive-sha256") != lock["archive_sha256"]
                or labels.get("io.packweir.oras-executable-sha256") != upstream["executable_sha256"]):
            raise RuntimeError("qualification image does not match pinned upstream, runtime user, platform, or current sources")
        report.update(image_id=metadata["Id"], image_tags=metadata.get("RepoTags"), platform="linux/amd64")
        print("Running real ORAS and actual CLI with container networking disabled", flush=True)
        container_started = True
        run_error = None
        try:
            code, _ = command([
                docker, "run", "--name", identifier, "--network", "none", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", "10001:10001", "--cpus", "2",
                "--memory", "4g", "--pids-limit", "256", metadata["Id"],
            ], "run.log", 300, check=False)
            if code:
                run_error = RuntimeError(f"real ORAS qualification failed with exit {code}; see {output / 'run.log'}")
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
        if (result.get("status") != "passed" or not result.get("qualification")
                or result["executables"]["/usr/local/bin/oras"] != upstream["executable_sha256"]):
            raise RuntimeError("runtime proof did not qualify the exact authenticated ORAS binary")
        report["qualification"] = result
        report["status"] = "passed"
        print(f"Real ORAS and product CLI passed. Report: {output / 'report.json'}", flush=True)
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = str(error)
        raise
    finally:
        if container_started:
            try:
                subprocess.run([docker, "rm", "--force", identifier], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as error:
                print(f"Cleanup warning for test container {identifier}: {error}", file=sys.stderr)
        report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
