#!/usr/bin/env python3
"""Qualify Packweir's license driver against the official bundled ScanCode release."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
VERSION = "32.5.0"
ARCHIVE = f"scancode-toolkit-v{VERSION}_py3.13-linux.tar.gz"
URL = f"https://github.com/aboutcode-org/scancode-toolkit/releases/download/v{VERSION}/{ARCHIVE}"
SHA256 = "f9f83ffcf90577a74b61a30ebc4632a1fc89f026b438f597b18206babb964e28"
TEST = "real_scancode_reports_complete_leaf_licenses_and_holds_unknowns"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", help="Docker executable, including a Windows Docker CLI path from WSL")
    parser.add_argument("--image", default="packweir:scancode-qualification")
    parser.add_argument("--skip-build", action="store_true")
    options = parser.parse_args()
    docker = options.docker or shutil.which("docker")
    if not docker:
        raise SystemExit("Docker executable not found; use --docker with its path")

    def native_path(path):
        if os.name != "nt" and str(docker).endswith(".exe"):
            return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        return str(path)

    identifier = "packweir-scancode-" + uuid.uuid4().hex[:12]
    output = ROOT / "target" / "scancode" / identifier
    output.mkdir(parents=True)

    def command(args, log_name, timeout):
        log = output / log_name
        with log.open("w", encoding="utf-8") as stream:
            result = subprocess.run([docker, *args], cwd=ROOT, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            print(log.read_text(encoding="utf-8", errors="replace")[-12000:], flush=True)
            raise RuntimeError(f"Docker failed; see {log}")
        return log.read_text(encoding="utf-8", errors="replace")

    print(f"Starting ScanCode {VERSION} qualification ({identifier})", flush=True)
    if not options.skip_build:
        archive_directory = ROOT / "target" / "tools" / "scancode"
        archive_directory.mkdir(parents=True, exist_ok=True)
        archive = archive_directory / ARCHIVE
        if not archive.exists():
            print("Downloading the official bundled release", flush=True)
            partial = archive.with_name(ARCHIVE + ".part")
            request = urllib.request.Request(URL, headers={"User-Agent": "Packweir-qualification"})
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as stream:
                        total = 0
                        while chunk := response.read(1024 * 1024):
                            total += len(chunk)
                            if total > 256 * 1024 * 1024:
                                raise RuntimeError("ScanCode release exceeds the pinned download size budget")
                            stream.write(chunk)
                    break
                except OSError:
                    if attempt == 2:
                        raise
                    time.sleep(attempt + 1)
            if digest(partial) != SHA256:
                raise RuntimeError(f"ScanCode release checksum mismatch: {partial}")
            partial.replace(archive)
        if digest(archive) != SHA256:
            raise RuntimeError(f"Cached ScanCode release checksum mismatch: {archive}")
        print("Release SHA-256 verified; building the non-root qualification image", flush=True)
        command(["build", "--platform", "linux/amd64", "--file", native_path(ROOT / "tests/scancode/Dockerfile"),
                 "--build-context", "scancode_archive=" + native_path(archive_directory),
                 "--tag", options.image, native_path(ROOT)], "build.log", 1800)

    metadata = json.loads(subprocess.check_output([docker, "image", "inspect", options.image], text=True))[0]
    if metadata["Os"] != "linux" or metadata["Architecture"] != "amd64":
        raise RuntimeError("ScanCode qualification requires a Linux AMD64 image")
    image_id = metadata["Id"]
    try:
        print("Running the real license driver with network access disabled", flush=True)
        log = command(["run", "--rm", "--name", identifier, "--network", "none", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges", "--user", "10001:10001", "--cpus", "2", "--memory", "4g",
                       "--pids-limit", "256", image_id], "run.log", 1200)
        if "running 1 test" not in log or "1 passed; 0 failed" not in log:
            raise RuntimeError(f"The requested real-tool test did not execute exactly once; see {output / 'run.log'}")
        report = {
            "status": "passed", "test": TEST, "scancode_version": VERSION,
            "release_url": URL, "release_sha256": SHA256,
            "platform": metadata["Os"] + "/" + metadata["Architecture"], "network": "none", "skip_build": options.skip_build,
            "image_id": image_id, "image_tags": metadata["RepoTags"],
            "image_user": metadata["Config"]["User"],
            "runtime_user": "10001:10001", "cpu_limit": 2,
            "memory_limit": "4g", "pids_limit": 256,
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Real ScanCode qualification passed. Report: {output / 'report.json'}", flush=True)
    finally:
        # Only this invocation's randomly named test container is eligible for cleanup.
        try:
            subprocess.run([docker, "rm", "--force", identifier], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"Cleanup warning for test container {identifier}: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
