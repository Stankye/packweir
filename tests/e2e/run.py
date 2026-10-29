#!/usr/bin/env python3
"""Docker/Compose client qualification. Run with Python 3 on Linux, WSL, or Windows."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ["npm", "pip", "cargo", "maven", "gradle", "nuget"]


def configuration(storage):
    backend = 'kind="fs"\nroot="/data"' if storage == "fs" else (
        'kind="s3"\nbucket="packweir"\nregion="us-east-1"\n'
        'endpoint="http://object-store:9000"\nroot=""'
    )
    sections = [
        'listen="0.0.0.0:8080"\npublic_url="http://gateway:8080/"\nallow_private_upstreams=true',
        "[storage]\n" + backend,
        '[policy]\nrevision="local-client-fixtures"\nrequired=["inventory","archive_safety"]',
    ]
    for name in ["npm", "pypi", "cargo", "maven", "nuget"]:
        suffix = "simple/" if name == "pypi" else ""
        section = (
            f'[repositories.{name}]\necosystem="{name}"\n'
            f'upstream="http://upstream:8081/{name}/{suffix}"\n'
            'download_origins=["http://upstream:8081/"]'
        )
        if name == "cargo":
            section += '\ncargo_download_template="http://upstream:8081/cargo/api/v1/crates/{crate}/{version}/download"'
        sections.append(section)
    return "\n\n".join(sections) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage", choices=["fs", "s3", "both"], default="both")
    parser.add_argument("--docker", help="Docker executable; docker.exe works from WSL without Linux integration")
    parser.add_argument("--skip-build", action="store_true")
    options = parser.parse_args()
    docker = options.docker or shutil.which("docker")
    if not docker:
        raise SystemExit("Docker executable not found; use --docker with its path")

    def native_path(path):
        if os.name != "nt" and str(docker).endswith(".exe"):
            return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        return str(path)

    results = []
    for storage in (["fs", "s3"] if options.storage == "both" else [options.storage]):
        project = "packweir-e2e-" + uuid.uuid4().hex[:12]
        output = ROOT / "target" / "e2e" / project
        output.mkdir(parents=True)
        config = output / "packweir.toml"
        config.write_text(configuration(storage))
        env = dict(os.environ, PACKWEIR_E2E_CONFIG=native_path(config), PACKWEIR_E2E_STORAGE=storage)
        if os.name != "nt" and str(docker).endswith(".exe"):
            exported = "PACKWEIR_E2E_CONFIG:PACKWEIR_E2E_STORAGE:PACKWEIR_E2E_IMAGE"
            env["WSLENV"] = ":".join(filter(None,[env.get("WSLENV", ""),exported]))
        base = [docker,"compose","--project-name",project,"--file",native_path(ROOT/"tests/e2e/compose.yaml"),"--profile","worker","--profile","clients"]
        if storage == "s3":
            base += ["--profile","s3"]

        command_number = 0

        def compose(*args, log_name=None, timeout=600):
            nonlocal command_number
            command_number += 1
            command = base + list(args)
            log_path = output / (log_name or f"{command_number:02d}-{args[0]}.log")
            try:
                result = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                captured = error.stdout or b""
                log_path.write_text(captured.decode(errors="replace") if isinstance(captured, bytes) else captured)
                raise RuntimeError(f"Compose timed out; see {log_path}") from error
            log_path.write_text(result.stdout)
            if result.returncode:
                print(result.stdout[-8000:], flush=True)
                raise RuntimeError(f"Compose command failed: {' '.join(args)}; see {log_path}")
            return result.stdout

        try:
            print(f"Starting {storage} qualification ({project})", flush=True)
            if not options.skip_build:
                compose("build","gateway",log_name="build.log",timeout=1200)
            compose("up","-d","--wait","--wait-timeout","180","gateway","image-defaults",timeout=300)
            compose("run","--rm","--no-deps","probe","python","/tests/probe.py","pending")
            compose("up","-d","--wait","--wait-timeout","15","--no-deps","worker")
            compose("run","--rm","--no-deps","probe","python","/tests/probe.py","prefetch")
            clients = {}
            for name in CLIENTS:
                log = compose("run","--rm","--no-deps",name,log_name=f"{name}.log")
                version = re.search(r"PACKWEIR_CLIENT_VERSION_BEGIN\s*(.*?)\s*PACKWEIR_CLIENT_VERSION_END", log, re.S)
                if not version:
                    raise RuntimeError(f"Client {name} did not report its version")
                clients[name] = {"status":"passed", "version_output":version.group(1), "log":f"{name}.log"}
                print(f"{storage}: {name} passed", flush=True)
            compose("run","--rm","--no-deps","probe","python","/tests/probe.py","verify")
            compose("stop","upstream")
            compose("run","--rm","--no-deps","storage-check")
            compose("stop","object-store" if storage == "s3" else "postgres")
            compose("run","--rm","--no-deps","probe","python","/tests/probe.py","unready")
            images = compose("config","--images").splitlines()
            inspected = subprocess.check_output([docker,"image","inspect",*sorted(set(images))], env=env, text=True)
            images = [{key: item[key] for key in ["Id","RepoTags","RepoDigests","Architecture","Os"]} for item in json.loads(inspected)]
            results.append({"storage":storage,"clients":clients,"pending_gate":"passed","denied_gate":"passed",
                            "offline_cache":"passed","retained_blob_tampering":"passed","dependency_outage":"passed",
                            "image_defaults":"passed","images":images,
                            "completed_at":datetime.datetime.now(datetime.timezone.utc).isoformat()})
            (output/"report.json").write_text(json.dumps(results[-1],indent=2))
            print(f"{storage}: policy gates, offline cache, and tamper rejection passed; report: {output / 'report.json'}", flush=True)
        finally:
            # Preserve the primary failure while still attempting both diagnostics and cleanup.
            primary_failure = sys.exc_info()[0] is not None
            cleanup_error = None
            for args, log_name in [(('logs','--no-color'),'compose.log'), (('down','--volumes','--remove-orphans'),'cleanup.log')]:
                try:
                    # Only this run's random, task-owned project and volumes are removed.
                    compose(*args,log_name=log_name,timeout=120)
                except Exception as error:
                    print(f"Diagnostics/cleanup failed for {project}: {error}", file=sys.stderr, flush=True)
                    cleanup_error = error
            if cleanup_error and not primary_failure:
                raise cleanup_error
        options.skip_build = True
    report = ROOT / "target" / "e2e" / "report.json"
    report.write_text(json.dumps(results,indent=2))
    print(f"Qualification passed. Combined report: {report}", flush=True)


if __name__ == "__main__":
    main()
