#!/usr/bin/env python3
"""Opt-in qualification against actual, isolated Assemblyline v4 services."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

from qualification import ROOT, HERE, digest, qualify, service_source_identity, source_proof, timestamp, write_json

# The runner uses the same immutable PostgreSQL image already used by this
# project's local qualification. It owns one fresh database, never an existing DB.
POSTGRES_IMAGE = "postgres:17-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5"


def shareable(relative):
    """Positive allowlist: generated appliance state/config never becomes evidence."""
    if len(relative.parts) > 1:
        return relative.parts[0] in {"server-captures", "product-captures", "acquisition", "samples"}
    if relative.suffix == ".log":
        return True  # Only this runner writes these logs, through secret redaction.
    if re.fullmatch(r"(?:benign|harmless-finding|archive-child)-ledger-(?:submitted|deferred)\.json", relative.name):
        return True  # Explicit harmless-case SQL projections omit credentials/tokens.
    return relative.name in {
        "source.json", "product-build.json", "deployment-inputs.json", "stack-identity.json",
        "samples.json", "policy.json", "policy-empty-omitted.json", "calibration.json", "product-results.json",
        "live-capture-manifest.json", "live-wrong-sid-tamper.json", "live-incomplete-service.json",
        "live-empty-policy-omitted.json", "database-queries.json", "package-origin-requests.json",
        "incomplete-worker-drain-jobs.json",
        "postgres-image.json", "postgres-host-config.json", "docker-version.json", "packweir.toml", "packweir-empty-omitted.toml",
        "yara-source-identity.json", "yara-runtime-identity.json",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", help="Docker executable (docker.exe is supported from WSL)")
    parser.add_argument("--state", type=Path, help="prepared state from this harness's stack.py")
    parser.add_argument("--output", type=Path, help="new evidence directory; defaults to target/assemblyline-live/<run>")
    parser.add_argument("--prepare-only", action="store_true", help="render isolated configuration/state; do not download images, start services, or run tests")
    parser.add_argument("--skip-build", action="store_true", help="reuse only an executable with the exact matching source/binary build proof")
    parser.add_argument("--keep-stack", action="store_true", help="retain this harness's stack for diagnosis (the product gateway and database are still stopped)")
    parser.add_argument("--stack-timeout", type=int, default=600)
    args = parser.parse_args()
    if args.prepare_only and args.skip_build:
        parser.error("--prepare-only and --skip-build cannot be combined")
    if not 60 <= args.stack_timeout <= 1200:
        parser.error("--stack-timeout must be 60..1200 seconds")
    docker = args.docker or shutil.which("docker")
    if not docker:
        raise SystemExit("Docker executable not found; provide --docker")
    run_id = "packweir-al-live-" + uuid.uuid4().hex[:12]
    output = (args.output or ROOT / "target" / "assemblyline-live" / run_id).resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("Evidence directory must be empty: " + str(output))
    output.mkdir(parents=True, exist_ok=True)
    secrets = []
    report = {"schema_version": 1, "status": "failed", "test": "real_assemblyline_v4_product_qualification",
              "run_id": run_id, "started_at": timestamp(), "prepare_only": args.prepare_only,
              "public_listeners": False, "product_database": {"image": POSTGRES_IMAGE,
                  "memory_limit_bytes": 256 * 1024 * 1024, "cpu_limit": 0.5, "pids_limit": 128},
              "live_services": "upstream Assemblyline core/UI/SDK and official Extract plus actual YARA engine qualification service"}
    state_path = args.state.resolve() if args.state else output / "stack" / "stack-state.json"
    postgres = run_id + "-postgres"
    postgres_started, stack_touched = False, False
    database_queries = []
    build_env = dict(os.environ)
    if os.name == "nt":
        build_env["PATH"] = str(ROOT / "target/tools/winlibs/mingw64/bin") + os.pathsep + build_env.get("PATH", "")
        build_env["RUSTUP_TOOLCHAIN"] = "stable-x86_64-pc-windows-gnu"
    build_env["CARGO_HOME"] = str(ROOT / "target/cargo-home")
    build_env["CARGO_BUILD_JOBS"] = "2"

    def clean(value):
        for secret in secrets:
            if secret: value = value.replace(secret, "[REDACTED]")
        return value

    def native_path(path):
        if os.name != "nt" and str(docker).lower().endswith(".exe"):
            return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        return str(path)

    def command(argv, log_name, timeout=600, env=None, check=True):
        path = output / log_name
        occurrence = 1
        while path.exists():
            occurrence += 1
            path = output / (Path(log_name).stem + f"-{occurrence:03d}" + Path(log_name).suffix)
        try:
            result = subprocess.run(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=timeout, text=True, encoding="utf-8", errors="replace")
            content = result.stdout
            code = result.returncode
        except subprocess.TimeoutExpired as error:
            captured = error.stdout or b""
            content = captured.decode(errors="replace") if isinstance(captured, bytes) else captured
            path.write_text(clean(content), encoding="utf-8")
            raise RuntimeError(f"command timed out after {timeout}s; see {path}") from error
        path.write_text(clean(content), encoding="utf-8")
        if check and code:
            print(clean(content[-8000:]), flush=True)
            raise RuntimeError(f"command failed with exit {code}; see {path}")
        return code, content

    def stack(action, *extra, timeout=600):
        return command([sys.executable, str(HERE / "stack.py"), action, "--state", str(state_path), *extra],
                       "stack-" + action + ".log", timeout)

    def sql(statement, json_result=True):
        # Only a fixed, runner-generated SHA256 enters SQL. No sample text or
        # package-provided field is interpolated into a query.
        log_name = f"database-{len(database_queries) + 1:03d}.log"
        database_queries.append({"statement": statement, "log_file": log_name, "at": timestamp()})
        write_json(output / "database-queries.json", database_queries)
        code, result = command([docker, "exec", "-i", postgres, "psql", "-U", "packweir", "-d", "packweir",
                                "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", statement],
                               log_name, 30)
        return json.loads(result.strip()) if json_result else result

    try:
        print("Preparing isolated real Assemblyline qualification: " + run_id, flush=True)
        proof = source_proof()
        write_json(output / "source.json", proof)
        report["source_sha256"] = proof["sha256"]
        command(["git", "rev-parse", "HEAD"], "git-head.log", 30)
        command(["git", "status", "--short"], "git-status.log", 30)
        command([docker, "version", "--format", "{{json .}}"], "docker-version.json", 30)
        if not args.state:
            _, prepared = command([sys.executable, str(HERE / "stack.py"), "prepare", "--output", str(output / "stack"),
                                   "--docker", docker], "stack-prepare.log", 1200)
            # prepare's stdout is precisely the state path, with diagnostics in
            # its own acquisition logs. Do not infer a successful preparation.
            returned = Path(prepared.strip().splitlines()[-1])
            if returned.resolve() != state_path.resolve():
                raise RuntimeError("stack prepare returned an unexpected state path")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not state["project"].startswith("packweir-al-live-"):
            raise RuntimeError("refusing state without the harness's unique project prefix")
        report["stack_state"] = str(state_path)
        for line in (Path(state["run_dir"]) / ".env").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                name, value = line.split("=", 1)
                if any(part in name for part in ("PASSWORD", "SECRET", "KEY")):
                    secrets.append(value)
        if args.prepare_only:
            report["status"] = "prepared"
            print("Prepared isolated configuration/state; no images downloaded and no live test executed. Report: " + str(output / "report.json"), flush=True)
            return
        # Build is bounded to two compiler processes and the exact input tree is
        # recorded before/after. A preexisting binary needs a matching prior proof.
        executable = ROOT / "target" / "debug" / ("packweir.exe" if os.name == "nt" else "packweir")
        build_proof_path = ROOT / "target/assemblyline-live/product-build.json"
        build_proof_path.parent.mkdir(parents=True, exist_ok=True)
        if args.skip_build:
            built = json.loads(build_proof_path.read_text(encoding="utf-8"))
            if built["source_sha256"] != proof["sha256"] or built["executable_sha256"] != digest(executable.read_bytes()):
                raise RuntimeError("existing product binary does not match the current source/build proof")
        else:
            print("Building the actual Packweir CLI and capture replay test", flush=True)
            command(["cargo", "build", "--locked", "--bin", "packweir"], "product-build.log", 1200, env=build_env)
            command(["cargo", "test", "--locked", "--test", "assemblyline_live", "--no-run"], "capture-test-build.log", 1200, env=build_env)
            built = {"source_sha256": proof["sha256"], "executable_sha256": digest(executable.read_bytes()),
                     "built_at": timestamp(), "executable": str(executable)}
            if source_proof()["sha256"] != proof["sha256"]:
                raise RuntimeError("source changed during product build; rerun with the final sources")
            write_json(build_proof_path, built)
        write_json(output / "product-build.json", built)
        report["product_executable_sha256"] = built["executable_sha256"]
        _, product_version = command([str(executable), "--version"], "product-version.log", 30, env=build_env)
        report["product_version"] = product_version.strip()
        report["build_environment"] = {key: build_env[key] for key in
            ("CARGO_HOME", "CARGO_BUILD_JOBS", "RUSTUP_TOOLCHAIN", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG") if key in build_env}
        secrets.append(Path(state["apikey_file"]).read_text(encoding="utf-8").strip())
        print("Starting bounded upstream services on an isolated Docker network", flush=True)
        stack_touched = True
        stack("up", "--timeout", str(args.stack_timeout), timeout=args.stack_timeout + 120)
        state = json.loads(state_path.read_text(encoding="utf-8"))
        deployment = {}
        for deployed, source in (("compose.yaml", "compose.yaml"), ("bootstrap.py", "bootstrap.py"),
                                 ("classification.yml", "config.classification.yml")):
            actual = Path(state["run_dir"]) / deployed
            expected = HERE / source
            if actual.read_text(encoding="utf-8") != expected.read_text(encoding="utf-8"):
                raise RuntimeError("prepared deployment input differs from the current reviewed source: " + deployed)
            deployment[deployed] = {"sha256": digest(actual.read_bytes()), "source": expected.relative_to(ROOT).as_posix()}
        rendered_config = (HERE / "config.yml").read_text(encoding="utf-8")
        for line in (Path(state["run_dir"]) / ".env").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                name, value = line.split("=", 1)
                rendered_config = rendered_config.replace("{" + name + "}", value)
        deployed_config = Path(state["run_dir"]) / "config.yml"
        if rendered_config != deployed_config.read_text(encoding="utf-8"):
            raise RuntimeError("actual rendered Assemblyline configuration differs from the current source/template")
        deployment["config.yml"] = {"sha256": digest(deployed_config.read_bytes()), "contains_generated_secrets": True,
                                    "source": "tests/assemblyline/live/config.yml"}
        write_json(output / "deployment-inputs.json", deployment)
        stack("identity", timeout=60)
        identity = json.loads(Path(state["identity_file"]).read_text(encoding="utf-8"))
        stack_lock = json.loads((HERE / "stack.lock.json").read_text(encoding="utf-8"))
        containers = identity["containers"]
        if (identity["lock_sha256"] != digest((HERE / "stack.lock.json").read_bytes())
                or not containers
                or identity["total_memory_limit"] + 256 * 1024 * 1024 >= 8 * 1024 ** 3
                or stack_lock["bootstrap_peak_memory_limit_mib"] >= 8 * 1024):
            raise RuntimeError("real stack identity does not match the reviewed lock or sub-8GiB resource budget")
        for container in containers:
            if (not container["state"]["Running"] or container["state"]["OOMKilled"]
                    or container["privileged"] or container["memory_limit"] <= 0 or container["nano_cpus"] <= 0
                    or container["image_id"] not in identity["images"]):
                raise RuntimeError("a real stack container is unhealthy, unbounded, privileged, or unidentified")
            image = identity["images"][container["image_id"]]
            configured = container["configured_image"]
            if image["os"] != "linux" or image["architecture"] != "amd64":
                raise RuntimeError("a real stack image does not match the qualified Linux AMD64 platform")
            if configured != container["image_id"]:
                if configured not in stack_lock["images"].values() or "@sha256:" not in configured:
                    raise RuntimeError("a running registry image is not one of the exact reviewed immutable pins")
                expected_digest = configured.split("@", 1)[1]
                if not any(pin.endswith("@" + expected_digest) for pin in image["repo_digests"]):
                    raise RuntimeError("a running registry image does not authenticate the reviewed repository digest")
            for bindings in (container["port_bindings"] or {}).values():
                if any(binding.get("HostIp") != "127.0.0.1" for binding in bindings or []):
                    raise RuntimeError("a real stack port is not explicitly loopback-only")
        write_json(output / "stack-identity.json", identity)
        report["stack_identity_sha256"] = digest((output / "stack-identity.json").read_bytes())
        report["aggregate_container_memory_limit_bytes"] = identity["total_memory_limit"] + 256 * 1024 * 1024
        report["aggregate_container_cpu_limit"] = sum(item["nano_cpus"] for item in containers) / 1_000_000_000 + 0.5
        runtime_code = """import hashlib, importlib.metadata, json
from pathlib import Path
import yara
directory = Path('/opt/al_service/packweir_yara')
framed = hashlib.sha256()
for name in ('__init__.py', 'service.py'):
    data = (directory / name).read_bytes()
    framed.update(name.encode('ascii') + b'\\0' + len(data).to_bytes(8, 'big') + data)
files = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in ('__init__.py', 'service.py', 'qualification.yar')}
native = Path(yara.__file__)
print(json.dumps({'driver_sha256': framed.hexdigest(), 'files': files, 'rules_sha256': files['qualification.yar'],
    'binding_version': importlib.metadata.version('yara-python'), 'engine_version': yara.YARA_VERSION,
    'requirements_sha256': hashlib.sha256(Path('/tmp/packweir-yara-requirements.lock').read_bytes()).hexdigest(),
    'native_module': str(native), 'native_module_sha256': hashlib.sha256(native.read_bytes()).hexdigest()}))
"""
        _, runtime = command([docker, "compose", "--project-name", state["project"], "--file", native_path(Path(state["compose_file"])),
                              "--env-file", native_path(Path(state["run_dir"]) / ".env"), "--profile", "analysis",
                              "exec", "-T", "yara", "python", "-c", runtime_code], "yara-runtime-identity.json", 45)
        runtime = json.loads(runtime)
        expected = service_source_identity()
        if any(runtime.get(key) != value for key, value in expected.items()):
            raise RuntimeError("actual YARA container driver/rules/engine/requirements differ from the exact reviewed source")
        report["yara_runtime_identity"] = runtime
        write_json(output / "yara-source-identity.json", expected)
        pg_password = uuid.uuid4().hex + uuid.uuid4().hex
        secrets.append(pg_password)
        pg_env = dict(os.environ, POSTGRES_PASSWORD=pg_password)
        postgres_started = True
        command([docker, "run", "--detach", "--name", postgres,
                 "--label", "io.packweir.assemblyline-live.run=" + run_id,
                 "--cpus", "0.5", "--memory", "256m", "--pids-limit", "128",
                 "--security-opt", "no-new-privileges", "--publish", "127.0.0.1::5432",
                 "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER=packweir", "--env", "POSTGRES_DB=packweir",
                 POSTGRES_IMAGE, "-c", "shared_buffers=32MB", "-c", "max_connections=20"],
                "postgres-start.log", 300, env=pg_env)
        command([docker, "image", "inspect", POSTGRES_IMAGE], "postgres-image.json", 30)
        _, host_config = command([docker, "inspect", "--format", "{{json .HostConfig}}", postgres], "postgres-host-config.json", 30)
        host_config = json.loads(host_config)
        if (host_config["Memory"] != 256 * 1024 * 1024 or host_config["NanoCpus"] != 500_000_000
                or host_config["PidsLimit"] != 128 or host_config["Privileged"]
                or any(binding.get("HostIp") != "127.0.0.1"
                       for bindings in host_config["PortBindings"].values() for binding in bindings or [])):
            raise RuntimeError("actual runner-owned database limits/loopback binding do not match the bounded profile")
        report["product_database"]["verified_host_config"] = {key: host_config[key]
            for key in ("Memory", "NanoCpus", "PidsLimit", "Privileged", "PortBindings", "SecurityOpt")}
        deadline = time.monotonic() + 45
        while True:
            code, _ = command([docker, "exec", postgres, "pg_isready", "-U", "packweir"], "postgres-ready.log", 15, check=False)
            if code == 0: break
            if time.monotonic() >= deadline: raise RuntimeError("runner-owned PostgreSQL readiness timed out")
            time.sleep(0.5)
        _, mapping = command([docker, "port", postgres, "5432/tcp"], "postgres-port.log", 30)
        mapping = mapping.strip()
        if not mapping.startswith("127.0.0.1:") or "\n" in mapping:
            raise RuntimeError("PostgreSQL did not bind exclusively to one explicit IPv4 loopback port")
        database_url = "postgres://packweir:" + pg_password + "@" + mapping + "/packweir"
        print("Submitting harmless bytes through the actual gateway and worker", flush=True)
        qualified = qualify(state, output, executable, database_url, sql, command, base_environment=build_env)
        report["qualification"] = qualified
        print("Replaying authenticated captures and fail-closed mutations through the Rust normalizer", flush=True)
        replay_env = dict(build_env, PACKWEIR_ASSEMBLYLINE_LIVE_MANIFEST=str(output / qualified["manifest"]))
        command(["cargo", "test", "--locked", "--test", "assemblyline_live", "--", "--ignored", "--exact",
                 "real_assemblyline_captures_and_tamper_replay"], "capture-tamper-replay.log", 300, env=replay_env)
        if source_proof()["sha256"] != proof["sha256"] or digest(executable.read_bytes()) != built["executable_sha256"]:
            raise RuntimeError("source or product binary changed while live qualification was running")
        report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = clean(str(error))
        print("Qualification failed: " + clean(str(error)), file=sys.stderr, flush=True)
        raise
    finally:
        cleanup = []
        if postgres_started:
            try:
                command([docker, "logs", postgres], "postgres.log", 30, check=False)
                _, actual_label = command([docker, "inspect", "--format", '{{index .Config.Labels "io.packweir.assemblyline-live.run"}}', postgres],
                                          "postgres-owner.log", 30, check=False)
                if actual_label.strip() == run_id:
                    code, _ = command([docker, "rm", "--force", "--volumes", postgres], "postgres-cleanup.log", 60, check=False)
                    cleanup.append({"resource": postgres, "removed": code == 0})
                else:
                    cleanup.append({"resource": postgres, "removed": False, "reason": "ownership label did not match"})
            except Exception as error:
                cleanup.append({"resource": postgres, "removed": False, "reason": clean(str(error))})
        if stack_touched:
            try:
                stack("identity", timeout=60)
                state = json.loads(state_path.read_text(encoding="utf-8"))
                command([docker, "compose", "--project-name", state["project"], "--file", state["compose_file"],
                         "--env-file", str(Path(state["run_dir"]) / ".env"), "--profile", "analysis",
                         "logs", "--no-color", "--timestamps", "--tail", "300"], "stack-runtime.log", 60, check=False)
                acquisition = output / "acquisition"
                acquisition.mkdir(exist_ok=True)
                for name in ("pull.log", "yara-build.log", "bootstrap.log", "extract-manifest-read.log", "infrastructure-up.log", "up.log", "analysis-up.log"):
                    source = Path(state["run_dir"]) / name
                    if source.is_file():
                        (acquisition / name).write_text(clean(source.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
            except Exception as error:
                report["identity_collection_error"] = clean(str(error))
            if not args.keep_stack:
                try:
                    stack("down", timeout=120)
                    cleanup.append({"resource": "real Assemblyline stack", "removed": True})
                except Exception as error:
                    cleanup.append({"resource": "real Assemblyline stack", "removed": False, "reason": clean(str(error))})
            else:
                cleanup.append({"resource": "real Assemblyline stack", "removed": False, "reason": "--keep-stack requested"})
        report["cleanup"] = cleanup
        cleanup_failed = [item for item in cleanup if not item["removed"] and item.get("reason") != "--keep-stack requested"]
        cleanup_error = None
        if cleanup_failed and report["status"] == "passed":
            cleanup_error = RuntimeError("live checks passed but owned-resource cleanup failed; see report.json cleanup")
            report["status"] = "failed"
            report["error"] = str(cleanup_error)
        report["completed_at"] = timestamp()
        # Seal only allowlisted evidence; appliance secrets/state stay private.
        report["artifacts"] = {path.relative_to(output).as_posix(): digest(path.read_bytes())
                               for path in sorted(output.rglob("*"))
                               if path.is_file() and shareable(path.relative_to(output))}
        write_json(output / "report.json", report)
        if cleanup_error:
            raise cleanup_error
    if report["status"] == "passed":
        print("Real Assemblyline and actual product qualification passed. Report: " + str(output / "report.json"), flush=True)


if __name__ == "__main__":
    main()
