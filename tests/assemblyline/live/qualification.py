#!/usr/bin/env python3
"""Exercise the actual Packweir gateway/worker against an isolated Assemblyline.

Only the package origin is a local fixture. Every /api/v4 response is obtained
from the real authenticated server. Modified records are labelled replay or SQL
fault injection and never represented as upstream captures.
"""
import datetime
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BENIGN = b"Packweir real Assemblyline qualification benign text.\n"
MARKER = b"PACKWEIR_ASSEMBLYLINE_HARMLESS_MARKER_V1\n"


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_proof():
    files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "build.rs")]
    for directory in ("src", "migrations", "tests", "tools"):
        files.extend(path for path in (ROOT / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sorted(set(files))}
    return {"sha256": digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()), "files": hashes}


def service_source_identity():
    directory = ROOT / "tools/assemblyline-yara/packweir_yara"
    framed = hashlib.sha256()
    for name in ("__init__.py", "service.py"):
        data = (directory / name).read_bytes()
        framed.update(name.encode("ascii") + b"\0" + len(data).to_bytes(8, "big") + data)
    files = {name: digest((directory / name).read_bytes()) for name in ("__init__.py", "service.py", "qualification.yar")}
    requirements_bytes = (ROOT / "tools/assemblyline-yara/requirements.lock").read_bytes()
    requirements = requirements_bytes.decode("utf-8")
    requirement = re.search(r"^yara-python==([0-9.]+)(?:\s|$)", requirements, re.MULTILINE)
    if requirement is None:
        raise RuntimeError("qualified YARA binding version is absent from the hash-locked requirements")
    binding = requirement.group(1)
    return {"driver_sha256": framed.hexdigest(), "files": files, "rules_sha256": files["qualification.yar"],
            "binding_version": binding, "engine_version": binding,
            "requirements_sha256": digest(requirements_bytes)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CaptureClient:
    def __init__(self, base_url, directory, headers=None, secrets=()):
        self.base_url = base_url.rstrip("/")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.headers = headers or {}
        self.secrets = [str(secret) for secret in secrets if secret]
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.number = 0
        self.index = []

    def clean(self, value):
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    def request(self, path, name, data=None, method=None, headers=None, timeout=30, request_proof=None):
        self.number += 1
        prefix = f"{self.number:03d}-{name}"
        values = dict(self.headers, **(headers or {}))
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data).encode()
            values["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers=values)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, body = response.code, response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise RuntimeError("capture response exceeded 4MiB")
            response_headers = {key: ("[REDACTED]" if key.lower() in ("set-cookie", "authorization") else self.clean(value))
                                for key, value in response.headers.items()}
        text = body.decode("utf-8", errors="replace")
        cleaned = self.clean(text)
        extension = ".json" if cleaned.lstrip().startswith(("{", "[")) else ".body"
        body_path = self.directory / (prefix + extension)
        # Raw bodies are retained, with only literal known secrets redacted.
        body_path.write_bytes(cleaned.encode("utf-8"))
        proof = {"captured_at": timestamp(), "method": request.get_method(), "path": path,
                 "status": status, "authenticated": bool(self.headers),
                 "request_headers": {key: ("[REDACTED]" if key.lower() in ("x-user", "x-apikey", "authorization") else value)
                                     for key, value in values.items()},
                 "response_headers": response_headers, "body_file": body_path.name,
                 "raw_response_sha256": digest(body), "saved_response_sha256": digest(cleaned.encode()),
                 "redacted": cleaned != text, "request": request_proof}
        write_json(self.directory / (prefix + ".http.json"), proof)
        self.index.append(proof)
        write_json(self.directory / "index.json", self.index)
        return status, body, body_path, proof

    def api(self, path, name, **kwargs):
        status, raw, file, proof = self.request(path, name, **kwargs)
        value = json.loads(raw)
        if status != 200 or value.get("api_error_message") or value.get("api_status_code") != 200:
            raise RuntimeError(f"real Assemblyline API failed: {path} HTTP {status}; capture {file}")
        return value["api_response"], file, proof, value


def submission_params(services, service_spec, classification):
    return {"classification": classification, "ttl": 1,
            "description": "Packweir artifact analysis",
            "services": {"selected": sorted(services), "excluded": [], "rescan": [], "resubmit": []},
            "service_spec": service_spec, "ignore_cache": False, "deep_scan": False,
            "ignore_recursion_prevention": False, "ignore_filtering": False, "ignore_size": False,
            "max_extracted": 255, "max_supplementary": 64, "generate_alert": False,
            "auto_archive": False, "delete_after_archive": False, "use_archive_alternate_dtl": False}


def multipart(metadata, data):
    boundary = "packweir-" + uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"json\"\r\n\r\n".encode()
            + json.dumps(metadata).encode()
            + f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"bin\"; filename=\"artifact.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
            + data + f"\r\n--{boundary}--\r\n".encode())
    return body, {"Content-Type": "multipart/form-data; boundary=" + boundary}


def archive_sample(marker=MARKER):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("marker.txt", date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, marker)
        empty = zipfile.ZipInfo("__init__.py", date_time=(2020, 1, 1, 0, 0, 0))
        empty.compress_type = zipfile.ZIP_DEFLATED
        empty.external_attr = 0o100644 << 16
        archive.writestr(empty, b"")
    return output.getvalue()


def collect_submission(client, sid, name, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        status, _, _, _ = client.api(f"/api/v4/submission/{sid}/", name + "-status")
        if status["state"] in ("completed", "failed"):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(f"real Assemblyline submission {sid} did not complete before deadline")
        time.sleep(1)
    report, report_file, _, envelope = client.api(
        f"/api/v4/submission/full/{sid}/?get_full_tree=true", name + "-full")
    tree, tree_file, _, _ = client.api(
        f"/api/v4/submission/tree/{sid}/?get_full_tree=true", name + "-tree")
    return {"report": report, "tree": tree, "report_file": report_file.relative_to(client.directory.parent).as_posix(),
            "tree_file": tree_file.relative_to(client.directory.parent).as_posix(),
            "captured_at": timestamp(), "server_version": envelope["api_server_version"]}


def calibrate(client, samples, specification, output):
    services = specification["services"]
    inventory, _, _, envelope = client.api("/api/v4/service/all/", "service-inventory")
    installed = {service["name"]: service for service in inventory}
    for name in services:
        if name not in installed or not installed[name].get("enabled"):
            raise RuntimeError(f"real required service {name} is missing or disabled")
        if installed[name].get("is_external") is not False or not isinstance(installed[name].get("privileged"), bool):
            raise RuntimeError(f"real required service {name} is not explicitly local with known privilege")
        version = urllib.parse.quote(installed[name]["version"], safe="")
        client.api(f"/api/v4/service/{urllib.parse.quote(name)}/?version={version}", "effective-" + name)
    records, pins = {}, {}
    source = service_source_identity()
    write_json(output / "yara-source-identity.json", source)
    known_inputs = {digest(data): data for data in samples.values()}
    for name, data in samples.items():
        metadata = {"name": name, "metadata": {"packweir_qualification_calibration": output.name},
                    "params": submission_params(services, specification["service_spec"], specification["classification"])}
        body, headers = multipart(metadata, data)
        accepted, _, _, _ = client.api("/api/v4/submit/", "calibration-" + name + "-accepted",
                                       data=body, headers=headers,
                                       request_proof={"json": metadata, "artifact_sha256": digest(data), "artifact_size": len(data)})
        sid = accepted["sid"]
        record = collect_submission(client, sid, "calibration-" + name)
        record["submission_id"] = sid
        records[name] = record
        for key, result in record["report"]["results"].items():
            response = result["response"]
            service = response["service_name"]
            if service not in services or key.endswith(".e"):
                continue
            if service == "PackweirYARA":
                tool = response.get("service_tool_version", "")
                expected_tool = (f"yara-python/{source['binding_version']}.yara/{source['engine_version']}"
                                 f".rules/{source['rules_sha256']}.driver/{source['driver_sha256']}")
                if tool != expected_tool or not re.fullmatch(specification["tool_version_pattern"], tool):
                    raise RuntimeError("real YARA result tool identity does not match pinned engine/rules/current driver source")
                sections = [section for section in result["result"]["sections"]
                            if section.get("title_text") == "Completed bounded YARA static scan"]
                if len(sections) != 1:
                    raise RuntimeError("real YARA result did not retain exactly one genuine execution metadata section")
                execution = json.loads(sections[0]["body"])
                data = known_inputs.get(result["sha256"])
                if data is None:
                    raise RuntimeError("YARA calibration analyzed bytes outside the known harmless input set")
                expected_matches = ["PackweirQualificationMarker"] if MARKER.rstrip(b"\n") in data else []
                expected = {"engine": "YARA", "engine_version": source["engine_version"],
                            "binding": "yara-python", "binding_version": source["binding_version"],
                            "rules_sha256": source["rules_sha256"], "driver_sha256": source["driver_sha256"],
                            "input_sha256": result["sha256"], "input_size": len(data),
                            "scan_scope": "qualification_marker_rule", "matching_rules": expected_matches}
                if execution != expected:
                    raise RuntimeError("real YARA execution metadata differs from the independent source/input identity")
            parts = key.split(".")
            if len(parts) != 4 or not parts[3].startswith("c"):
                raise RuntimeError("unrecognized genuine service result configuration key: " + key)
            pin = {"version": response["service_version"], "tool_version": response.get("service_tool_version"),
                   "configuration_key": parts[3][1:],
                   "applies_to": specification.get("applies_to", {}).get(service, [])}
            if service in pins and pins[service] != pin:
                raise RuntimeError("service identity changed during calibration: " + service)
            pins[service] = pin
    if set(pins) != set(services):
        raise RuntimeError("real nonempty results did not establish all exact service pins: " + repr(pins))
    policy = {"required_services": pins, "deny_rules": specification["deny_rules"],
              "informational_rules": specification.get("informational_rules", []),
              "allow_empty_files": specification.get("allow_empty_files", False), "max_result_age_seconds": 86400}
    write_json(output / "policy.json", policy)
    write_json(output / "calibration.json", records)
    return policy, envelope["api_server_version"]


def toml(value):
    if isinstance(value, bool): return "true" if value else "false"
    if isinstance(value, str): return json.dumps(value)
    if isinstance(value, (int, float)): return str(value)
    if isinstance(value, list): return "[" + ",".join(toml(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key) + "=" + toml(item) for key, item in value.items() if item is not None) + "}"
    raise TypeError(value)


def configuration(output, gateway_port, fixture_port, state, specification, policy, server_version, filename="packweir.toml"):
    values = {"listen": f"127.0.0.1:{gateway_port}", "public_url": f"http://127.0.0.1:{gateway_port}/",
              "allow_private_upstreams": True, "storage": {"kind": "fs", "root": str(output / "blobs")},
              "policy": {"revision": "real-assemblyline-live-v1", "required": ["assemblyline"],
                         "deny_on_failure": ["assemblyline"]},
              "repositories": {"live": {"ecosystem": "maven", "upstream": f"http://127.0.0.1:{fixture_port}/",
                                         "retain": True}},
              "remote_scanners": {"assemblyline": {
                  "kind": "assemblyline", "endpoint": state["base_url"].rstrip("/") + "/",
                  "server_version": server_version, "user_env": "PACKWEIR_LIVE_AL_USER",
                  "api_key_env": "PACKWEIR_LIVE_AL_KEY", "allow_upload": True,
                  "classification": specification["classification"], "retention_days": 1,
                  "profile_revision": "isolated-real-services-v1", "service_spec": specification["service_spec"],
                  "policy": policy, "allow_private_network": True, "allow_insecure_http": True,
                  "allow_external_services": False, "allow_privileged_services": True,
                  "request_timeout_seconds": 15, "analysis_timeout_seconds": 180,
                  "poll_interval_seconds": 1, "max_poll_failures": 2}}}
    path = output / filename
    path.write_text("\n".join(key + "=" + toml(value) for key, value in values.items()) + "\n", encoding="utf-8")
    return path


class PackageOrigin:
    def __init__(self, samples, output):
        self.requests = []
        paths = {f"/dev/packweir/live/{name}/1.0.0/{name}-1.0.0." + ("zip" if name == "archive-child" else "txt"): data
                 for name, data in samples.items()}
        self.paths = {name: next(path for path, data in paths.items() if data == content)
                      for name, content in samples.items()}
        requests = self.requests
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append({"path": self.path, "at": timestamp()})
                write_json(output / "package-origin-requests.json", requests)
                if self.path not in paths:
                    self.send_error(404)
                    return
                data = paths[self.path]
                self.send_response(200)
                self.send_header("Content-Type", "application/zip" if self.path.endswith(".zip") else "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args): pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def qualify(state, output, executable, database_url, sql, command, specification=None, base_environment=None):
    """Return product results; sql executes only in the runner-owned database."""
    output = Path(output)
    specification = dict(specification or json.loads((ROOT / "tools/assemblyline-yara/qualification.json").read_text(encoding="utf-8")))
    specification["classification"] = state["classification"]
    key = Path(state["apikey_file"]).read_text(encoding="utf-8").strip()
    parsed = urllib.parse.urlparse(state["base_url"])
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost"):
        raise RuntimeError("qualification requires the isolated stack's explicit loopback-only API")
    private_values = [key, state["user"]]
    for line in (Path(state["run_dir"]) / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            if any(part in name for part in ("PASSWORD", "SECRET", "KEY")):
                private_values.append(value)
    client = CaptureClient(state["base_url"], output / "server-captures",
                           {"X-USER": state["user"], "X-APIKEY": key, "Accept": "application/json"}, private_values)
    nonce = uuid.uuid4().hex
    suffix = b"Qualification nonce: " + nonce.encode("ascii") + b"\n"
    marker = MARKER + suffix
    samples = {"benign": BENIGN + suffix, "harmless-finding": marker, "archive-child": archive_sample(marker)}
    fixtures = output / "samples"
    fixtures.mkdir()
    for name, data in samples.items():
        (fixtures / (name + ".bin")).write_bytes(data)
    write_json(output / "samples.json", {"qualification_nonce": nonce,
               "samples": {name: {"sha256": digest(data), "size": len(data)} for name, data in samples.items()}})
    policy, server_version = calibrate(client, samples, specification, output)
    admin, read = uuid.uuid4().hex + uuid.uuid4().hex, uuid.uuid4().hex + uuid.uuid4().hex
    environment = dict(base_environment or os.environ, DATABASE_URL=database_url, PACKWEIR_ADMIN_TOKEN=admin,
                       PACKWEIR_READ_TOKEN=read, PACKWEIR_LIVE_AL_USER=state["user"], PACKWEIR_LIVE_AL_KEY=key,
                       RUST_LOG="packweir=info")
    results, manifest_cases = {}, []
    injected = {"tamper-known-sid": samples["benign"] + b"Separate wrong-SID qualification subject.\n",
                "incomplete-service": samples["benign"] + b"Separate service-unavailable qualification subject.\n"}
    for name, data in injected.items():
        (fixtures / (name + ".bin")).write_bytes(data)
    with PackageOrigin(dict(samples, **injected), output) as origin:
        port = free_port()
        config = configuration(output, port, origin.server.server_port, state, specification, policy, server_version)
        command([str(executable), "--config", str(config), "validate"], "product-validate.log", 30, env=environment)
        gateway_log = (output / "gateway.log").open("w", encoding="utf-8")
        gateway = subprocess.Popen([str(executable), "--config", str(config), "serve"], cwd=ROOT,
                                   env=environment, stdout=gateway_log, stderr=subprocess.STDOUT)
        product = CaptureClient(f"http://127.0.0.1:{port}", output / "product-captures",
                                {"Authorization": "Bearer " + admin}, (admin, read, key, state["user"]))

        def worker(name, with_key=True):
            env = dict(environment)
            if not with_key: env.pop("PACKWEIR_LIVE_AL_KEY")
            command([str(executable), "--config", str(config), "worker", "--once"], name + ".log", 90, env=env)

        def ledger(subject, configuration=None):
            if configuration is not None and not re.fullmatch(r"[a-f0-9]{64}", configuration):
                raise RuntimeError("invalid configuration SHA256 in qualification SQL")
            extra = " AND configuration='" + configuration + "'" if configuration else ""
            return sql("SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM "
                       "(SELECT id,job_id,subject,configuration,state,remote_id,poll_attempts,poll_failures,"
                       "request_digest,service_fingerprint,evidence_digest,created_at,deadline_at,next_poll_at,error "
                       f"FROM remote_analysis WHERE subject='{subject}'{extra} ORDER BY created_at) t")

        def due(subject):
            sql(f"UPDATE jobs SET not_before=now()-interval '1 second' WHERE subject='{subject}'; "
                f"UPDATE remote_analysis SET next_poll_at=now()-interval '1 second' WHERE subject='{subject}';", json_result=False)

        try:
            deadline = time.monotonic() + 45
            while True:
                if gateway.poll() is not None:
                    raise RuntimeError("actual Packweir gateway exited; see gateway.log")
                try:
                    status, _, _, _ = product.request("/ready", "readiness", timeout=3)
                    if status == 200: break
                except (OSError, urllib.error.URLError): pass
                if time.monotonic() >= deadline: raise RuntimeError("Packweir gateway readiness deadline exceeded")
                time.sleep(0.5)
            for name, data in samples.items():
                subject = digest(data)
                route = "/r/live" + origin.paths[name]
                status, body, _, _ = product.request(route, name + "-initial", headers={"Authorization": "Bearer " + read})
                if status != 503 or body == data:
                    raise RuntimeError(f"{name} was not withheld pending real service evidence (HTTP {status})")
                worker(name + "-submit")
                first = ledger(subject)
                write_json(output / (name + "-ledger-submitted.json"), first)
                if len(first) != 1 or first[0]["state"] != "submitted" or not first[0]["remote_id"]:
                    raise RuntimeError(f"{name}: actual worker did not durably persist exactly one real SID")
                # Restart with an unavailable credential after recording the SID.
                # Safe polling must defer without consuming a scan retry/reposting.
                due(subject)
                worker(name + "-credential-missing", with_key=False)
                deferred = ledger(subject)
                job = sql(f"SELECT row_to_json(t) FROM (SELECT state,attempts,analysis_checkpoint,lease_until FROM jobs WHERE subject='{subject}') t")
                write_json(output / (name + "-ledger-deferred.json"), {"remote": deferred, "job": job})
                if (len(deferred) != 1 or deferred[0]["id"] != first[0]["id"]
                        or deferred[0]["remote_id"] != first[0]["remote_id"] or job["attempts"] != 0
                        or job["state"] != "queued" or job["lease_until"] is not None):
                    raise RuntimeError(name + ": known-SID restart did not preserve durable deferred work")
                captured = collect_submission(client, first[0]["remote_id"], "product-" + name)
                deadline = time.monotonic() + 90
                while True:
                    due(subject)
                    worker(name + "-resume")
                    complete = ledger(subject)
                    if complete[0]["state"] in ("complete", "failed"): break
                    if time.monotonic() >= deadline: raise RuntimeError(name + ": product poll deadline exceeded")
                    time.sleep(1)
                correlation = str(uuid.UUID(first[0]["id"]))
                query = urllib.parse.urlencode({"query": "metadata.packweir_run_id:" + correlation, "rows": 100})
                search_deadline = time.monotonic() + 20
                while True:
                    matches, _, _, _ = client.api("/api/v4/search/submission/?" + query, name + "-server-correlation-search")
                    if matches["total"] != 0: break
                    if time.monotonic() >= search_deadline: raise RuntimeError(name + ": server did not index the correlation before deadline")
                    time.sleep(0.5)
                if matches["total"] != 1 or len(matches["items"]) != 1 or matches["items"][0]["sid"] != first[0]["remote_id"]:
                    raise RuntimeError(name + ": actual server search did not prove exactly one submission for the durable correlation")
                status, inspection, _, _ = product.request("/api/v1/artifacts/" + subject, name + "-inspection")
                inspection = json.loads(inspection)
                remote_evidence = [item for item in inspection.get("evidence", []) if item["check"] == "assemblyline"]
                expected = "pass" if name == "benign" else "fail"
                status, served, _, _ = product.request(route, name + "-delivery", headers={"Authorization": "Bearer " + read})
                result = {"subject": subject, "submission_id": first[0]["remote_id"], "ledger": complete,
                          "server_correlation_matches": matches["total"],
                          "expected_outcome": expected, "actual_outcomes": [item["outcome"] for item in remote_evidence],
                          "delivery_status": status, "inspection": inspection, "captured": captured}
                results[name] = result
                write_json(output / "product-results.json", results)
                if complete[0]["state"] != "complete" or [item["outcome"] for item in remote_evidence] != [expected]:
                    raise RuntimeError(f"{name}: real product outcome did not match {expected}; see product-results.json")
                if (name == "benign" and (status != 200 or served != data)) or (name != "benign" and (status != 403 or served == data)):
                    raise RuntimeError(name + ": actual delivery policy did not gate the original artifact bytes")
                if name == "archive-child":
                    details = remote_evidence[0]["details"]
                    if not any(item["child_sha256"] == digest(marker) for item in details["extracted"]):
                        raise RuntimeError("official Extract did not establish the harmless marker child edge")
                manifest_cases.append({"name": name, "subject": subject, "submission_id": first[0]["remote_id"],
                                       "captured_at": captured["captured_at"],
                                       "report_file": captured["report_file"],
                                       "tree_file": captured["tree_file"], "policy_file": "policy.json"})
            # Inject an operator mistake into our database, then poll the real
            # (unmodified) older submission. No HTTP response is fabricated.
            data = injected["tamper-known-sid"]
            subject = digest(data)
            route = "/r/live" + origin.paths["tamper-known-sid"]
            status, _, _, _ = product.request(route, "tamper-initial", headers={"Authorization": "Bearer " + read})
            if status != 503: raise RuntimeError("tamper subject was not initially withheld")
            worker("tamper-submit")
            original = ledger(subject)
            if len(original) != 1 or original[0]["state"] != "submitted":
                raise RuntimeError("tamper subject did not receive a real durable SID")
            wrong_sid = results["benign"]["submission_id"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", wrong_sid):
                raise RuntimeError("real submission SID cannot be safely represented by this fault-injection harness")
            sql(f"UPDATE remote_analysis SET remote_id='{wrong_sid}' WHERE subject='{subject}';", json_result=False)
            for iteration in range(3):
                due(subject)
                worker(f"tamper-poll-{iteration}")
                mutated = ledger(subject)
                if mutated[0]["state"] == "failed": break
            status, inspection, _, _ = product.request("/api/v1/artifacts/" + subject, "tamper-inspection")
            inspection = json.loads(inspection)
            status, served, _, _ = product.request(route, "tamper-delivery", headers={"Authorization": "Bearer " + read})
            fault = {"kind": "runner_owned_database_wrong_sid_injection", "subject": subject,
                     "original": original, "replacement_submission_id": wrong_sid, "after": mutated,
                     "inspection": inspection, "delivery_status": status}
            write_json(output / "live-wrong-sid-tamper.json", fault)
            if (len(mutated) != 1 or mutated[0]["id"] != original[0]["id"] or mutated[0]["state"] != "failed"
                    or status != 503 or served == data
                    or any(item["check"] == "assemblyline" and item["outcome"] == "pass" for item in inspection.get("evidence", []))):
                raise RuntimeError("real wrong-SID poll did not fail closed")
            results["wrong-sid-tamper"] = fault
            # Omit the opt-in empty-file policy in a new real configuration.
            # The same archive's zero-byte __init__.py cannot disappear from
            # local inventory merely because the upstream SDK omitted it.
            gateway.terminate()
            try: gateway.wait(timeout=15)
            except subprocess.TimeoutExpired:
                gateway.kill()
                gateway.wait(timeout=5)
            gateway_log.close()
            strict_policy = dict(policy)
            strict_policy.pop("allow_empty_files", None)
            write_json(output / "policy-empty-omitted.json", strict_policy)
            config = configuration(output, port, origin.server.server_port, state, specification,
                                   strict_policy, server_version, filename="packweir-empty-omitted.toml")
            gateway_log = (output / "gateway-empty-omitted.log").open("w", encoding="utf-8")
            gateway = subprocess.Popen([str(executable), "--config", str(config), "serve"], cwd=ROOT,
                                       env=environment, stdout=gateway_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while True:
                if gateway.poll() is not None: raise RuntimeError("strict empty-file gateway exited")
                try:
                    status, _, _, _ = product.request("/ready", "empty-omitted-readiness", timeout=3)
                    if status == 200: break
                except (OSError, urllib.error.URLError): pass
                if time.monotonic() >= deadline: raise RuntimeError("strict empty-file gateway readiness timed out")
                time.sleep(0.5)
            subject = digest(samples["archive-child"])
            route = "/r/live" + origin.paths["archive-child"]
            status, initial, _, _ = product.request(route, "empty-omitted-initial", headers={"Authorization": "Bearer " + read})
            if status != 503: raise RuntimeError("omitting empty-file policy did not require fresh current evidence")
            current_configuration = json.loads(initial)["configuration"]
            deadline = time.monotonic() + 90
            while True:
                due(subject)
                worker("empty-omitted-worker")
                _, inspection, _, _ = product.request("/api/v1/artifacts/" + subject, "empty-omitted-inspection")
                inspection = json.loads(inspection)
                remote_evidence = [item for item in inspection.get("evidence", []) if item["check"] == "assemblyline"]
                if remote_evidence: break
                if time.monotonic() >= deadline: raise RuntimeError("omitted empty-file policy did not produce a bounded result")
                time.sleep(1)
            current = ledger(subject, current_configuration)
            status, served, _, _ = product.request(route, "empty-omitted-delivery", headers={"Authorization": "Bearer " + read})
            details = remote_evidence[0]["details"]
            applicable = [item for item in details["coverage"] if item.get("applicable") is True]
            remote_complete = bool(applicable) and all(item["status"] == "complete" for item in applicable)
            reconciliation = details["local_inventory_reconciliation"]
            only_expected_empty = (reconciliation["complete"] is False
                                   and reconciliation["missing_files"] == [{"sha256": digest(b""), "size": 0}]
                                   and reconciliation["known_empty_content"] == [])
            expected_reason = "remote analysis omitted files observed by the gateway inventory"
            sole_expected_reason = details["coverage_reasons"] == [expected_reason]
            result = {"kind": "actual_product_configuration_omits_empty_file_opt_in", "subject": subject,
                      "configuration": current_configuration, "ledger": current,
                      "actual_outcomes": [item["outcome"] for item in remote_evidence], "delivery_status": status,
                      "all_applicable_remote_services_complete": remote_complete,
                      "missing_only_expected_empty_file": only_expected_empty,
                      "sole_expected_incomplete_reason": sole_expected_reason,
                      "inspection": inspection}
            write_json(output / "live-empty-policy-omitted.json", result)
            if [item["outcome"] for item in remote_evidence] != ["inconclusive"] or status != 503 or served == samples["archive-child"]:
                raise RuntimeError("SDK-omitted empty archive member was not withheld without explicit operator policy")
            if not (remote_complete and only_expected_empty and sole_expected_reason):
                raise RuntimeError("omitted-empty policy negative was not isolated to exactly the known empty archive member")
            results["empty-policy-omitted"] = result
            write_json(output / "product-results.json", results)
            # Withhold a real service from this owned appliance. Capture the
            # genuine unfinished server state, then exercise the bounded local
            # deadline without treating the unfinished work as clean evidence.
            compose_file, env_file = state["compose_file"], str(Path(state["run_dir"]) / ".env")
            if os.name != "nt" and state["docker"].lower().endswith(".exe"):
                compose_file, env_file = [subprocess.check_output(["wslpath", "-w", value], text=True).strip()
                                          for value in (compose_file, env_file)]
            compose = [state["docker"], "compose", "--project-name", state["project"],
                       "--file", compose_file, "--env-file", env_file,
                       "--profile", "analysis"]
            command(compose + ["stop", "--timeout", "10", "yara"], "incomplete-stop-service.log", 45)
            try:
                data = injected["incomplete-service"]
                subject = digest(data)
                route = "/r/live" + origin.paths["incomplete-service"]
                status, _, _, _ = product.request(route, "incomplete-initial", headers={"Authorization": "Bearer " + read})
                if status != 503: raise RuntimeError("incomplete subject was not initially withheld")
                first = []
                for attempt in range(4):
                    # A preceding pending GET legitimately requeues its terminal
                    # job. Drain that older real job rather than altering queue
                    # state or assuming worker --once selects this new subject.
                    worker(f"incomplete-submit-{attempt + 1}")
                    first = ledger(subject)
                    if first: break
                if not first:
                    pending_jobs = sql("SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM "
                                       "(SELECT id,subject,configuration,state,attempts,not_before,error "
                                       "FROM jobs ORDER BY created_at) t")
                    write_json(output / "incomplete-worker-drain-jobs.json", pending_jobs)
                    raise RuntimeError("four actual worker processes did not produce the incomplete subject ledger; see incomplete-worker-drain-jobs.json")
                if len(first) != 1 or first[0]["state"] != "submitted":
                    raise RuntimeError("service-unavailable subject did not receive a durable real SID")
                server_status, status_file, _, _ = client.api(
                    "/api/v4/submission/" + first[0]["remote_id"] + "/", "incomplete-real-server-status")
                if server_status["state"] != "submitted":
                    raise RuntimeError("real unavailable-service submission did not remain unfinished")
                due(subject)
                worker("incomplete-poll")
                pending = ledger(subject)
                status, pending_body, _, _ = product.request(route, "incomplete-pending", headers={"Authorization": "Bearer " + read})
                if status != 503 or pending_body == data or pending[0]["state"] != "submitted":
                    raise RuntimeError("real incomplete remote analysis was not deferred safely")
                sql(f"UPDATE remote_analysis SET deadline_at=now()+interval '1 second' WHERE subject='{subject}';", json_result=False)
                time.sleep(1.1)
                due(subject)
                worker("incomplete-deadline")
                expired = ledger(subject)
                _, inspection, _, _ = product.request("/api/v1/artifacts/" + subject, "incomplete-inspection")
                inspection = json.loads(inspection)
                status, served, _, _ = product.request(route, "incomplete-expired-delivery", headers={"Authorization": "Bearer " + read})
                fault = {"kind": "real_required_service_stopped_then_runner_shortened_local_deadline",
                         "subject": subject, "submission_id": first[0]["remote_id"], "before": first,
                         "pending": pending, "after": expired, "server_status_file": status_file.relative_to(output).as_posix(),
                         "delivery_status": status, "inspection": inspection}
                write_json(output / "live-incomplete-service.json", fault)
                if (len(expired) != 1 or expired[0]["id"] != first[0]["id"] or expired[0]["state"] != "failed"
                        or status != 503 or served == data
                        or any(item["check"] == "assemblyline" and item["outcome"] == "pass" for item in inspection.get("evidence", []))):
                    raise RuntimeError("real incomplete remote work did not fail closed at its local deadline")
                results["incomplete-service"] = fault
            finally:
                command(compose + ["start", "yara"], "incomplete-restart-service.log", 45)
            write_json(output / "product-results.json", results)
            write_json(output / "live-capture-manifest.json", {"provenance": "authenticated_real_assemblyline_v4", "cases": manifest_cases})
        finally:
            if gateway.poll() is None:
                gateway.terminate()
            try: gateway.wait(timeout=15)
            except subprocess.TimeoutExpired:
                gateway.kill()
                gateway.wait(timeout=5)
            gateway_log.close()
            log_secrets = private_values + [admin, read, database_url, urllib.parse.urlparse(database_url).password]
            for path in output.glob("gateway*.log"):
                content = path.read_text(encoding="utf-8", errors="replace")
                for secret in log_secrets:
                    if secret: content = content.replace(secret, "[REDACTED]")
                path.write_text(content, encoding="utf-8")
    return {"cases": results, "manifest": "live-capture-manifest.json", "fixture_nonce": nonce,
            "sample_sha256": {name: digest(data) for name, data in samples.items()},
            "server_version": server_version, "policy_sha256": digest((output / "policy.json").read_bytes())}
