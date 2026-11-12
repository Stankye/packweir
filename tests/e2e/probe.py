"""Frontend-only policy, byte-integrity, and topology assertions."""
import hashlib
import base64
import datetime
import json
import os
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "http://gateway:8080"
READ = os.environ["PACKWEIR_READ_TOKEN"]
ADMIN = os.environ.get("PACKWEIR_ADMIN_TOKEN", "")
PUBLISH = os.environ.get("PACKWEIR_PUBLISH_TOKEN", "")
PROMOTE = os.environ.get("PACKWEIR_PROMOTE_TOKEN", "")
COPY = os.environ.get("PACKWEIR_COPY_TOKEN", "")
PROD_PROMOTE = os.environ.get("PACKWEIR_PROD_PROMOTE_TOKEN", "")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, token=READ, data=None, headers=None, method=None):
    values = dict(headers or {})
    if token:
        values["Authorization"] = "Bearer " + token
    if data is not None and not isinstance(data, bytes):
        data = json.dumps(data).encode()
        values["Content-Type"] = "application/json"
    try:
        with OPENER.open(urllib.request.Request(BASE + path, data=data, headers=values, method=method), timeout=10) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def route(item):
    return f"/r/{item['repository']}/{item['path']}"


HOSTED_ROOT = "dev/packweir/private/hosted-fixture"
HOSTED_PREFIX = HOSTED_ROOT + "/1.0.0/hosted-fixture-1.0.0"
HOSTED_PUBLIC = "/r/maven-local/"


def basic(token):
    return {"Authorization": "Basic " + base64.b64encode(("publisher:" + token).encode()).decode()}


def stage_info(stage_id, token=PUBLISH):
    status, body, _ = request("/api/v1/staging/" + stage_id, token=token)
    assert status == 200, (status, body)
    return json.loads(body)


def assert_hosted_hidden(repository="maven-local"):
    for path in [HOSTED_PREFIX + extension for extension in [".jar", ".pom", ".jar.sha1", ".jar.sha256", ".jar.md5"]] + [HOSTED_ROOT + "/maven-metadata.xml"]:
        for method in ["GET", "HEAD"]:
            status, body, _ = request("/r/" + repository + "/" + path, method=method)
            assert status == 404, (path, method, status, body)
        status, body, _ = request("/r/" + repository + "/" + path, headers={"Range":"bytes=0-3"})
        assert status == 404, (path, status, body)


def hosted(phase, stage_id):
    stage_url = "/api/v1/staging/" + stage_id
    if phase == "hosted-create":
        payload = {"id":stage_id, "name":"dev.packweir.private:hosted-fixture", "version":"1.0.0"}
        for token in [READ, PROMOTE]:
            status, body, _ = request("/api/v1/repositories/maven-local/staging", token=token, data=payload)
            assert status == 403, (status, body)
        status, body, _ = request("/api/v1/repositories/maven-local/staging", token=PUBLISH, data=dict(payload, version="1.0-SNAPSHOT"))
        assert status == 400, (status, body)
        status, body, _ = request("/api/v1/repositories/maven-local/staging", token=PUBLISH, data=dict(payload, name="outside.namespace:fixture"))
        assert status == 403, (status, body)
        status, body, _ = request("/api/v1/repositories/maven-local/staging", token=PUBLISH, data=payload)
        created = json.loads(body)
        assert status == 201 and created["id"] == stage_id, (status, body)
        assert created["upload_url"] == BASE + stage_url + "/", body
        assert_hosted_hidden()
    elif phase == "hosted-seal":
        info = stage_info(stage_id)
        assert {item["path"] for item in info["files"]} == {HOSTED_PREFIX + ".jar", HOSTED_PREFIX + ".pom"}, info
        source = Path("/fixtures/java/library.jar").read_bytes()
        upload = stage_url + "/" + HOSTED_PREFIX + ".jar"
        status, body, _ = request(upload, token=None, headers=basic(PUBLISH), data=source, method="PUT")
        assert status in (201, 204), (status, body)
        status, body, _ = request(upload, token=None, headers=basic(PUBLISH), data=b"changed release bytes", method="PUT")
        assert status == 409, (status, body)
        status, body, _ = request(upload + ".sha256", token=PUBLISH, data=b"0" * 64, method="PUT")
        assert status == 400, (status, body)
        status, body, _ = request(stage_url + "/seal", token=READ, method="POST")
        assert status == 403, (status, body)
        status, body, _ = request(stage_url + "/seal", token=PUBLISH, method="POST")
        assert status == 200, (status, body)
        info = stage_info(stage_id)
        manifest = info["stage"]["manifest_digest"]
        assert len(manifest) == 64, info
        for token in [READ, PUBLISH]:
            status, body, _ = request(stage_url + "/promote", token=token, data={"manifest_digest":manifest})
            assert status == 403, (status, body)
        status, body, _ = request(stage_url + "/promote", token=PROMOTE, data={"manifest_digest":manifest})
        assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
        status, body, _ = request(upload, token=PUBLISH, data=source, method="PUT")
        assert status == 409, (status, body)
        assert_hosted_hidden()
    elif phase == "hosted-promote":
        info = stage_info(stage_id)
        manifest = info["stage"]["manifest_digest"]
        status, body, _ = request(stage_url + "/promote", token=PROMOTE, data={"manifest_digest":"0" * 64})
        assert status == 409, (status, body)
        deadline = time.monotonic() + 120
        while True:
            status, body, _ = request(stage_url + "/promote", token=PROMOTE, data={"manifest_digest":manifest})
            if status == 200:
                break
            assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
            if time.monotonic() > deadline:
                raise AssertionError(("hosted approval timed out", stage_info(stage_id)))
            time.sleep(0.25)
        file_proof = []
        for item in stage_info(stage_id)["files"]:
            status, content, _ = request(HOSTED_PUBLIC + item["path"])
            assert status == 200 and hashlib.sha256(content).hexdigest() == item["artifact"]["digest"], (status, content)
            if item["path"].endswith(".jar"):
                assert content == Path("/fixtures/java/library.jar").read_bytes()
            for algorithm in ["md5", "sha1", "sha256", "sha512"]:
                status, digest, _ = request(HOSTED_PUBLIC + item["path"] + "." + algorithm)
                assert status == 200 and digest.decode().strip() == hashlib.new(algorithm, content).hexdigest(), (status, digest)
            file_proof.append({"path":item["path"], "sha256":hashlib.sha256(content).hexdigest()})
        status, metadata, _ = request(HOSTED_PUBLIC + HOSTED_ROOT + "/maven-metadata.xml")
        assert status == 200 and b"<version>1.0.0</version>" in metadata and b"SNAPSHOT" not in metadata, (status, metadata)
        status, digest, _ = request(HOSTED_PUBLIC + HOSTED_ROOT + "/maven-metadata.xml.sha256")
        assert status == 200 and digest.decode().strip() == hashlib.sha256(metadata).hexdigest(), (status, digest)
        status, body, _ = request("/r/maven/" + HOSTED_PREFIX + ".jar")
        assert status == 403, (status, body)
        status, body, _ = request("/r/maven/dev/packweir/private/missing/1.0/missing-1.0.jar")
        assert status == 403, (status, body)
        wrapped = base64.urlsafe_b64encode(("http://upstream:8081/maven/" + HOSTED_PREFIX + ".jar").encode()).decode().rstrip("=")
        status, body, _ = request("/r/maven/_fetch/" + wrapped)
        assert status == 403, (status, body)
        status, body, _ = request("/r/maven/dev/packweir/privatex/missing/1.0/missing-1.0.jar")
        assert status == 404, (status, body)
        status, body, _ = request(stage_url + "/" + HOSTED_PREFIX + ".jar", token=PUBLISH, data=b"replace published bytes", method="PUT")
        assert status == 409, (status, body)
        proof = {"stage_id":stage_id, "manifest_digest":manifest, "coordinate":"dev.packweir.private:hosted-fixture:1.0.0", "files":file_proof,
                 "quarantine":"passed", "pending_promotion":"passed", "role_separation":"passed", "checksum_algorithms":["md5","sha1","sha256","sha512"],
                 "namespace_reservation":"passed", "immutable_uploads":"passed", "snapshots":"explicitly_rejected"}
        print("PACKWEIR_HOSTED_PROOF=" + json.dumps(proof, separators=(",", ":")), flush=True)
    elif phase == "hosted-revoke":
        manifest = stage_info(stage_id)["stage"]["manifest_digest"]
        status, body, _ = request(stage_url + "/revoke", token=PUBLISH, data={"manifest_digest":manifest})
        assert status == 403, (status, body)
        status, body, _ = request(stage_url + "/revoke", token=PROMOTE, data={"manifest_digest":manifest})
        assert status == 200, (status, body)
        assert_hosted_hidden()
        events = [json.loads(line) for line in Path("/fixtures/requests.jsonl").read_text().splitlines()]
        assert not any(event["path"].startswith("/maven/dev/packweir/private/") for event in events), events
    else:
        raise AssertionError("unknown hosted phase")
    print(f"probe {phase}: passed", flush=True)


def inspect_delivery(digest, repository):
    status, body, _ = request(f"/api/v1/artifacts/{digest}?repository={repository}", token=ADMIN)
    assert status == 200, (status, body)
    report = json.loads(body)
    assert len(report["scopes"]) == 1 and report["scopes"][0]["scope"]["repository"] == repository, report
    return report


def production_bytes(info):
    files = []
    for item in info["files"]:
        status, content, _ = request("/r/maven-prod/" + item["path"])
        assert status == 200 and hashlib.sha256(content).hexdigest() == item["artifact"]["digest"], (status, content)
        if item["path"].endswith(".jar"):
            assert content == Path("/fixtures/java/library.jar").read_bytes()
        for algorithm in ["md5", "sha1", "sha256", "sha512"]:
            status, digest, _ = request("/r/maven-prod/" + item["path"] + "." + algorithm)
            assert status == 200 and digest.decode().strip() == hashlib.new(algorithm, content).hexdigest(), (status, digest)
        files.append({"path":item["path"], "sha256":hashlib.sha256(content).hexdigest()})
    status, metadata, _ = request("/r/maven-prod/" + HOSTED_ROOT + "/maven-metadata.xml")
    assert status == 200 and b"<version>1.0.0</version>" in metadata and b"SNAPSHOT" not in metadata, (status, metadata)
    status, digest, _ = request("/r/maven-prod/" + HOSTED_ROOT + "/maven-metadata.xml.sha256")
    assert status == 200 and digest.decode().strip() == hashlib.sha256(metadata).hexdigest(), (status, digest)
    return files


def cross(phase, source_id, target_id):
    source_url, target_url = "/api/v1/staging/" + source_id, "/api/v1/staging/" + target_id
    source = stage_info(source_id)
    payload = {"id":target_id, "destination_repository":"maven-prod", "source_manifest_digest":source["stage"]["manifest_digest"]}
    if phase == "cross-denied":
        assert source["stage"]["state"] == "published", source
        for token in [READ, PUBLISH, PROMOTE, PROD_PROMOTE]:
            status, body, _ = request(source_url + "/copy", token=token, data=payload)
            assert status == 403, (status, body)
        assert_hosted_hidden("maven-prod")
    elif phase == "cross-pending":
        target = stage_info(target_id, COPY)
        assert target["stage"]["state"] == "sealed" and target["promotion"] is None, target
        assert target["stage"]["package"] == source["stage"]["package"], target
        lineage = target["copy"]
        assert lineage["source_stage"] == source_id and lineage["source_repository"] == "maven-local" and lineage["source_manifest_digest"] == payload["source_manifest_digest"] and lineage["actor"] == "copier", lineage
        assert lineage["destination"]["stage"]["id"] == target_id, lineage
        assert lineage["destination"]["manifest_digest"] != payload["source_manifest_digest"], lineage
        source_files = {item["path"]:item["artifact"] for item in source["files"]}
        copied_sources = {item["path"]:item for item in lineage["source_files"]}
        assert set(source_files) == {item["path"] for item in target["files"]}, target
        for item in target["files"]:
            original, summary = source_files[item["path"]], copied_sources[item["path"]]
            assert item["artifact"]["digest"] == original["digest"] == summary["subject"], item
            assert item["artifact"]["origin"] == BASE + "/r/maven-prod/" + item["path"], item
            assert item["artifact"]["origin"] != original["origin"], item
            assert summary["evidence_ids"] and len(summary["evidence_digest"]) == 64, summary
            assert "policy" not in summary and "evidence" not in summary, summary
            report = inspect_delivery(item["artifact"]["digest"], "maven-prod")
            assert report["decision"]["state"] == "pending" and not report["evidence"], report
            assert report["configuration"] != summary["configuration"], report
            assert "fixture_review" in report["scopes"][0]["policy"]["policy"]["required"], report
        for token in [READ, PUBLISH, PROMOTE, COPY, PROD_PROMOTE]:
            assert request(target_url + "/copy-evidence", token=token)[0] == 401
        status, full, _ = request(target_url + "/copy-evidence", token=ADMIN)
        assert status == 200 and all(item["evidence"] for item in json.loads(full)["source_files"]), (status, full)
        status, replay, _ = request(source_url + "/copy", token=COPY, data=payload)
        assert status == 201 and json.loads(replay) == lineage, (status, replay)
        for token in [READ, PUBLISH, PROMOTE, COPY]:
            assert request(target_url + "/promote", token=token, data={"manifest_digest":target["stage"]["manifest_digest"]})[0] == 403
        status, body, _ = request(target_url + "/promote", token=PROD_PROMOTE, data={"manifest_digest":target["stage"]["manifest_digest"]})
        assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
        for item in target["files"]:
            assert not inspect_delivery(item["artifact"]["digest"], "maven-prod")["evidence"]
        assert_hosted_hidden("maven-prod")
    elif phase == "cross-promote":
        target = stage_info(target_id, COPY)
        manifest = target["stage"]["manifest_digest"]
        deadline = time.monotonic() + 120
        while True:
            status, body, _ = request(target_url + "/promote", token=PROD_PROMOTE, data={"manifest_digest":manifest})
            if status == 200:
                break
            assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
            if time.monotonic() > deadline:
                raise AssertionError(("fresh production review timed out", stage_info(target_id, COPY)))
            time.sleep(0.25)
        target = stage_info(target_id, COPY)
        sources = {item["path"]:item for item in target["copy"]["source_files"]}
        source_ids = {identifier for item in sources.values() for identifier in item["evidence_ids"]}
        assert target["promotion"]["actor"] == "prod-promoter", target
        for item in target["promotion"]["files"]:
            assert item["configuration"] != sources[item["path"]]["configuration"], item
            assert "fixture_review" in item["policy"]["policy"]["required"], item
            assert not source_ids.intersection(entry["id"] for entry in item["evidence"]), item
            review = [entry["document"] for entry in item["evidence"] if entry["document"]["check"] == "fixture_review"]
            assert len(review) == 1, item
            review = review[0]
            assert review["outcome"] == "pass" and review["configuration"] == item["configuration"] and review["subject"] == item["subject"], review
            assert review["details"]["fixture_only"] is True and review["details"]["production_scope_matched"] is True, review
            assert review["details"]["binding_subject"] == item["subject"] and review["details"]["binding_configuration"] == item["configuration"], review
            assert datetime.datetime.fromisoformat(review["created_at"].replace("Z", "+00:00")) >= datetime.datetime.fromisoformat(target["copy"]["created_at"].replace("Z", "+00:00")), review
        proof = {"source_stage_id":source_id, "source_repository":"maven-local", "source_manifest_digest":payload["source_manifest_digest"], "stage_id":target_id, "repository":"maven-prod", "manifest_digest":manifest,
                 "coordinate":"dev.packweir.private:hosted-fixture:1.0.0", "files":production_bytes(target), "same_bytes":"passed", "fresh_destination_evidence":"passed", "stronger_policy":"passed", "review_adapter":"qualification_fixture_only",
                 "copy_roles":"passed", "source_evidence_privacy":"passed", "copy_replay":"passed", "quarantine":"passed", "pending_promotion":"passed", "role_separation":"passed", "namespace_reservation":"passed", "immutable_uploads":"passed", "checksum_algorithms":["md5","sha1","sha256","sha512"], "snapshots":"explicitly_rejected"}
        print("PACKWEIR_CROSS_PROOF=" + json.dumps(proof, separators=(",", ":")), flush=True)
    elif phase == "cross-revoke-source":
        status, body, _ = request(source_url + "/revoke", token=PROMOTE, data={"manifest_digest":payload["source_manifest_digest"]})
        assert status == 200, (status, body)
        assert_hosted_hidden("maven-local")
        production_bytes(stage_info(target_id, COPY))
        status, body, _ = request(source_url + "/copy", token=COPY, data=dict(payload, id=str(uuid.uuid4())))
        assert status == 409, (status, body)
    elif phase == "cross-revoke-target":
        target = stage_info(target_id, COPY)
        assert request(target_url + "/revoke", token=COPY, data={"manifest_digest":target["stage"]["manifest_digest"]})[0] == 403
        status, body, _ = request(target_url + "/revoke", token=PROD_PROMOTE, data={"manifest_digest":target["stage"]["manifest_digest"]})
        assert status == 200, (status, body)
        assert_hosted_hidden("maven-local")
        assert_hosted_hidden("maven-prod")
        events = [json.loads(line) for line in Path("/fixtures/requests.jsonl").read_text().splitlines()]
        assert not any(event["path"].startswith("/maven/dev/packweir/private/") for event in events), events
    else:
        raise AssertionError("unknown cross-repository phase")
    print(f"probe {phase}: passed", flush=True)


def main():
    phase = sys.argv[1]
    if phase.startswith("cross-"):
        cross(phase, sys.argv[2], sys.argv[3])
        return
    if phase.startswith("hosted-"):
        hosted(phase, sys.argv[2])
        return
    catalog = json.loads(Path("/fixtures/catalog.json").read_text())
    first = catalog[0]
    if phase == "pending":
        try:
            socket.getaddrinfo("upstream", 8081)
        except socket.gaierror:
            pass
        else:
            raise AssertionError("client can resolve the private upstream network")
        assert request("/ready", token=None)[0] == 200
        assert request(route(first), token=None)[0] == 401
        assert request("/api/v1/capabilities", token=READ)[0] == 401
        assert request("/metrics",token=None)[0] == 401
        assert request("/metrics",token=READ)[0] == 401
        status, body, headers = request(route(first), headers={"Range": "bytes=0-3"})
        assert status == 503 and headers["Retry-After"] and first["digest"] in body.decode(), (status, body)
        assert body != Path(f"/fixtures/{first['digest']}.bytes").read_bytes()
    elif phase == "unready":
        status, body, _ = request("/ready", token=None)
        assert status == 503 and json.loads(body) == {"ready": False}, (status, body)
        assert request("/health", token=None)[0] == 200
    elif phase == "prefetch":
        # Identity-based npm/PyPI rules require discovery binding, not filename guesses.
        for metadata in ["/r/npm/packweir-fixture", "/r/npm/@packweir/fixture", "/r/pypi/packweir-fixture/"]:
            status, body, _ = request(metadata)
            assert status == 200, (metadata, status, body)
        for item in catalog:
            status, body, _ = request("/api/v1/prefetch", token=ADMIN, data={"repository": item["repository"], "path": item["path"]})
            assert status in (200, 403, 503), (item, status, body)
        for item in catalog:
            deadline = time.monotonic() + 90
            while True:
                status, body, _ = request(f"/api/v1/artifacts/{item['digest']}", token=ADMIN)
                assert status == 200, body
                state = json.loads(body)["decision"]["state"]
                expected = "denied" if item.get("denied") else "approved"
                if state == expected:
                    break
                if time.monotonic() > deadline or state == "denied":
                    raise AssertionError((item, state, body))
                time.sleep(0.25)
        print("explain_digest=" + catalog[1]["digest"], flush=True)
    elif phase == "verify":
        status,body,_=request("/api/v1/operations",token=ADMIN)
        assert status==200,body
        snapshot=json.loads(body)
        assert snapshot["jobs"]["complete"]>0 and snapshot["artifacts"]["distinct_digests"]>0
        assert snapshot["coverage"]["physical_storage_verified"] is False
        status,body,headers=request("/metrics",token=ADMIN)
        assert status==200 and headers["Content-Type"].startswith("text/plain"),body
        assert b"# HELP packweir_" in body and b"fixture-read-token" not in body
        for item in catalog:
            status, body, headers = request(route(item))
            if item.get("denied"):
                assert status == 403 and b"blocked fixture" not in body
            else:
                assert status == 200 and hashlib.sha256(body).hexdigest() == item["digest"], (item, status, body[:300])
                assert headers["x-packweir-sha256"] == item["digest"]
                status, report, _ = request(f"/api/v1/artifacts/{item['digest']}?repository={item['repository']}", token=ADMIN)
                assert status == 200, report
                scopes = json.loads(report)["scopes"]
                assert scopes and all(scope["scope"]["package"] and scope["decision"]["state"] == "approved" for scope in scopes), scopes
                for scope in scopes:
                    assert scope["scope"]["package"]["purl"].startswith("pkg:")
                    assert scope["scope"]["package"]["basis"] in ("registry_path_observed", "registry_metadata_observed")
                    if scope["scope"]["package"]["name"] == "@packweir/fixture":
                        assert any(layer.startswith("scope:fixture-npm-scope:") for layer in scope["policy"]["layers"])
        original = Path(f"/fixtures/{first['digest']}.bytes").read_bytes()
        status, body, _ = request(route(first), headers={"Range": "bytes=0-3"})
        assert status == 206 and body == original[:4]
        events = [json.loads(line) for line in Path("/fixtures/requests.jsonl").read_text().splitlines()]
        assert events and not any(event["authorization_received"] for event in events)
    else:
        raise AssertionError("unknown test phase")
    print(f"probe {phase}: passed", flush=True)


if __name__ == "__main__":
    main()
