"""Hosted NuGet qualification: protocol bytes, quarantine, roles, and fresh policy."""
import base64
import datetime
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import uuid
import zipfile

from probe import (ADMIN, BASE, COPY, PROD_PROMOTE, PROMOTE, PUBLISH,
                   READ, inspect_delivery, request, stage_info)

PACKAGE = "packweir.private.fixture"
VERSION = "1.0.0"
FLAT = "flatcontainer/" + PACKAGE
PACKAGE_PATH = FLAT + "/" + VERSION + "/" + PACKAGE + "." + VERSION + ".nupkg"
NUSPEC_PATH = FLAT + "/" + VERSION + "/" + PACKAGE + ".nuspec"
ORIGINAL = Path("/fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg")


def api_url(stage_id):
    return "/api/v1/staging/" + stage_id


def flat_url(repository, path):
    return "/r/" + repository + "/" + path


def package_metadata(repository):
    status, body, _ = request("/r/" + repository + "/index.json")
    assert status == 200, (status, body)
    index = json.loads(body)
    resources = [r for r in index["resources"] if r["@type"] == "PackageBaseAddress/3.0.0"]
    assert len(resources) == 1 and resources[0]["@id"] == BASE + "/r/" + repository + "/flatcontainer/", index
    assert all("PackagePublish" not in str(r["@type"]) for r in index["resources"]), index
    return index


def assert_hidden(repository):
    package_metadata(repository)
    for path in [PACKAGE_PATH, PACKAGE_PATH + ".sha512", NUSPEC_PATH, FLAT + "/index.json"]:
        for method in ["GET", "HEAD"]:
            status, body, _ = request(flat_url(repository, path), method=method)
            assert status == 404, (repository, path, method, status, body)
        status, body, _ = request(flat_url(repository, path), headers={"Range": "bytes=0-3"})
        assert status == 404, (repository, path, status, body)


def create(stage_id, name="Packweir.Private.Fixture", version=VERSION):
    payload = {"id": stage_id, "name": name, "version": version}
    status, body, _ = request("/api/v1/repositories/nuget-local/staging", token=PUBLISH, data=payload)
    assert status == 201, (status, body)
    created = json.loads(body)
    assert created["id"] == stage_id, created
    assert created["upload_url"] == BASE + api_url(stage_id) + "/nuget/index.json", created
    return created


def qualify_normalization():
    # The SDK fixture runs the bundled, official NuGet.Versioning implementation.
    expected = json.loads(Path("/fixtures/nuget/normalization.json").read_text())
    for number, (raw, normalized) in enumerate(expected.items()):
        stage_id = str(uuid.uuid4())
        payload = {"id": stage_id, "name": "Packweir.Private.Normalization" + str(number), "version": raw}
        status, body, _ = request("/api/v1/repositories/nuget-local/staging", token=PUBLISH, data=payload)
        if normalized is None:
            assert status == 400, (raw, normalized, status, body)
        else:
            assert status == 201, (raw, normalized, status, body)
            actual = stage_info(stage_id)["stage"]["package"]["version"]
            assert actual == normalized, (raw, normalized, actual)
    # Every representation aliases the actual native publication's reservation.
    for raw in ["1", "1.0", "01.0.0", "1.0.0.0", "1.0.0+other"]:
        payload = {"id": str(uuid.uuid4()), "name": "PACKWEIR.PRIVATE.FIXTURE", "version": raw}
        status, body, _ = request("/api/v1/repositories/nuget-local/staging", token=PUBLISH, data=payload)
        assert status == 409, (raw, status, body)
    return expected


def push_path(stage_id):
    status, body, _ = request(api_url(stage_id) + "/nuget/index.json", token=None)
    assert status == 200, (status, body)
    resources = [r for r in json.loads(body)["resources"] if r["@type"] == "PackagePublish/2.0.0"]
    assert len(resources) == 1 and resources[0]["@id"].startswith(BASE + api_url(stage_id) + "/"), body
    return resources[0]["@id"][len(BASE):]


def push(stage_id, content, token=PUBLISH):
    boundary = "packweir-fixture-boundary-0000000000"
    body = ("--" + boundary + '\r\nContent-Disposition: form-data; name="package"; filename="fixture.nupkg"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode() + content + ("\r\n--" + boundary + "--\r\n").encode()
    return request(push_path(stage_id), token=None, data=body, method="PUT",
                   headers={"X-NuGet-ApiKey": token, "Content-Type": "multipart/form-data; boundary=" + boundary})


def altered_package(content, replace=None, duplicate_nuspec=False):
    result = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(content)) as source, zipfile.ZipFile(result, "w") as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.endswith(".nuspec") and replace:
                data = replace(data)
            target.writestr(item, data)
            if item.filename.endswith(".nuspec") and duplicate_nuspec:
                target.writestr("second.nuspec", data)
    return result.getvalue()


def assert_proxy_reservation():
    for repository in ["nuget", "nuget-other"]:
        # Metadata-only requests must fail before a private identity can be seeded.
        for relative in [
            "flat/packweir.private.fixture/index.json",
            "flat/Packweir.Private.Fixture/index.json",
            "flat/packweir.private.missing/1.0.0/packweir.private.missing.nuspec",
            "flat/packweir.private.fixture/1.0.0/packweir.private.fixture.1.0.0.nupkg",
            "registration/packweir.private.fixture/index.json",
        ]:
            status, body, _ = request("/r/" + repository + "/" + relative)
            assert status == 403, (repository, relative, status, body)
        for origin in ["http://upstream:8081/nuget/flat/", "http://upstream:8081/v3-flatcontainer/", "http://upstream:8081/cdn/flatcontainer/"]:
            target = origin + "Packweir.Private.Fixture/index.json"
            wrapped = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
            status, body, _ = request("/r/" + repository + "/_fetch/" + wrapped)
            assert status == 403, (target, status, body)
        status, body, _ = request("/r/" + repository + "/flat/packweir.privatex.fixture/index.json")
        assert status == 404, (status, body)
        status, body, _ = request("/r/" + repository + "/flat/redirect.fixture/index.json")
        # Redirects rejected by fetch_guarded use the sanitized upstream-error response.
        assert status == 502, ("private metadata redirect", repository, status, body)
    events = [json.loads(line) for line in Path("/fixtures/requests.jsonl").read_text().splitlines()]
    assert not any("packweir.private." in event["path"].lower() for event in events), events


def published_bytes(repository, info):
    package_metadata(repository)
    source = ORIGINAL.read_bytes()
    assert len(info["files"]) == 1 and info["files"][0]["path"] == PACKAGE_PATH, info
    item = info["files"][0]
    status, content, headers = request(flat_url(repository, PACKAGE_PATH))
    assert status == 200 and content == source, (status, content[:100])
    digest = hashlib.sha256(source).hexdigest()
    assert item["artifact"]["digest"] == digest and headers["x-packweir-sha256"] == digest, (item, headers)
    status, body, _ = request(flat_url(repository, FLAT + "/index.json"))
    assert status == 200 and json.loads(body) == {"versions": [VERSION]}, (status, body)
    with zipfile.ZipFile(io.BytesIO(source)) as archive:
        nuspec = archive.read(next(name for name in archive.namelist() if name.endswith(".nuspec")))
    status, body, _ = request(flat_url(repository, NUSPEC_PATH))
    assert status == 200 and body == nuspec, (status, body)
    status, body, _ = request(flat_url(repository, PACKAGE_PATH + ".sha512"))
    assert status == 200 and body.decode().strip() == base64.b64encode(hashlib.sha512(source).digest()).decode(), (status, body)
    status, head, headers = request(flat_url(repository, PACKAGE_PATH), method="HEAD")
    assert status == 200 and not head and int(headers["Content-Length"]) == len(source), (status, headers)
    status, partial, _ = request(flat_url(repository, PACKAGE_PATH), headers={"Range": "bytes=0-3"})
    assert status == 206 and partial == source[:4], (status, partial)
    return [{"path": PACKAGE_PATH, "sha256": digest}]


def promote(stage_id, token):
    manifest = stage_info(stage_id, PUBLISH if token == PROMOTE else COPY)["stage"]["manifest_digest"]
    deadline = time.monotonic() + 120
    while True:
        status, body, _ = request(api_url(stage_id) + "/promote", token=token, data={"manifest_digest": manifest})
        if status == 200:
            return stage_info(stage_id, PUBLISH if token == PROMOTE else COPY)
        assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
        assert time.monotonic() < deadline, ("fresh NuGet approval timed out", stage_id, body)
        time.sleep(0.25)


def run(phase, source_id, target_id=None):
    source_url = api_url(source_id)
    if phase == "create":
        payload = {"id": source_id, "name": "Packweir.Private.Fixture", "version": VERSION}
        for token in [READ, PROMOTE, COPY, PROD_PROMOTE]:
            assert request("/api/v1/repositories/nuget-local/staging", token=token, data=payload)[0] == 403
        for name in ["Outside.Namespace.Fixture", "Packweir.Privatex.Fixture"]:
            assert request("/api/v1/repositories/nuget-local/staging", token=PUBLISH, data=dict(payload, name=name))[0] == 403
        create(source_id)
        qualify_normalization()
        assert_hidden("nuget-local")
        assert_hidden("nuget-prod")
        assert_proxy_reservation()
    elif phase == "seal":
        source = ORIGINAL.read_bytes()
        with zipfile.ZipFile(io.BytesIO(source)) as archive:
            assert ".signature.p7s" in archive.namelist()
        info = stage_info(source_id)
        assert len(info["files"]) == 1 and info["files"][0]["path"] == PACKAGE_PATH, info
        assert info["files"][0]["artifact"]["digest"] == hashlib.sha256(source).hexdigest(), info
        assert push(source_id, source, token="")[0] == 401
        for token in [READ, PROMOTE, COPY, PROD_PROMOTE]:
            assert push(source_id, source, token=token)[0] == 403
        assert push(source_id, source)[0] in (201, 204)
        assert push(source_id, altered_package(source, lambda data: data.replace(b"qualification fixture", b"changed fixture")))[0] == 409
        for malformed in [b"not a ZIP", altered_package(source, lambda data: b"<package>"),
                          altered_package(source, lambda data: data.replace(b"Packweir.Private.Fixture", b"Packweir.Private.Other")),
                          altered_package(source, duplicate_nuspec=True)]:
            assert push(source_id, malformed)[0] == 400
        assert request(source_url + "/seal", token=READ, method="POST")[0] == 403
        status, body, _ = request(source_url + "/seal", token=PUBLISH, method="POST")
        assert status == 200, (status, body)
        info = stage_info(source_id)
        manifest = info["stage"]["manifest_digest"]
        assert len(manifest) == 64 and info["stage"]["package"]["name"] == PACKAGE, info
        for token in [READ, PUBLISH, COPY, PROD_PROMOTE]:
            assert request(source_url + "/promote", token=token, data={"manifest_digest": manifest})[0] == 403
        status, body, _ = request(source_url + "/promote", token=PROMOTE, data={"manifest_digest": manifest})
        assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
        assert push(source_id, source)[0] == 409
        assert_hidden("nuget-local")
    elif phase == "promote":
        status, body, _ = request(source_url + "/promote", token=PROMOTE, data={"manifest_digest": "0" * 64})
        assert status == 409, (status, body)
        source = promote(source_id, PROMOTE)
        assert_proxy_reservation()
        assert push(source_id, ORIGINAL.read_bytes())[0] == 409
        proof = {"stage_id": source_id, "repository": "nuget-local", "manifest_digest": source["stage"]["manifest_digest"],
                 "coordinate": PACKAGE + "@" + VERSION, "files": published_bytes("nuget-local", source),
                 "quarantine": "passed", "original_nupkg_bytes": "passed", "native_push": "dotnet-nuget-push",
                 "package_signature": "native-dotnet-nuget-sign", "test_certificate": "ephemeral-self-signed-code-signing-only",
                 "client_trusted_signer_sha256": Path("/fixtures/nuget/fingerprint.txt").read_text(),
                 "packweir_signature_verification": False,
                 "malformed_nuspec": "rejected", "mismatched_nuspec": "rejected", "immutable_uploads": "passed",
                 "normalization": json.loads(Path("/fixtures/nuget/normalization.json").read_text()),
                 "normalization_reference": Path("/fixtures/nuget/versioning.txt").read_text(), "duplicate_version_alias": "rejected",
                 "role_separation": "passed", "namespace_reservation": "passed", "verifier": "qualification_fixture_only"}
        print("PACKWEIR_NUGET_SOURCE_PROOF=" + json.dumps(proof, separators=(",", ":")), flush=True)
    else:
        cross(phase, source_id, target_id)
    print("probe nuget-" + phase + ": passed", flush=True)


def cross(phase, source_id, target_id):
    source = stage_info(source_id)
    source_url, target_url = api_url(source_id), api_url(target_id)
    payload = {"id": target_id, "destination_repository": "nuget-prod", "source_manifest_digest": source["stage"]["manifest_digest"]}
    if phase == "copy-denied":
        for token in [READ, PUBLISH, PROMOTE, PROD_PROMOTE]:
            status, body, _ = request(source_url + "/copy", token=token, data=payload)
            assert status == 403, (status, body)
        assert_hidden("nuget-prod")
    elif phase == "copy-pending":
        target = stage_info(target_id, COPY)
        assert target["stage"]["state"] == "sealed" and target["promotion"] is None, target
        lineage = target["copy"]
        assert lineage["source_stage"] == source_id and lineage["source_repository"] == "nuget-local" and lineage["actor"] == "copier", lineage
        assert lineage["destination"]["stage"]["id"] == target_id and lineage["destination"]["manifest_digest"] != payload["source_manifest_digest"], lineage
        source_files = {item["path"]: item["artifact"] for item in source["files"]}
        for item in target["files"]:
            summary = next(s for s in lineage["source_files"] if s["path"] == item["path"])
            assert item["artifact"]["digest"] == source_files[item["path"]]["digest"] == summary["subject"], item
            assert item["artifact"]["origin"] == BASE + "/r/nuget-prod/" + item["path"], item
            report = inspect_delivery(item["artifact"]["digest"], "nuget-prod")
            assert report["decision"]["state"] == "pending" and not report["evidence"], report
            assert report["configuration"] != summary["configuration"], report
            assert "fixture_review" in report["scopes"][0]["policy"]["policy"]["required"], report
            assert "policy" not in summary and "evidence" not in summary and summary["evidence_ids"], summary
        status, body, _ = request(source_url + "/copy", token=COPY, data=payload)
        assert status == 201 and json.loads(body) == lineage, (status, body)
        for token in [READ, PUBLISH, PROMOTE, COPY]:
            assert request(target_url + "/promote", token=token, data={"manifest_digest": target["stage"]["manifest_digest"]})[0] == 403
        status, body, _ = request(target_url + "/promote", token=PROD_PROMOTE, data={"manifest_digest": target["stage"]["manifest_digest"]})
        assert status == 409 and json.loads(body)["error"] == "release_not_approved", (status, body)
        for token in [READ, PUBLISH, PROMOTE, COPY, PROD_PROMOTE]:
            assert request(target_url + "/copy-evidence", token=token)[0] == 401
        status, full, _ = request(target_url + "/copy-evidence", token=ADMIN)
        assert status == 200 and all(item["evidence"] for item in json.loads(full)["source_files"]), (status, full)
        assert_hidden("nuget-prod")
    elif phase == "copy-promote":
        target = promote(target_id, PROD_PROMOTE)
        source_files = {item["path"]: item for item in target["copy"]["source_files"]}
        prior_ids = {identifier for item in source_files.values() for identifier in item["evidence_ids"]}
        assert target["promotion"]["actor"] == "prod-promoter", target
        for item in target["promotion"]["files"]:
            assert item["configuration"] != source_files[item["path"]]["configuration"], item
            assert "fixture_review" in item["policy"]["policy"]["required"], item
            assert not prior_ids.intersection(entry["id"] for entry in item["evidence"]), item
            review = [entry["document"] for entry in item["evidence"] if entry["document"]["check"] == "fixture_review"]
            assert len(review) == 1 and review[0]["outcome"] == "pass", item
            review = review[0]
            assert review["subject"] == item["subject"] and review["configuration"] == item["configuration"], review
            assert review["details"]["fixture_only"] is True and review["details"]["production_scope_matched"] is True, review
            assert review["details"]["binding_subject"] == item["subject"] and review["details"]["binding_configuration"] == item["configuration"], review
            assert datetime.datetime.fromisoformat(review["created_at"].replace("Z", "+00:00")) >= datetime.datetime.fromisoformat(target["copy"]["created_at"].replace("Z", "+00:00")), review
        proof = {"source_stage_id": source_id, "source_repository": "nuget-local", "source_manifest_digest": payload["source_manifest_digest"],
                 "stage_id": target_id, "repository": "nuget-prod", "manifest_digest": target["stage"]["manifest_digest"],
                 "coordinate": PACKAGE + "@" + VERSION, "files": published_bytes("nuget-prod", target), "same_bytes": "passed",
                 "fresh_destination_evidence": "passed", "stronger_policy": "passed", "review_adapter": "qualification_fixture_only",
                 "copy_roles": "passed", "source_evidence_privacy": "passed", "copy_replay": "passed", "quarantine": "passed"}
        print("PACKWEIR_NUGET_PROOF=" + json.dumps(proof, separators=(",", ":")), flush=True)
    elif phase == "revoke-source":
        status, body, _ = request(source_url + "/revoke", token=PROMOTE, data={"manifest_digest": payload["source_manifest_digest"]})
        assert status == 200, (status, body)
        assert_hidden("nuget-local")
        published_bytes("nuget-prod", stage_info(target_id, COPY))
        assert request(source_url + "/copy", token=COPY, data=dict(payload, id=str(uuid.uuid4())))[0] == 409
    elif phase == "revoke-target":
        target = stage_info(target_id, COPY)
        assert request(target_url + "/revoke", token=COPY, data={"manifest_digest": target["stage"]["manifest_digest"]})[0] == 403
        status, body, _ = request(target_url + "/revoke", token=PROD_PROMOTE, data={"manifest_digest": target["stage"]["manifest_digest"]})
        assert status == 200, (status, body)
        assert_hidden("nuget-local")
        assert_hidden("nuget-prod")
        assert_proxy_reservation()
        events = [json.loads(line) for line in Path("/fixtures/requests.jsonl").read_text().splitlines()]
        assert not any("packweir.private." in event["path"].lower() for event in events), events
    else:
        raise AssertionError("unknown NuGet phase: " + phase)


if __name__ == "__main__":
    run(*sys.argv[1:])
