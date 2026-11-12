"""Exercise evidence CAS export/import/readback through the real gateway storage backend."""
import base64
import hashlib
import json
import sys

from probe import ADMIN, READ, request


def decode(value):
    content = base64.b64decode(value, validate=True)
    assert base64.b64encode(content).decode() == value
    return content


def get(path):
    status, body, headers = request(path, token=ADMIN)
    assert status == 200, (path, status, body)
    return json.loads(body), headers


def authority(report):
    # Explanatory ages can advance; policy inputs and decisions must stay identical.
    return {key: report[key] for key in (
        "configuration", "engine_configuration", "decision", "evidence", "documents", "identities"
    )} | {"scope_decisions": [
        {key: scope[key] for key in ("scope", "configuration", "policy", "decision")}
        for scope in report["scopes"]
    ]}


def main():
    subject = sys.argv[1]
    prefix = f"/api/v1/artifacts/{subject}"
    before, _ = get(prefix)
    assert before["decision"]["state"] == "approved", before
    assert len(before["documents"]) >= 3, before
    assert all(document["origin"] == "artifact_observed" for document in before["documents"])
    for token in (None, READ):
        assert request(prefix + "/evidence-export", token=token)[0] == 401
    transfer, headers = get(prefix + "/evidence-export")
    assert headers["Cache-Control"] == "no-store"
    raw_manifest = decode(transfer["manifest"])
    manifest_digest = "sha256:" + hashlib.sha256(raw_manifest).hexdigest()
    assert transfer["manifest_digest"] == manifest_digest
    manifest = json.loads(raw_manifest)
    assert manifest["schemaVersion"] == 2
    assert manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
    assert manifest["artifactType"] == "application/vnd.packweir.evidence.v1"
    assert "subject" not in manifest
    assert manifest["config"]["mediaType"] == "application/vnd.oci.empty.v1+json"
    assert manifest["layers"][0]["mediaType"] == "application/vnd.packweir.evidence-envelope.v1+json"
    decoded = {}
    for descriptor in [manifest["config"], *manifest["layers"]]:
        content = decode(transfer["blobs"][descriptor["digest"]])
        assert len(content) == descriptor["size"]
        assert "sha256:" + hashlib.sha256(content).hexdigest() == descriptor["digest"]
        decoded[descriptor["digest"]] = content
    assert decoded[manifest["config"]["digest"]] == b"{}"
    envelope = json.loads(decoded[manifest["layers"][0]["digest"]])
    assert envelope["schema_version"] == 1 and envelope["subject"] == subject
    documents = envelope["documents"]
    assert len(documents) >= 3
    assert documents == [{key: descriptor[key] for key in ("mediaType", "digest", "size")}
                         for descriptor in manifest["layers"][1:]]
    expected_digests = {document["blob_digest"] for document in before["documents"]}
    assert {document["digest"].removeprefix("sha256:") for document in documents} == expected_digests
    assert {document["blob_digest"] for document in envelope["snapshot"]["documents"]} == expected_digests
    for document in documents:
        assert document["mediaType"] == "application/json"
        digest = document["digest"].removeprefix("sha256:")
        status, content, _ = request(prefix + "/documents/" + digest, token=ADMIN)
        assert status == 200 and content == decoded[document["digest"]], (status, digest)
        json.loads(content)
    status, body, _ = request(prefix + "/evidence-import", token=ADMIN, data=transfer)
    assert status == 201, (status, body)
    receipt = json.loads(body)
    assert receipt["subject"] == subject and receipt["manifest_digest"] == manifest_digest
    assert receipt["verified"] is False and receipt["trust_status"] == "unverified"
    assert receipt["approval_effect"] == "none"
    imported = prefix + "/evidence-imports/" + receipt["id"]
    stored_receipt, _ = get(imported)
    assert stored_receipt == receipt
    readback, headers = get(imported + "/export")
    assert headers["Cache-Control"] == "no-store"
    assert readback == transfer, "CAS readback must preserve every exact base64 byte sequence and root digest"
    listing, _ = get(prefix + "/evidence-imports")
    assert any(item["id"] == receipt["id"] and item["manifest_digest"] == manifest_digest
               and item["verified"] is False for item in listing["imports"])
    status, body, _ = request(prefix + "/evidence-import", token=ADMIN, data=transfer)
    assert status == 200 and json.loads(body) == receipt, (status, body)
    after, _ = get(prefix)
    assert authority(after) == authority(before), "foreign import must not alter local policy authority"
    proof = {
        "status": "passed", "subject": subject, "manifest_digest": manifest_digest,
        "import_id": receipt["id"], "document_count": len(documents),
        "document_sha256": sorted(expected_digests), "exact_document_api_bytes": "passed",
        "exact_import_readback": "passed", "idempotent_import": "passed",
        "verified": False, "trust_status": "unverified", "approval_effect": "none",
        "local_decisions_unchanged": "passed", "export_admin_only": "passed",
    }
    print("PACKWEIR_EVIDENCE_PROOF=" + json.dumps(proof, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
