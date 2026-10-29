"""Frontend-only policy, byte-integrity, and topology assertions."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.request

BASE = "http://gateway:8080"
READ = os.environ["PACKWEIR_READ_TOKEN"]
ADMIN = os.environ.get("PACKWEIR_ADMIN_TOKEN", "")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, token=READ, data=None, headers=None):
    values = dict(headers or {})
    if token:
        values["Authorization"] = "Bearer " + token
    if data is not None:
        data = json.dumps(data).encode()
        values["Content-Type"] = "application/json"
    try:
        with OPENER.open(urllib.request.Request(BASE + path, data=data, headers=values), timeout=10) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def route(item):
    return f"/r/{item['repository']}/{item['path']}"


def main():
    phase = sys.argv[1]
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
