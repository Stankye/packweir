"""Corrupt and restore a test-owned retained blob; no host paths or production data."""
import json
import os
from pathlib import Path
from probe import request, route
import s3

item = json.loads(Path("/fixtures/catalog.json").read_text())[0]
digest = item["digest"]
key = f"blobs/sha256/{digest[:2]}/{digest}"
original = Path(f"/fixtures/{digest}.bytes").read_bytes()
path = Path("/data") / key
using_s3 = os.environ["STORAGE"] == "s3"


def write(data):
    if using_s3:
        status, body = s3.request("PUT", "/packweir/" + key, data)
        assert status == 200, (status, body)
    else:
        path.write_bytes(data)


try:
    status, body, _ = request(route(item))
    assert status == 200 and body == original, "approved retained bytes must work with upstream stopped"
    corrupt = b"tampered test-owned blob"
    write(corrupt)
    status, body, _ = request(route(item))
    assert status >= 400 and body != original and corrupt not in body, (status, body)
finally:
    write(original)
assert request(route(item))[0] == 200
print("retained blob tampering rejected and original restored", flush=True)
