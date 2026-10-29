"""Small SigV4 helper for test-owned RustFS objects; no external SDK dependency."""
import datetime
import hashlib
import hmac
import urllib.error
import urllib.request

ENDPOINT = "http://object-store:9000"
ACCESS = "fixture-access-key"
SECRET = "fixture-secret-key-000000000000000"


def request(method, path, data=b""):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload = hashlib.sha256(data).hexdigest()
    headers = {"host": "object-store:9000", "x-amz-content-sha256": payload, "x-amz-date": timestamp}
    signed = ";".join(sorted(headers))
    canonical_headers = "".join(f"{key}:{headers[key]}\n" for key in sorted(headers))
    canonical = "\n".join([method, path, "", canonical_headers, signed, payload])
    scope = f"{date}/us-east-1/s3/aws4_request"
    string = "\n".join(["AWS4-HMAC-SHA256", timestamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + SECRET).encode()
    for part in [date, "us-east-1", "s3", "aws4_request"]:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, SignedHeaders={signed}, Signature={signature}"
    body = data if method in ("PUT", "POST") else None
    req = urllib.request.Request(ENDPOINT + path, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
