"""Deterministic, local-only package registries. No package code or public registry is used."""
import base64
import csv
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import tarfile
import threading
import time
import urllib.parse
import zipfile
import s3

ROOT = Path("/fixtures")
ORIGIN = "http://upstream:8081"
FILES = {}
CATALOG = []
LOCK = threading.Lock()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(entries, zipped=False):
    output = io.BytesIO()
    if zipped:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as writer:
            for name, data in entries.items():
                writer.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data)
        return output.getvalue()
    with tarfile.open(fileobj=output, mode="w") as writer:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            writer.addfile(info, io.BytesIO(data))
    return gzip.compress(output.getvalue(), mtime=0)


def add(repo, path, data, content_type="application/octet-stream", wire=None):
    FILES[wire or f"/{repo}/{path}"] = (data, content_type)
    CATALOG.append({"repository": repo, "path": path, "digest": sha(data), "wire": wire or f"/{repo}/{path}"})


def document(path, data, content_type="application/json"):
    if not isinstance(data, bytes):
        data = json.dumps(data).encode()
    FILES[path] = (data, content_type)


def wrapped(target):
    return "_fetch/" + base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")


def fixtures():
    for name, filename in [("packweir-fixture", "packweir-fixture"), ("@packweir/fixture", "fixture")]:
        tarball = archive({"package/package.json": json.dumps({"name": name, "version": "1.0.0", "main": "index.js"}).encode(),
                           "package/index.js": b"module.exports = 'packweir-ok';\n"})
        path = f"{name}/-/{filename}-1.0.0.tgz"
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        add("npm", wrapped(f"{ORIGIN}/npm/{path}#sha512={integrity[7:]}"), tarball, wire=f"/npm/{path}")
        document(f"/npm/{name}", {"name": name, "dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {
            "name": name, "version": "1.0.0", "dist": {"tarball": f"{ORIGIN}/npm/{path}",
            "integrity": integrity}}}})

    entries = {"packweir_fixture/__init__.py": b"MARKER = 'packweir-ok'\n",
               "packweir_fixture-1.0.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: packweir-fixture\nVersion: 1.0.0\nLicense: MIT\n",
               "packweir_fixture-1.0.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: packweir-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    records = io.StringIO()
    writer = csv.writer(records, lineterminator="\n")
    for path, data in entries.items():
        writer.writerow([path, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="), len(data)])
    writer.writerow(["packweir_fixture-1.0.0.dist-info/RECORD", "", ""])
    entries["packweir_fixture-1.0.0.dist-info/RECORD"] = records.getvalue().encode()
    wheel = archive(entries, zipped=True)
    wheel_name = "packweir_fixture-1.0.0-py3-none-any.whl"
    add("pypi", wrapped(f"{ORIGIN}/pypi/packages/{wheel_name}#sha256={sha(wheel)}"), wheel, wire=f"/pypi/packages/{wheel_name}")
    document("/pypi/simple/packweir-fixture/", f'<a href="../../packages/{wheel_name}#sha256={sha(wheel)}">{wheel_name}</a>'.encode(), "text/html")
    (ROOT / "requirements.txt").write_text(f"packweir-fixture==1.0.0 --hash=sha256:{sha(wheel)}\n")

    crate = archive({"packweir-fixture-1.0.0/Cargo.toml": b'[package]\nname="packweir-fixture"\nversion="1.0.0"\nedition="2021"\n',
                     "packweir-fixture-1.0.0/src/lib.rs": b'pub fn marker() -> &\'static str { "packweir-ok" }\n'})
    add("cargo", "_cargo/packweir-fixture/1.0.0/download", crate, wire="/cargo/api/v1/crates/packweir-fixture/1.0.0/download")
    document("/cargo/pa/ck/packweir-fixture", {"name": "packweir-fixture", "vers": "1.0.0", "deps": [], "cksum": sha(crate), "features": {}, "yanked": False})

    for artifact, jar in [("fixture", "library.jar"), ("packweir-maven-plugin", "plugin.jar")]:
        prefix = f"dev/packweir/{artifact}/1.0.0/{artifact}-1.0.0"
        packaging = "maven-plugin" if artifact.endswith("plugin") else "jar"
        pom = f'<project><modelVersion>4.0.0</modelVersion><groupId>dev.packweir</groupId><artifactId>{artifact}</artifactId><version>1.0.0</version><packaging>{packaging}</packaging></project>'.encode()
        for extension, data in [("jar", (ROOT / "java" / jar).read_bytes()), ("pom", pom)]:
            path = f"{prefix}.{extension}"
            add("maven", path, data)
            document(f"/maven/{path}.sha1", hashlib.sha1(data).hexdigest().encode(), "text/plain")
            document(f"/maven/{path}.sha256", sha(data).encode(), "text/plain")

    nupkg = archive({"Packweir.Fixture.nuspec": b'<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>Packweir.Fixture</id><version>1.0.0</version><authors>Packweir</authors><description>Local qualification fixture</description><license type="expression">MIT</license></metadata></package>',
                     "contentFiles/any/any/fixture.txt": b"packweir fixture\n"}, zipped=True)
    add("nuget", "flat/packweir.fixture/1.0.0/packweir.fixture.1.0.0.nupkg", nupkg)
    document("/nuget/index.json", {"version": "3.0.0", "resources": [{"@id": ORIGIN + "/nuget/flat/", "@type": "PackageBaseAddress/3.0.0"}]})
    document("/nuget/flat/packweir.fixture/index.json", {"versions": ["1.0.0"]})
    bad = archive({"../escape": b"blocked fixture"})
    add("npm", "blocked/-/blocked-1.0.0.tgz", bad)
    CATALOG[-1]["denied"] = True
    (ROOT / "catalog.json").write_text(json.dumps(CATALOG))
    for item in CATALOG:
        (ROOT / (item["digest"] + ".bytes")).write_bytes(FILES[item["wire"]][0])


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if path == "/health":
            data, content_type, status = b"ok", "text/plain", 200
        else:
            leaked = bool(self.headers.get("Authorization"))
            with LOCK:
                with (ROOT / "requests.jsonl").open("a") as output:
                    output.write(json.dumps({"path": path, "authorization_received": leaked}) + "\n")
            if leaked:
                data, content_type, status = b"client credential leak", "text/plain", 500
            elif path in FILES:
                data, content_type = FILES[path]
                status = 200
            else:
                data, content_type, status = b"missing fixture", "text/plain", 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    if os.environ.get("STORAGE") == "s3":
        for attempt in range(90):
            try:
                status, body = s3.request("PUT", "/packweir")
                if status in (200, 409):
                    break
            except OSError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("S3 fixture bucket could not be created")
    fixtures()
    http.server.ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
