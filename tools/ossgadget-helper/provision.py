#!/usr/bin/env python3
"""Acquire the pinned Microsoft release at installation time; never used by scanning."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import urllib.request
import zipfile


def fetch(url, digest, limit):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"size or digest mismatch: {url}")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--package", type=Path, help="use an already acquired, hash-verified nupkg")
    parser.add_argument("--rules-directory", type=Path, help="use already acquired pinned source rules")
    args = parser.parse_args()
    lock = json.loads(Path(__file__).with_name("provision.lock.json").read_text())
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("destination must be empty; installation never replaces existing files")
    version = lock["package_version"]
    url = f"https://api.nuget.org/v3-flatcontainer/microsoft.cst.ossgadget.cli/{version}/microsoft.cst.ossgadget.cli.{version}.nupkg"
    package = args.package.read_bytes() if args.package else fetch(url, lock["package_sha256"], 32 * 1024 * 1024)
    if len(package) > 32 * 1024 * 1024 or hashlib.sha256(package).hexdigest() != lock["package_sha256"]:
        raise ValueError("package size or digest mismatch")
    pins = {}

    def write(name, content):
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in (".", "..") for part in path.parts) or "\\" in name or ":" in name:
            raise ValueError("unsafe deployment path")
        if name in pins:
            raise ValueError("duplicate deployment path")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        pins[name] = hashlib.sha256(content).hexdigest()

    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        entries = archive.infolist()
        if len(entries) > 512 or sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
            raise ValueError("package expansion limit exceeded")
        prefix = "tools/net8.0/any/"
        for entry in entries:
            if not entry.is_dir() and entry.filename.startswith(prefix):
                write(entry.filename[len(prefix):], archive.read(entry))
        write("LICENSE.OSSGadget.txt", archive.read("LICENSE.txt"))
    revision = lock["source_revision"]
    for name, digest in lock["backdoor_rules"].items():
        url = f"https://raw.githubusercontent.com/microsoft/OSSGadget/{revision}/src/Shared.CLI/Resources/BackdoorRules/{name}"
        content = (args.rules_directory / name).read_bytes() if args.rules_directory else fetch(url, digest, 1024 * 1024)
        if len(content) > 1024 * 1024 or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError(f"rule size or digest mismatch: {name}")
        write(f"Resources/BackdoorRules/{name}", content)
    manifest = {"package_version": version, "package_sha256": lock["package_sha256"], "source_revision": revision, "files": dict(sorted(pins.items()))}
    (destination / ".pins.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    print(json.dumps({"destination": str(destination), "files": len(pins), "package_sha256": lock["package_sha256"]}))


if __name__ == "__main__":
    main()
