#!/usr/bin/env python3
"""Acquire exact official Ghidra/JDK release assets without executing them."""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK = json.loads((HERE / "upstream.lock.json").read_text(encoding="utf-8"))


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(4 * 1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def metadata(pin, output, name):
    request = urllib.request.Request(pin["release_api"], headers={"User-Agent": "packweir-ghidra-provision", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("official release metadata exceeds bound")
    (output / (name + "-release.json")).write_bytes(raw)
    value = json.loads(raw)
    assets = [asset for asset in value["assets"] if asset["name"] == pin["asset"]]
    if (value["tag_name"] != pin["tag"] or len(assets) != 1 or assets[0]["size"] != pin["size"]
            or assets[0].get("digest") != "sha256:" + pin["sha256"]
            or assets[0]["browser_download_url"] != pin["url"]):
        raise RuntimeError("official release metadata differs from the reviewed pin: " + name)
    return {"release_metadata_sha256": hashlib.sha256(raw).hexdigest(), "published_at": value["published_at"]}


def asset(pin, output, name):
    proof = metadata(pin, output, name)
    target = output / pin["asset"]
    cached = target.is_file() and target.stat().st_size == pin["size"] and sha256(target) == pin["sha256"]
    if not cached:
        partial = output / (pin["asset"] + ".part")
        deadline = time.monotonic() + 1200
        request = urllib.request.Request(pin["url"], headers={"User-Agent": "packweir-ghidra-provision"})
        total, hashed = 0, hashlib.sha256()
        print("Downloading official " + name + " (" + str(pin["size"]) + " bytes)", flush=True)
        with urllib.request.urlopen(request, timeout=90) as response, partial.open("wb") as destination:
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("asset acquisition deadline exceeded: " + name)
                part = response.read(4 * 1024 * 1024)
                if not part:
                    break
                total += len(part)
                if total > pin["size"]:
                    raise RuntimeError("upstream asset exceeded exact reviewed size: " + name)
                hashed.update(part)
                destination.write(part)
        if total != pin["size"] or hashed.hexdigest() != pin["sha256"]:
            raise RuntimeError("upstream asset failed size/SHA256 authentication: " + name)
        partial.replace(target)
    proof.update({"asset": pin["asset"], "size": pin["size"], "sha256": pin["sha256"], "cached": cached,
                  "authentication": pin["authentication"]})
    return name, proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/ghidra/upstream-assets")
    options = parser.parse_args()
    output = options.output.resolve()
    target = (ROOT / "target").resolve()
    if output == target or target not in output.parents:
        parser.error("output must be a child of this workspace's ignored target directory")
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "lock_sha256": sha256(HERE / "upstream.lock.json"), "assets": {}}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            tasks = [executor.submit(asset, LOCK[name], output, name) for name in ("ghidra", "jdk")]
            for task in concurrent.futures.as_completed(tasks):
                name, proof = task.result()
                report["assets"][name] = proof
                print("Authenticated " + name + " " + proof["sha256"], flush=True)
        report["status"] = "prepared"
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "provision.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
