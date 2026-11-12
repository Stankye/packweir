#!/usr/bin/env python3
"""Create the exact deployment file manifest to pin before the .NET host loads code."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment", type=Path)
    args = parser.parse_args()
    root = args.deployment.resolve(strict=True)
    manifest = root / "deployment-manifest.json"
    files = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("deployment links are unsupported")
        if not path.is_file() or path == manifest:
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in (".", "..") for part in path.relative_to(root).parts) or ":" in relative or "\\" in relative:
            raise ValueError("unsafe deployment path")
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("deployment file exceeds 8MiB")
        content = path.read_bytes()
        total += len(content)
        if len(content) > 8 * 1024 * 1024 or total > 64 * 1024 * 1024 or len(files) >= 512:
            raise ValueError("deployment exceeds 8MiB/file, 64MiB total, or 512 files")
        files[relative] = hashlib.sha256(content).hexdigest()
    for required in ("packweir-ossgadget-helper.dll", "packweir-ossgadget-helper.deps.json", "packweir-ossgadget-helper.runtimeconfig.json", "upstream/ApplicationInspector.Commands.dll"):
        if required not in files:
            raise ValueError(f"required deployment file missing: {required}")
    value = {"protocol_version": 1, "entrypoint": "packweir-ossgadget-helper.dll", "files": files}
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    manifest.write_bytes(content)
    print(json.dumps({"manifest": str(manifest), "sha256": hashlib.sha256(content).hexdigest(), "files": len(files), "bytes": total}))


if __name__ == "__main__":
    main()
