"""Bake the immutable producer identity into the SDK's supported tool_version."""
from pathlib import Path
import json
import re
import sys

sys.path.insert(0, "/opt/packweir-ghidra")
import runtime

path = Path("/opt/al_service/service_manifest.yml")
manifest = path.read_text()
if re.search(r"^tool_version\s*:", manifest, re.MULTILINE):
    raise RuntimeError("source manifest must not contain a stale generated tool version")
identity = runtime.producer()
tool_version = "ghidra/12.2.identity/" + identity["identity_sha256"]
path.write_text(manifest.rstrip() + "\ntool_version: " + json.dumps(tool_version) + "\n")
path.chmod(0o644)
print("Baked Ghidra producer identity " + identity["identity_sha256"])
