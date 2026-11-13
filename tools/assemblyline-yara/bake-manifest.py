"""Bake the installed engine/rules/driver identity into the supported SDK field."""
import json
import re
from pathlib import Path

from packweir_yara.service import identity_tool_version, runtime_identity


path = Path("/opt/al_service/service_manifest.yml")
manifest = path.read_text()
if re.search(r"^tool_version\s*:", manifest, re.MULTILINE):
    raise RuntimeError("source manifest must not contain a stale generated tool version")
identity, _ = runtime_identity()
tool_version = identity_tool_version(identity)
path.write_text(manifest.rstrip() + "\ntool_version: " + json.dumps(tool_version) + "\n")
path.chmod(0o644)
print("Baked YARA tool identity " + tool_version)
