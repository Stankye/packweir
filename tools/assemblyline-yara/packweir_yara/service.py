"""A real Assemblyline SDK service that runs the pinned YARA native engine.

The always-present execution section retains genuine SDK milestones for a
completed no-match scan. It avoids Assemblyline's intentionally lossy empty
result cache representation without inventing execution timestamps.
"""

import hashlib
import importlib.metadata
import json
from pathlib import Path

import yara
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import ResultSection

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RULE_BYTES = 64 * 1024
MATCH_TIMEOUT_SECONDS = 10
ENGINE_VERSION = "4.5.4"
RULE_PATH = Path(__file__).with_name("qualification.yar")
DRIVER_FILES = ("__init__.py", "service.py")


def driver_sha256():
    digest = hashlib.sha256()
    for name in DRIVER_FILES:
        data = Path(__file__).with_name(name).read_bytes()
        digest.update(name.encode("ascii") + b"\0" + len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


class PackweirYARA(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config=config)
        # The real SDK queries tool identity before start_service().
        self.binding_version = importlib.metadata.version("yara-python")
        self.engine_version = yara.YARA_VERSION
        if self.binding_version != ENGINE_VERSION or self.engine_version != ENGINE_VERSION:
            raise RuntimeError("YARA binding or native engine differs from the qualified pin")
        rule_bytes = RULE_PATH.read_bytes()
        if not rule_bytes or len(rule_bytes) > MAX_RULE_BYTES:
            raise RuntimeError("YARA rules are empty or exceed the qualified bound")
        self.rule_sha256 = hashlib.sha256(rule_bytes).hexdigest()
        self.driver_sha256 = driver_sha256()
        # Includes are disabled: this rule resource is the complete rule input.
        self.rules = yara.compile(source=rule_bytes.decode("utf-8"), includes=False, error_on_warning=True)

    def get_tool_version(self):
        return f"yara-python/{self.binding_version}.yara/{self.engine_version}.rules/{self.rule_sha256}.driver/{self.driver_sha256}"

    def execute(self, request):
        # Read a bounded snapshot, verify its actual digest, and scan those same
        # bytes. No package paths, interpreters, build tools, or subprocesses run.
        with open(request.file_path, "rb") as source:
            file_bytes = source.read(MAX_FILE_BYTES + 1)
        if len(file_bytes) > MAX_FILE_BYTES:
            raise ValueError("input exceeds the qualified 16 MiB YARA scan bound")
        actual_sha256 = hashlib.sha256(file_bytes).hexdigest()
        if actual_sha256 != request.sha256:
            raise ValueError("input SHA256 differs from the Assemblyline task")
        matches = self.rules.match(data=file_bytes, timeout=MATCH_TIMEOUT_SECONDS)
        execution = ResultSection("Completed bounded YARA static scan")
        execution.add_line(json.dumps({
            "engine": "YARA",
            "engine_version": self.engine_version,
            "binding": "yara-python",
            "binding_version": self.binding_version,
            "rules_sha256": self.rule_sha256,
            "driver_sha256": self.driver_sha256,
            "input_sha256": actual_sha256,
            "input_size": len(file_bytes),
            "scan_scope": "qualification_marker_rule",
            "matching_rules": sorted(match.rule for match in matches),
        }, sort_keys=True))
        request.result.add_section(execution)
        for match in matches:
            finding = ResultSection(f"YARA rule matched: {match.rule}")
            finding.add_line("A harmless integration qualification marker matched the actual YARA engine.")
            finding.set_heuristic(1, signature=match.rule)
            request.result.add_section(finding)
