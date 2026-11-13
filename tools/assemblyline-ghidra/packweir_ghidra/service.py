"""Actual Assemblyline SDK bridge to the isolated Ghidra static analyzer."""
import base64
import hashlib
import json
from pathlib import Path
import sys

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.helper import get_service_manifest
from assemblyline_v4_service.common.result import ResultSection

sys.path.insert(0, "/opt/packweir-ghidra")
import runtime

MAX_FILE_BYTES = 16 * 1024 * 1024
TITLE = "Packweir binary analysis manifest v1"


class PackweirGhidra(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config=config)
        self.producer = runtime.producer()
        if get_service_manifest().get("tool_version") != self.get_tool_version():
            raise RuntimeError("baked SDK tool version differs from actual immutable Ghidra producer")

    def get_tool_version(self):
        return "ghidra/12.2.identity/" + self.producer["identity_sha256"]

    def analyze_file(self, file_path, expected_sha256):
        return runtime.analyze(file_path, expected_sha256)

    def execute(self, request):
        with open(request.file_path, "rb") as source:
            data = source.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES: raise ValueError("input exceeds qualified 16 MiB Ghidra bound")
        if hashlib.sha256(data).hexdigest() != request.sha256: raise ValueError("actual input SHA256 differs from SDK task")
        report = self.analyze_file(request.file_path, request.sha256)
        if report["producer"] != self.producer: raise RuntimeError("actual Ghidra producer changed after service initialization")
        decoded = [item for item in report["outputs"] if item["kind"] == "decoded_bytes"]
        if len(decoded) > 8: raise RuntimeError("decoded-child count exceeds qualified bound")
        if report["analysis"]["status"] != "complete": request.partial()
        extracted_hashes = set()
        for item in decoded:
            content = base64.b64decode(item["data_base64"], validate=True)
            if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise RuntimeError("actual decoded child identity differs")
            # Preserve all typed derivations in the manifest. The SDK graph
            # needs only one parent/child edge for identical decoded bytes.
            if item["sha256"] in extracted_hashes:
                continue
            extracted_hashes.add(item["sha256"])
            path = Path(self.working_directory) / ("decoded-" + item["sha256"])
            path.write_bytes(content)
            if not request.add_extracted(str(path), path.name + ".bin", "File-backed constant-XOR derivation; provenance is in the manifest"):
                request.partial()
                report["analysis"]["status"] = "incomplete"
                report["analysis"]["errors"].append("SDK did not retain the verified decoded child")
        section = ResultSection(TITLE)
        section.add_line(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        request.result.add_section(section, on_top=True)
