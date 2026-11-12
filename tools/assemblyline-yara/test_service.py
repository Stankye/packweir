"""Exercise the actual native engine through real SDK tasks, without a server.

Run in the built service image, with this directory mounted read-only at /source
and the qualified instance classification.yml mounted at /etc/assemblyline.
These tests do not claim live server or dispatcher qualification.
"""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.task import Task as ServiceTask
from packweir_yara.service import MAX_FILE_BYTES, PackweirYARA


class RealSDKAndYaraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = PackweirYARA()
        # This call order is the one used by the actual SDK run_service module.
        cls.tool_version = cls.service.get_tool_version()
        source_directory = Path(__file__).resolve().parent / "packweir_yara"
        identity = hashlib.sha256()
        for name in ["__init__.py", "service.py"]:
            data = (source_directory / name).read_bytes()
            identity.update(name.encode("ascii"))
            identity.update(b"\0")
            identity.update(len(data).to_bytes(8, "big"))
            identity.update(data)
        cls.expected_driver_sha256 = identity.hexdigest()
        assert cls.tool_version.endswith(".driver/" + cls.expected_driver_sha256)
        assert len(cls.tool_version) < 256
        cls.service.start_service()
        cls.identify = forge.get_identify(use_cache=False)

    def run_task(self, data, expected_error=False):
        with tempfile.TemporaryDirectory() as directory:
            os.environ["TASKING_DIR"] = directory
            digest = hashlib.sha256(data).hexdigest()
            file_path = Path(directory) / digest
            file_path.write_bytes(data)
            info = self.identify.fileinfo(str(file_path), skip_fuzzy_hashes=True, calculate_entropy=False)
            for field in ["ascii", "hex", "entropy"]:
                info.pop(field, None)
            task = ServiceTask({
                "sid": get_random_id(),
                "metadata": {},
                "service_name": "PackweirYARA",
                "service_config": {},
                "fileinfo": info,
                "filename": "harmless-qualification.txt",
                "min_classification": forge.get_classification().UNRESTRICTED,
                "max_files": 255,
                "ttl": 1,
            })
            self.service.handle_task(task)
            prefix = Path(directory) / f"{task.sid}_{digest}"
            result_path = Path(str(prefix) + "_result.json")
            error_path = Path(str(prefix) + "_error.json")
            if expected_error:
                self.assertFalse(result_path.exists())
                self.assertTrue(error_path.exists())
                error = json.loads(error_path.read_text())
                self.assertEqual(error["response"]["status"], "FAIL_NONRECOVERABLE")
                return error
            self.assertFalse(error_path.exists())
            result = json.loads(result_path.read_text())
            self.assertEqual(result["sha256"], digest)
            self.assertEqual(result["response"]["service_tool_version"], self.tool_version)
            self.assertTrue(result["response"]["milestones"]["service_started"])
            self.assertTrue(result["response"]["milestones"]["service_completed"])
            self.assertFalse(result["partial"])
            self.assertFalse(result["drop_file"])
            execution = json.loads(result["result"]["sections"][0]["body"])
            self.assertEqual(execution["input_sha256"], digest)
            self.assertEqual(execution["input_size"], len(data))
            self.assertEqual(execution["engine_version"], "4.5.4")
            self.assertEqual(execution["driver_sha256"], self.expected_driver_sha256)
            return result

    def test_actual_no_match_retains_execution_section(self):
        result = self.run_task(b"Packweir real Assemblyline qualification benign text.\n")
        self.assertEqual(len(result["result"]["sections"]), 1)
        self.assertIsNone(result["result"]["sections"][0]["heuristic"])
        self.assertEqual(json.loads(result["result"]["sections"][0]["body"])["matching_rules"], [])

    def test_actual_rule_match_is_attributable(self):
        result = self.run_task(b"PACKWEIR_ASSEMBLYLINE_HARMLESS_MARKER_V1\n")
        self.assertEqual(len(result["result"]["sections"]), 2)
        self.assertEqual(json.loads(result["result"]["sections"][0]["body"])["matching_rules"], ["PackweirQualificationMarker"])
        heuristic = result["result"]["sections"][1]["heuristic"]
        self.assertEqual(heuristic["heur_id"], 1)
        self.assertEqual(heuristic["signatures"], {"PackweirQualificationMarker": 1})

    def test_oversize_input_is_a_real_sdk_error(self):
        error = self.run_task(b"x" * (MAX_FILE_BYTES + 1), expected_error=True)
        self.assertIn("qualified 16 MiB", error["response"]["message"])


if __name__ == "__main__":
    unittest.main()
