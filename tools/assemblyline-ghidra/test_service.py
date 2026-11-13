"""Run real SDK tasks and real Ghidra; generated native inputs are never executed.

Mount trusted fixtures at /fixtures, this file at /test_service.py, and an output
directory at /qualification. These are local SDK tests, not a server simulation.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.helper import get_service_manifest
from packweir_ghidra.service import MAX_FILE_BYTES, PackweirGhidra, TITLE
import runtime

FIXTURES = Path(os.environ.get("GHIDRA_SMOKE_FIXTURES", "/fixtures"))
OUTPUT = Path(os.environ.get("GHIDRA_SMOKE_OUTPUT", "/qualification"))


class InstrumentedService(PackweirGhidra):
    """Trusted qualification subclass; production SDK has no fault request flag."""
    fault_mode = None

    def analyze_file(self, file_path, expected_sha256):
        return runtime.analyze(file_path, expected_sha256, fault_mode=self.fault_mode,
                               retain_directory=OUTPUT / self.case / "headless")


class RealSDKAndGhidraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads((FIXTURES / "fixtures.json").read_text())
        cls.service = InstrumentedService()
        cls.service.start_service()
        assert get_service_manifest()["tool_version"] == cls.service.get_tool_version()
        cls.identify = forge.get_identify(use_cache=False)
        OUTPUT.mkdir(parents=True, exist_ok=True)
        (OUTPUT / "producer.json").write_text(json.dumps(cls.service.producer, indent=2) + "\n")

    def run_task(self, data, case, *, fault=None, expected_error=False):
        self.service.fault_mode, self.service.case = fault, case
        directory = OUTPUT / case
        directory.mkdir(parents=True, exist_ok=False)
        if len(data) <= MAX_FILE_BYTES: (directory / "input.bin").write_bytes(data)
        with tempfile.TemporaryDirectory() as tasking:
            os.environ["TASKING_DIR"] = tasking
            digest = hashlib.sha256(data).hexdigest()
            path = Path(tasking) / digest
            path.write_bytes(data)
            info = self.identify.fileinfo(str(path), skip_fuzzy_hashes=True, calculate_entropy=False)
            for field in ("ascii", "hex", "entropy"): info.pop(field, None)
            task = ServiceTask({"sid": get_random_id(), "metadata": {}, "service_name": "PackweirGhidra",
                "service_config": {}, "fileinfo": info, "filename": case + ".bin",
                "min_classification": forge.get_classification().UNRESTRICTED, "max_files": 255, "ttl": 1})
            self.service.handle_task(task)
            prefix = Path(tasking) / (task.sid + "_" + digest)
            result_path, error_path = Path(str(prefix) + "_result.json"), Path(str(prefix) + "_error.json")
            if expected_error:
                self.assertFalse(result_path.exists())
                error = json.loads(error_path.read_bytes())
                (directory / "sdk-error.json").write_bytes(error_path.read_bytes())
                self.assertEqual(error["response"]["status"], "FAIL_NONRECOVERABLE")
                return error
            self.assertFalse(error_path.exists())
            result = json.loads(result_path.read_bytes())
            (directory / "sdk-result.json").write_bytes(result_path.read_bytes())
            self.assertEqual(result["sha256"], digest)
            self.assertEqual(result["response"]["service_tool_version"], self.service.get_tool_version())
            self.assertTrue(result["response"]["milestones"]["service_started"])
            self.assertTrue(result["response"]["milestones"]["service_completed"])
            section = result["result"]["sections"][0]
            self.assertEqual(section["title_text"], TITLE)
            report = json.loads(section["body"])
            self.assertEqual(report["input"]["sha256"], digest)
            self.assertEqual(report["producer"], self.service.producer)
            self.assertEqual(result["partial"], report["analysis"]["status"] != "complete")
            self.assertFalse(result["drop_file"])
            for child in result["response"]["extracted"]:
                decoded = Path(child["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(decoded).hexdigest(), child["sha256"])
                self.assertEqual(child["parent_relation"], "EXTRACTED")
                self.assertFalse(child["allow_dynamic_recursion"])
                (directory / (child["sha256"] + ".bin")).write_bytes(decoded)
            (directory / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
            return result, report

    def fixture(self, name):
        record = self.fixtures["fixtures"][name]
        data = (FIXTURES / record["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
        return data

    def test_four_real_compiled_inputs(self):
        for name in ("benign-elf64", "encoded-elf64", "benign-pe32plus", "encoded-pe32plus"):
            with self.subTest(name=name):
                result, report = self.run_task(self.fixture(name), name)
                self.assertEqual(report["analysis"]["status"], "complete", report["analysis"])
                self.assertEqual(report["analysis"]["functions_total"], 3)
                self.assertEqual(report["analysis"]["functions_decompiled"], 3)
                self.assertEqual(report["analysis"]["functions_failed"], 0)
                self.assertEqual(report["analysis"]["errors"], [])
                pcode = b"\n".join(base64.b64decode(item["data_base64"]) for item in report["outputs"] if item["kind"] == "pcode")
                self.assertIn(b"INT_XOR", pcode)
                children = result["response"]["extracted"]
                if name.startswith("encoded"):
                    self.assertEqual(len(children), 1)
                    expected = self.fixtures["decoded_expected"]["sha256"]
                    self.assertEqual(children[0]["sha256"], expected)
                    self.assertEqual([item["sha256"] for item in report["outputs"] if item["kind"] == "decoded_bytes"], [expected])
                else: self.assertEqual(children, [])

    def test_real_analyzer_throws_even_with_exit_zero(self):
        _, report = self.run_task(self.fixture("encoded-elf64"), "analyzer-throw", fault="throw")
        self.assertEqual(report["analysis"]["status"], "incomplete")
        self.assertTrue(any("PACKWEIR_QUALIFICATION_REAL_ANALYZER_THROW" in error for error in report["analysis"]["errors"]))
        notes = {item["name"]: item["value"] for item in report["observations"] if item["kind"] == "note"}
        self.assertEqual(notes["actual_headless_exit_code"], "0")
        self.assertEqual(notes["process_group_live_pids_after_stop"], "0")

    def test_real_deadline_kills_process_group(self):
        # Exercise actual repeated launch/SIGKILL races, not a synthetic process
        # list. Every descendant must acknowledge death within the drain bound.
        for attempt in range(5):
            with self.subTest(attempt=attempt):
                case = "process-deadline" if attempt == 0 else "process-deadline-repeat-" + str(attempt)
                _, report = self.run_task(self.fixture("encoded-elf64"), case, fault="deadline")
                self.assertEqual(report["analysis"]["status"], "incomplete")
                self.assertTrue(report["analysis"]["timed_out"])
                notes = {item["name"]: item["value"] for item in report["observations"] if item["kind"] == "note"}
                self.assertEqual(notes["actual_headless_exit_code"], "-9")
                self.assertEqual(notes["process_group_live_pids_after_stop"], "0")
                self.assertLess(float(notes["process_group_stop_wait_seconds"]), 3)

    def test_logged_analyzer_failure_before_ghidra_clears_it(self):
        _, report = self.run_task(self.fixture("encoded-elf64"), "analyzer-logged-failure", fault="logged_failure")
        self.assertEqual(report["analysis"]["status"], "incomplete")
        self.assertEqual(report["analysis"]["functions_decompiled"], 3)
        self.assertTrue(any("Ghidra internal analysis MessageLog:" in value and "PACKWEIR_QUALIFICATION_REAL_ANALYZER_LOGGED_FAILURE" in value
                            for value in report["analysis"]["errors"]))
        notes = {item["name"]: item["value"] for item in report["observations"] if item["kind"] == "note"}
        self.assertEqual(notes["actual_headless_exit_code"], "0")
        self.assertEqual(notes["process_group_live_pids_after_stop"], "0")

    def test_unsupported_is_an_actual_partial_sdk_result(self):
        result, report = self.run_task(b"\0asm\x01\0\0\0", "unsupported-wasm")
        self.assertEqual(report["analysis"]["status"], "unsupported")
        self.assertEqual(report["analysis"]["functions_total"], 0)
        self.assertEqual(result["response"]["extracted"], [])

    def test_oversize_is_a_real_sdk_error(self):
        error = self.run_task(b"x" * (MAX_FILE_BYTES + 1), "oversize", expected_error=True)
        self.assertIn("qualified 16 MiB", error["response"]["message"])


if __name__ == "__main__": unittest.main(verbosity=2)
