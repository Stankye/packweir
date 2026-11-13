"""Actual Ghidra process failures and trusted-profile XOR qualification.

Run only as root in a disposable, owned, bounded image container. The analysis
child runs as the real assemblyline user. Mode/profile mutations are restored in
finally blocks. This file is never copied into the production service image.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import unittest

BASE = Path("/opt/packweir-ghidra")
OUTPUT = Path(os.environ.get("GHIDRA_SMOKE_OUTPUT", "/qualification"))
FIXTURES = Path(os.environ.get("GHIDRA_SMOKE_FIXTURES", "/fixtures"))
PROFILE = BASE / "profile.json"
NATIVE = Path("/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile")
CATALOG = Path("/opt/ghidra/Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn")
MANIFEST = Path("/opt/al_service/service_manifest.yml")


def digest(data): return hashlib.sha256(data).hexdigest()


class ActualRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0: raise RuntimeError("qualification requires an owned disposable container root")
        cls.account = pwd.getpwnam("assemblyline")
        cls.original_profile = PROFILE.read_bytes()
        cls.fixtures = json.loads((FIXTURES / "fixtures.json").read_bytes())
        OUTPUT.mkdir(parents=True, exist_ok=True)

    def run_analysis(self, case, data, profile=None, sdk=False):
        destination = OUTPUT / case
        destination.mkdir(exist_ok=False)
        destination.chmod(0o777)
        source = destination / "input.bin"
        source.write_bytes(data)
        expected = digest(data)
        original_manifest = MANIFEST.read_bytes()
        if profile is not None: PROFILE.write_text(json.dumps(profile, indent=2) + "\n")
        # Trusted static Python, not bytes or instructions supplied by the subject.
        code = "import json,sys; from pathlib import Path; sys.path.insert(0,'/opt/packweir-ghidra'); import runtime; p=Path(sys.argv[1]); r=runtime.analyze(p/'input.bin',sys.argv[2],retain_directory=p/'headless'); (p/'manifest.json').write_text(json.dumps(r,indent=2)+'\\n')"
        def as_worker(argv, **options):
            return subprocess.run(argv, user=self.account.pw_uid, group=self.account.pw_gid, extra_groups=[],
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}, **options)

        def write_manifest(data):
            # The image manifest belongs to assemblyline. Preserve capability
            # dropping: write as its owner instead of granting root DAC bypass.
            writer = as_worker([sys.executable, "-c", "from pathlib import Path; import sys; Path('/opt/al_service/service_manifest.yml').write_bytes(sys.stdin.buffer.read())"],
                               input=data, capture_output=True, timeout=15)
            self.assertEqual(writer.returncode, 0, writer.stderr.decode(errors="replace"))
        try:
            argv = [sys.executable, "-c", code, str(destination), expected]
            if sdk:
                # A private, operator-profile image mutation inside this owned
                # disposable test container. Use the same genuine build bake
                # before constructing the actual SDK service, then restore it.
                manifest, removed = re.subn(rb"^tool_version:.*\n", b"", original_manifest, flags=re.MULTILINE)
                self.assertEqual(removed, 1)
                write_manifest(manifest)
                baked = as_worker([sys.executable, "/tmp/bake-ghidra-manifest.py"], capture_output=True, timeout=15)
                (destination / "manifest-bake.log").write_bytes(baked.stdout + baked.stderr)
                self.assertEqual(baked.returncode, 0)
                argv = [sys.executable, "/test_runtime.py", "--sdk-probe", str(destination)]
            child = as_worker(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=145)
            (destination / "launcher.log").write_bytes(child.stdout[:1048576])
            self.assertEqual(child.returncode, 0, child.stdout.decode(errors="replace"))
            return json.loads((destination / "manifest.json").read_bytes())
        finally:
            PROFILE.write_bytes(self.original_profile)
            if sdk: write_manifest(original_manifest)

    def fixture(self, name):
        record = self.fixtures["fixtures"][name]
        data = (FIXTURES / record["file"]).read_bytes()
        self.assertEqual(digest(data), record["sha256"])
        return data

    def test_missing_native_execute_permission(self):
        mode, before = NATIVE.stat().st_mode & 0o777, digest(NATIVE.read_bytes())
        try:
            NATIVE.chmod(0o644)
            report = self.run_analysis("missing-decompiler-execution", self.fixture("encoded-elf64"))
            self.assertEqual(report["analysis"]["status"], "incomplete")
            self.assertEqual(report["analysis"]["functions_decompiled"], 0)
            self.assertGreater(report["analysis"]["functions_failed"], 0)
            self.assertTrue(any("decompil" in value.lower() or "permission denied" in value.lower() for value in report["analysis"]["errors"]))
        finally:
            NATIVE.chmod(mode)
            self.assertEqual(digest(NATIVE.read_bytes()), before)

    def test_operator_defined_nonframed_region_and_invalid_profiles(self):
        native = self.fixture("benign-elf64")
        plain = b"Packweir operator-defined constant XOR region.\n"
        key = bytes.fromhex("1327")
        encoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(plain))
        data = native + encoded
        base = json.loads(self.original_profile)
        base["qualification_xor_frame"] = None
        base["xor_regions"] = [{"offset": len(native), "length": len(encoded), "key_hex": key.hex()}]
        report = self.run_analysis("operator-region", data, base)
        self.assertEqual(report["analysis"]["status"], "complete", report["analysis"])
        output, = [item for item in report["outputs"] if item["kind"] == "decoded_bytes"]
        self.assertEqual(base64.b64decode(output["data_base64"]), plain)
        self.assertEqual(output["derivation"]["parameters"], {"key_hex": key.hex()})
        self.assertEqual(output["derivation"]["source_spans"], [{"offset": len(native), "length": len(encoded), "sha256": digest(encoded)}])
        for name, changes in (("bad-bounds", {"offset": len(data) + 1}), ("bad-key", {"key_hex": "zz"}),
                              ("fractional-offset", {"offset": 1.5})):
            invalid = json.loads(json.dumps(base))
            invalid["xor_regions"][0].update(changes)
            failed = self.run_analysis(name, data, invalid)
            self.assertEqual(failed["analysis"]["status"], "incomplete", failed["analysis"])
            self.assertEqual(failed["analysis"]["capabilities"]["decode_xor"], "error")
            self.assertTrue(failed["analysis"]["errors"])
        overlap = json.loads(json.dumps(base))
        overlap["xor_regions"].append(overlap["xor_regions"][0].copy())
        failed = self.run_analysis("overlapping-regions", data, overlap)
        self.assertEqual(failed["analysis"]["status"], "incomplete")
        self.assertTrue(any("overlapping" in value for value in failed["analysis"]["errors"]))

    def test_stock_analyzer_catalog_permission_failure(self):
        mode, before = CATALOG.stat().st_mode & 0o777, digest(CATALOG.read_bytes())
        try:
            CATALOG.chmod(0)
            report = self.run_analysis("stock-catalog-unreadable", self.fixture("benign-pe32plus"))
            self.assertEqual(report["analysis"]["status"], "incomplete")
            self.assertEqual(report["analysis"]["functions_decompiled"], 3)
            self.assertTrue(any("Ghidra internal analysis MessageLog:" in value and "PEFunctionsThatDoNotReturn" in value and "Permission denied" in value
                                for value in report["analysis"]["errors"]))
            notes = {item["name"]: item["value"] for item in report["observations"] if item["kind"] == "note"}
            self.assertEqual(notes["actual_headless_exit_code"], "0")
        finally:
            CATALOG.chmod(mode)
            self.assertEqual(digest(CATALOG.read_bytes()), before)

    def test_sdk_preserves_duplicate_regions_and_cross_kind_products(self):
        native = self.fixture("benign-elf64")
        plain = b"Two operator regions, one identical decoded child.\n"
        encoded = bytes(value ^ 0x5a for value in plain)
        profile = json.loads(self.original_profile)
        profile["qualification_xor_frame"] = None
        profile["xor_regions"] = [
            {"offset": len(native), "length": len(encoded), "key_hex": "5a"},
            {"offset": len(native) + len(encoded), "length": len(encoded), "key_hex": "5a"}]
        report = self.run_analysis("sdk-identical-decoded-regions", native + encoded + encoded, profile, sdk=True)
        self.assertEqual(report["analysis"]["status"], "complete", report["analysis"])
        decoded = [item for item in report["outputs"] if item["kind"] == "decoded_bytes"]
        self.assertEqual(len(decoded), 2)
        self.assertEqual([item["sha256"] for item in decoded], [digest(plain)] * 2)
        spans = [item["derivation"]["source_spans"][0] for item in decoded]
        self.assertEqual([span["offset"] for span in spans], [len(native), len(native) + len(encoded)])
        result = json.loads((OUTPUT / "sdk-identical-decoded-regions/sdk-result.json").read_bytes())
        self.assertEqual(len(result["response"]["extracted"]), 1)
        self.assertEqual(result["response"]["extracted"][0]["sha256"], digest(plain))

        profile["xor_regions"] = []
        baseline = self.run_analysis("cross-kind-baseline", native, profile)
        c = min((base64.b64decode(item["data_base64"]) for item in baseline["outputs"] if item["kind"] == "decompiled_c"), key=len)
        encoded_c = bytes(value ^ 0x5a for value in c)
        profile["xor_regions"] = [{"offset": len(native), "length": len(encoded_c), "key_hex": "5a"}]
        report = self.run_analysis("sdk-cross-kind-identical-bytes", native + encoded_c, profile, sdk=True)
        self.assertEqual(report["analysis"]["status"], "complete", report["analysis"])
        equal = [item for item in report["outputs"] if item["sha256"] == digest(c)]
        self.assertEqual({item["kind"] for item in equal}, {"decompiled_c", "decoded_bytes"})
        self.assertEqual(len(equal), 2)
        self.assertEqual({item["derivation"]["operation"] for item in equal}, {"ghidra.decompile", "xor.decode"})
        result = json.loads((OUTPUT / "sdk-cross-kind-identical-bytes/sdk-result.json").read_bytes())
        self.assertEqual(len(result["response"]["extracted"]), 1)
        self.assertEqual(result["response"]["extracted"][0]["sha256"], digest(c))


def sdk_probe(destination):
    """Run a genuine SDK task using the genuinely baked private test profile."""
    import importlib.util
    sys.path.insert(0, "/opt/al_service")
    spec = importlib.util.spec_from_file_location("sdk_tests", "/test_service.py")
    sdk_tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sdk_tests)
    sdk_tests.OUTPUT = destination / "sdk"
    sdk_tests.RealSDKAndGhidraTests.setUpClass()
    case = sdk_tests.RealSDKAndGhidraTests("test_four_real_compiled_inputs")
    result, report = case.run_task((destination / "input.bin").read_bytes(), "execution")
    (destination / "sdk-result.json").write_bytes((destination / "sdk/execution/sdk-result.json").read_bytes())
    (destination / "manifest.json").write_bytes((destination / "sdk/execution/manifest.json").read_bytes())


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--sdk-probe": sdk_probe(Path(sys.argv[2]))
    else: unittest.main(verbosity=2)
