"""Run actual ORAS and the product command with external networking unavailable."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

OUTPUT = Path("/qualification")
TEST = "real_oras_roundtrip_and_cli_qualification"


def invoke(command, name):
    with (OUTPUT / name).open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    content = (OUTPUT / name).read_text(encoding="utf-8", errors="replace")
    if result.returncode:
        print(content[-12000:], flush=True)
        raise RuntimeError(f"{name} failed with exit {result.returncode}")
    return content


def main():
    report = {"status": "failed", "network": "none", "test": TEST}
    try:
        report["oras_version"] = invoke(["oras", "version"], "oras-version.log")
        report["packweir_version"] = invoke(["packweir", "--version"], "packweir-version.log").strip()
        report["rust_version"] = Path("/opt/oras/rust-version.txt").read_text().strip()
        report["executables"] = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                 for path in ("/usr/local/bin/oras", "/usr/local/bin/packweir",
                                              "/usr/local/bin/packweir-oras-tests")}
        content = invoke(["/usr/local/bin/packweir-oras-tests", "--exact", TEST,
                          "--ignored", "--nocapture"], "qualification.log")
        if "running 1 test" not in content or "1 passed; 0 failed" not in content:
            raise RuntimeError("the selected real ORAS test must execute exactly once")
        matches = re.findall(r"PACKWEIR_ORAS_PROOF=(\{[^\r\n]*\})", content)
        if len(matches) != 1:
            raise RuntimeError("real qualification test must emit exactly one proof")
        proof = json.loads(matches[0])
        expected = {
            "oras_fetch_exact_manifest", "oras_fetch_exact_blobs", "oras_copy_preserves_root_digest",
            "packweir_reads_copied_exact_documents", "oras_push_independent_bundle",
            "cli_validate_configless_export", "cli_validate_configless_copy",
            "cli_validate_configless_oras_push", "cli_rejects_tampered_document",
        }
        if (proof.get("qualified") is not True or set(proof.get("cases", [])) != expected
                or proof["export_manifest_digest"] != proof["copied_manifest_digest"]
                or len(proof["document_sha256"]) != 2):
            raise RuntimeError("real ORAS proof is incomplete")
        (OUTPUT / "qualification.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
        report["qualification"] = proof
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        shutil.copy2("/opt/oras/LICENSE.ORAS.txt", OUTPUT / "LICENSE.ORAS.txt")
        report["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUTPUT / "runtime.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
