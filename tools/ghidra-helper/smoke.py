"""Run the actual installed Ghidra on compiled benign fixtures, never execute them."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, "/opt/packweir-ghidra")
import runtime

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixtures", type=Path, default=Path("/fixtures"))
parser.add_argument("--output", type=Path, default=Path("/qualification"))
parser.add_argument("--case", default="encoded-elf64")
parser.add_argument("--throw", action="store_true")
parser.add_argument("--deadline", action="store_true")
args = parser.parse_args()
manifest = json.loads((args.fixtures / "fixtures.json").read_text())
item = manifest["fixtures"][args.case]
source = args.fixtures / item["file"]
data = source.read_bytes()
assert hashlib.sha256(data).hexdigest() == item["sha256"]
if args.throw and args.deadline: parser.error("select one qualification fault")
fault = "throw" if args.throw else "deadline" if args.deadline else None
destination = args.output / (args.case + ("-" + fault if fault else "") + "-" + uuid.uuid4().hex[:8])
destination.mkdir(parents=True, exist_ok=True)
report = runtime.analyze(source, item["sha256"], fault_mode=fault,
                         retain_directory=destination)
(destination / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"case": args.case, "throw": args.throw, "analysis": report["analysis"],
                  "outputs": [{key: output[key] for key in ("kind", "sha256", "size")} for output in report["outputs"]],
                  "notes": [entry for entry in report["observations"] if entry["kind"] == "note"]}, indent=2), flush=True)
