"""Genuine bounded helper failures inside this run's existing Ghidra worker.

These are trusted qualification probes, not service submission parameters. No
second analysis container or package execution is involved.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid


NATIVE = "/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
NORETURN_CATALOG = "/opt/ghidra/Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_negatives(state, fixture_root, output, command):
    """Return a safe receipt; command has the full live runner's redaction/logging."""
    project = state["project"]
    if not re.fullmatch(r"packweir-al-live-[a-f0-9]{12}", project) or state.get("profile") != "ghidra":
        raise ValueError("negative probes require an owned optional Ghidra project")
    docker = state["docker"]
    fixture_root, output = Path(fixture_root).resolve(), Path(output).resolve()
    evidence = output / "engine-negatives"
    evidence.mkdir(parents=True, exist_ok=False)
    code, listed = command([docker, "ps", "-q", "--filter", "label=com.docker.compose.project=" + project,
                           "--filter", "label=com.docker.compose.service=ghidra"], "engine-negative-worker.log", 30)
    ids = listed.split()
    if len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{12,64}", ids[0]):
        raise RuntimeError("negative probes require exactly one running owned Ghidra worker")
    container = ids[0]
    _, labels_raw = command([docker, "inspect", "--format", "{{json .Config.Labels}}", container], "engine-negative-labels.log", 30)
    labels = json.loads(labels_raw)
    if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") != "ghidra":
        raise RuntimeError("worker ownership differs")
    _, uid = command([docker, "exec", container, "id", "-u"], "engine-negative-uid.log", 30)
    if not uid.strip().isdigit() or uid.strip() == "0":
        raise RuntimeError("actual analysis probes must run as the unprivileged worker user")

    def native(path):
        if os.name != "nt" and str(docker).lower().endswith(".exe"):
            return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        return str(path)

    work = "/tmp/packweir-ghidra-negative-" + uuid.uuid4().hex
    prefix = [docker, "exec", container, "python", "-c"]
    receipt = {"status": "failed", "scope": "actual helper failure probes in the owned existing worker",
               "project": project, "container_id": container, "worker_uid": int(uid.strip()),
               "separate_analysis_container": False, "target_execution": False, "cases": [],
               "native_permissions_restored": False, "temporary_workspace_removed": False}
    receipt['catalog_permissions_restored'] = False
    original_mode = None
    native_digest = None
    workspace_created = False
    try:
        command([*prefix, "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.mkdir(mode=0o700); (p/'inputs').mkdir(); (p/'captures').mkdir()", work],
                "engine-negative-prepare.log", 30)
        workspace_created = True
        fixtures = json.loads((fixture_root / "fixtures.json").read_bytes())
        record = fixtures["fixtures"]["encoded-elf64"]
        original = (fixture_root / record["file"]).read_bytes()
        if sha(original) != record["sha256"]:
            raise RuntimeError("actual compiled fixture identity differs")
        inputs = {
            "encoded-elf64.bin": original,
            "benign-pe32plus.exe": (fixture_root / fixtures['fixtures']['benign-pe32plus']['file']).read_bytes(),
            "unsupported.txt": (fixture_root / "samples/unsupported.txt").read_bytes(),
            "malformed-elf.bin": (fixture_root / "samples/malformed-elf.bin").read_bytes(),
            "malformed-pe.exe": (fixture_root / "samples/malformed-pe.exe").read_bytes(),
            # Keeps the real AMD64 ELF preflight header but removes section data;
            # this invokes the actual importer, rather than a preflight shortcut.
            "truncated-elf.bin": original[:64],
        }
        local_inputs = evidence / "inputs"
        local_inputs.mkdir()
        for name, data in inputs.items():
            source = local_inputs / name
            source.write_bytes(data)
            command([docker, "cp", native(source), container + ":" + work + "/inputs/" + name],
                    "engine-negative-copy-" + name + ".log", 30)
        script = evidence / "probe.py"
        script.write_text('''import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,"/opt/packweir-ghidra")
import runtime
work,case,filename,fault=map(str,sys.argv[1:])
root=Path(work); destination=root/"captures"/case; destination.mkdir()
data=(root/"inputs"/filename).read_bytes(); subject=hashlib.sha256(data).hexdigest()
(destination/"input.bin").write_bytes(data)
report=runtime.analyze(root/"inputs"/filename,subject,fault_mode=None if fault=="none" else fault,retain_directory=destination/"headless")
(destination/"manifest.json").write_text(json.dumps(report,indent=2)+"\\n")
print(json.dumps({"case":case,"input_sha256":subject,"producer_identity_sha256":report["producer"]["identity_sha256"],"analysis":report["analysis"],"notes":[x for x in report["observations"] if x["kind"]=="note"]}))
''', encoding="utf-8")
        command([docker, "cp", native(script), container + ":" + work + "/probe.py"], "engine-negative-script-copy.log", 30)

        def probe(case, filename, fault="none"):
            _, raw = command([docker, "exec", container, "python", work + "/probe.py", work, case, filename, fault],
                             "engine-negative-" + case + ".log", 145)
            actual = json.loads(raw)
            analysis = actual["analysis"]
            notes = {item["name"]: item["value"] for item in actual["notes"]}
            if analysis["status"] == "complete" or notes.get("process_group_live_pids_after_stop") != "0":
                raise RuntimeError("negative probe completed or left a live process group: " + case)
            if case in ("unsupported", "malformed-elf-preflight", "malformed-pe-preflight"):
                if analysis["status"] != "unsupported" or notes["actual_headless_exit_code"] != "None":
                    raise RuntimeError("unsupported probe unexpectedly invoked the engine")
            elif case == "truncated-elf-import":
                if analysis["status"] != "incomplete" or notes["actual_headless_exit_code"] == "None":
                    raise RuntimeError("malformed import lacks actual engine failure evidence")
            elif case == "analyzer-throw":
                if analysis["status"] != "incomplete" or notes["actual_headless_exit_code"] != "0" or not any(
                        "PACKWEIR_QUALIFICATION_REAL_ANALYZER_THROW" in message for message in analysis["errors"]):
                    raise RuntimeError("real zero-exit analyzer error was not retained")
            elif case == "deadline":
                if not analysis["timed_out"] or notes["actual_headless_exit_code"] != "-9":
                    raise RuntimeError("deadline did not kill the actual process group")
            elif case == "missing-native":
                if analysis["functions_decompiled"] != 0 or analysis["functions_failed"] == 0 or not any(
                        "permission denied" in message.lower() for message in analysis["errors"]):
                    raise RuntimeError("missing native execute permission did not cause actual decompiler failure")
            elif case == "stock-analyzer-false":
                errors='\n'.join(analysis['errors'])
                if (analysis['status']!='incomplete' or notes['actual_headless_exit_code']!='0'
                        or analysis['functions_total']<3 or analysis['functions_decompiled']!=analysis['functions_total']
                        or analysis['functions_failed']!=0 or NORETURN_CATALOG not in errors
                        or 'Ghidra internal analysis MessageLog: ' not in errors
                        or 'permission denied' not in errors.lower()):
                    raise RuntimeError('stock zero-exit analyzer failure was not retained with complete function exports')
            receipt["cases"].append({"case": case, "input_sha256": actual["input_sha256"],
                "producer_identity_sha256": actual["producer_identity_sha256"], "status": analysis["status"],
                "timed_out": analysis["timed_out"], "headless_exit_code": notes["actual_headless_exit_code"],
                "process_group_live_pids_after_stop": int(notes["process_group_live_pids_after_stop"]),
                "manifest": "engine-negatives/worker-captures/" + case + "/manifest.json"})

        probe("unsupported", "unsupported.txt")
        probe("malformed-elf-preflight", "malformed-elf.bin")
        probe("malformed-pe-preflight", "malformed-pe.exe")
        probe("truncated-elf-import", "truncated-elf.bin")
        probe("analyzer-throw", "encoded-elf64.bin", "throw")
        probe("deadline", "encoded-elf64.bin", "deadline")
        inspect_native = "import hashlib,json,os,sys; p=sys.argv[1]; print(json.dumps({'mode':os.stat(p).st_mode&511,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}))"
        _, raw = command([*prefix, inspect_native, NATIVE], "engine-negative-native-before.log", 30)
        before = json.loads(raw)
        original_mode, native_digest = before["mode"], before["sha256"]
        if original_mode & 0o111 == 0:
            raise RuntimeError("native decompiler was not executable before the probe")
        try:
            command([docker, "exec", "--user", "0", container, "chmod", "0644", NATIVE], "engine-negative-native-disable.log", 30)
            probe("missing-native", "encoded-elf64.bin")
        finally:
            command([docker, "exec", "--user", "0", container, "chmod", format(original_mode, "04o"), NATIVE],
                    "engine-negative-native-restore.log", 30)
            _, raw = command([*prefix, inspect_native, NATIVE], "engine-negative-native-after.log", 30)
            after = json.loads(raw)
            receipt["native_permissions_restored"] = after == before
            if not receipt["native_permissions_restored"]:
                raise RuntimeError("owned worker native decompiler restoration failed")
        receipt["native_decompiler_sha256"] = native_digest
        _, raw = command([*prefix, inspect_native, NORETURN_CATALOG], 'engine-negative-catalog-before.log', 30)
        catalog_before=json.loads(raw)
        if catalog_before['mode'] & 0o444 == 0:
            raise RuntimeError('stock analyzer catalog was not readable before the probe')
        try:
            command([docker,'exec','--user','0',container,'chmod','0000',NORETURN_CATALOG], 'engine-negative-catalog-disable.log',30)
            probe('stock-analyzer-false','benign-pe32plus.exe')
        finally:
            command([docker,'exec','--user','0',container,'chmod',format(catalog_before['mode'],'04o'),NORETURN_CATALOG],
                    'engine-negative-catalog-restore.log',30)
            _, raw=command([*prefix,inspect_native,NORETURN_CATALOG],'engine-negative-catalog-after.log',30)
            receipt['catalog_permissions_restored']=json.loads(raw)==catalog_before
            if not receipt['catalog_permissions_restored']:
                raise RuntimeError('owned worker stock analyzer catalog restoration failed')
        receipt['stock_analyzer_catalog_sha256']=catalog_before['sha256']
        receipt["status"] = "passed"
    except BaseException as error:
        receipt["error"] = str(error)
        raise
    finally:
        cleanup_errors = []
        if workspace_created:
            # Preserve the actual original reports and bounded raw diagnostics,
            # including failure cases. No worker environment or SDK keys copied.
            try:
                command([docker, "cp", container + ":" + work + "/captures", native(evidence / "worker-captures")],
                        "engine-negative-captures-copy.log", 30)
            except BaseException as error:
                cleanup_errors.append("negative capture copy failed: " + str(error))
            finally:
                cleanup = "from pathlib import Path; import shutil,sys; p=Path(sys.argv[1]); prefix='packweir-ghidra-negative-'; assert p.parent==Path('/tmp') and p.name.startswith(prefix) and len(p.name)==len(prefix)+32; shutil.rmtree(p)"
                try:
                    command([*prefix, cleanup, work], "engine-negative-workspace-cleanup.log", 30)
                    receipt["temporary_workspace_removed"] = True
                except BaseException as error:
                    cleanup_errors.append("negative workspace cleanup failed: " + str(error))
        captures = evidence / "worker-captures"
        artifacts = {}
        if captures.exists():
            for path in sorted(captures.rglob("*")):
                if path.is_file():
                    if path.is_symlink() or path.stat().st_size > 1048577:
                        raise RuntimeError("negative probe artifact exceeds its bounded regular-file capture")
                    artifacts[path.relative_to(output).as_posix()] = sha(path.read_bytes())
        receipt["artifacts"] = artifacts
        if cleanup_errors:
            receipt["status"] = "failed"
            receipt["cleanup_errors"] = cleanup_errors
        (output / "engine-negative-results.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
    return receipt
