"""Real, bounded Ghidra headless execution; no target program is launched."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time

BASE = Path("/opt/packweir-ghidra")
ENGINE = Path("/opt/ghidra")
JAVA = Path("/opt/ghidra-jdk")
SERVICE = Path("/opt/al_service/packweir_ghidra")
SCHEMA = "packweir.binary-analysis.v1"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def framed(files):
    hashed = hashlib.sha256()
    for name, path in sorted(files.items()):
        data = path.read_bytes()
        hashed.update(name.encode("utf-8") + b"\0" + len(data).to_bytes(8, "big") + data)
    return hashed.hexdigest()


def producer():
    installed = json.loads((BASE / "runtime-install.json").read_text())
    fields = ("engine", "engine_version", "engine_archive_sha256", "jdk_version", "jdk_archive_sha256", "decompiler_sha256")
    value = {name: installed[name] for name in fields}
    native = ENGINE / "Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
    if sha256(native.read_bytes()) != value["decompiler_sha256"]:
        raise RuntimeError("actual native decompiler differs from the authenticated installation")
    value["scripts_sha256"] = framed({path.name: path for path in (BASE / "scripts").glob("*.java")})
    value["profile_sha256"] = sha256((BASE / "profile.json").read_bytes())
    value["driver_sha256"] = framed({"runtime.py": Path(__file__), "service.py": SERVICE / "service.py", "__init__.py": SERVICE / "__init__.py"})
    value["identity_sha256"] = sha256(canonical(value))
    return value


def kind(data):
    if data.startswith(b"\x7fELF"): return "elf"
    if data.startswith(b"MZ"): return "pe"
    if data.startswith(b"\0asm"): return "wasm"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "mach_o_or_java"
    return "binary"


def supported(data):
    if kind(data) == "elf":
        return len(data) >= 64 and data[4:6] == b"\x02\x01" and int.from_bytes(data[18:20], "little") == 62
    if kind(data) == "pe" and len(data) >= 64:
        offset = int.from_bytes(data[60:64], "little")
        return (offset <= len(data) - 26 and data[offset:offset + 4] == b"PE\0\0"
                and int.from_bytes(data[offset + 4:offset + 6], "little") == 0x8664
                and int.from_bytes(data[offset + 24:offset + 26], "little") == 0x20b)
    return False


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate engine report field")
        result[key] = value
    return result


def kill_group(process):
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait(timeout=10)


def group_rss(group):
    total = 0
    for path in Path("/proc").iterdir():
        if not path.name.isdigit(): continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) != group: continue
            matched = re.search(r"^VmRSS:\s+(\d+) kB$", (path / "status").read_text(), re.MULTILINE)
            if matched: total += int(matched.group(1)) * 1024
        except (OSError, ValueError, IndexError): pass
    return total


def group_live_pids(group):
    result = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit(): continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group and fields[0] != "Z": result.append(int(path.name))
        except (OSError, ValueError, IndexError): pass
    return result


def drain_group(group, seconds):
    """SIGKILL delivery to descendants can finish after the launcher is reaped."""
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 5:
        raise ValueError("qualified process-group drain must be a bounded 1..5 seconds")
    started = time.monotonic()
    deadline = started + seconds
    live = group_live_pids(group)
    while live and time.monotonic() < deadline:
        try: os.killpg(group, signal.SIGKILL)
        except ProcessLookupError: pass
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        live = group_live_pids(group)
    return len(live), time.monotonic() - started


def analyze(file_path, expected_sha256, *, fault_mode=None, retain_directory=None):
    """fault_mode is test instrumentation only; the production SDK never sets it."""
    if fault_mode not in (None, "throw", "deadline", "logged_failure"):
        raise ValueError("unsupported qualification-only fault mode")
    profile = json.loads((BASE / "profile.json").read_text())
    with Path(file_path).open("rb") as source:
        data = source.read(profile["max_file_bytes"] + 1)
    if len(data) > profile["max_file_bytes"]: raise ValueError("input exceeds qualified 16 MiB bound")
    subject = sha256(data)
    if subject != expected_sha256: raise ValueError("input SHA256 differs from actual SDK task")
    identity = producer()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    requested = profile["capabilities"]
    empty = {"status": "unsupported", "timed_out": False, "errors": [], "warnings": [], "language_id": None,
             "compiler_spec_id": None, "capabilities": {name: "unsupported" for name in requested},
             "functions_total": 0, "functions_decompiled": 0, "functions_failed": 0, "export_truncated": False,
             "observations": [], "outputs": []}
    raw, logs, extra_errors, timed_out, peak_rss, exit_code, live_after_stop, stop_wait = empty, b"", [], False, 0, None, 0, 0.0
    if supported(data):
        with tempfile.TemporaryDirectory(prefix="packweir-ghidra-") as directory:
            work = Path(directory)
            for name in ("home", "tmp", "project", "cache", "settings"):
                (work / name).mkdir()
            original = work / "input.bin"
            original.write_bytes(data)
            original.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            result = work / "post.json"
            events = work / "events.jsonl"
            console = work / "console.log"
            paths = [console, work / "ghidra.log", work / "scripts.log", events]
            arguments = [str(ENGINE / "support/analyzeHeadless"), str(work / "project"), "analysis", "-import", str(original),
                         "-readOnly", "-deleteProject", "-max-cpu", str(profile["max_cpu"]), "-analysisTimeoutPerFile", str(profile["analysis_timeout_seconds"]),
                         "-scriptPath", str(BASE / "scripts"), "-log", str(work / "ghidra.log"), "-scriptlog", str(work / "scripts.log"),
                         "-preScript", "PackweirPre.java", str(events), str(BASE / "profile.json")]
            if fault_mode in ("throw", "logged_failure"): arguments += ["-preScript", "PackweirThrow.java", fault_mode]
            arguments += ["-postScript", "PackweirPost.java", str(original), str(result), str(BASE / "profile.json")]
            environment = {"PATH": str(JAVA / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(JAVA), "HOME": str(work / "home"),
                           "TMPDIR": str(work / "tmp"), "LANG": "C.UTF-8", "GHIDRA_HEADLESS_MAXMEM": profile["heap"],
                           "GHIDRA_HEADLESS_JAVA_OPTIONS": " ".join(("-Duser.home=" + str(work / "home"), "-Djava.io.tmpdir=" + str(work / "tmp"),
                               "-Dapplication.settingsdir=" + str(work / "settings"), "-Dapplication.cachedir=" + str(work / "cache"), "-Dapplication.tempdir=" + str(work / "tmp")))}
            effective_timeout = 2 if fault_mode == "deadline" else profile["process_timeout_seconds"]
            deadline = time.monotonic() + effective_timeout
            process = None
            with console.open("wb") as output:
                try:
                    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                               env=environment, cwd=work, start_new_session=True)
                    while process.poll() is None:
                        peak_rss = max(peak_rss, group_rss(process.pid))
                        if time.monotonic() >= deadline:
                            timed_out = True; extra_errors.append("whole Ghidra process-group deadline exceeded"); break
                        if sum(path.stat().st_size for path in paths if path.exists()) > profile["max_log_bytes"]:
                            extra_errors.append("bounded Ghidra diagnostic output limit exceeded"); break
                        if result.exists() and result.stat().st_size > profile["max_manifest_bytes"]:
                            extra_errors.append("bounded Ghidra post-script output limit exceeded"); break
                        time.sleep(0.1)
                    if process.poll() is None: kill_group(process)
                    exit_code = process.wait(timeout=10)
                finally:
                    if process is not None:
                        kill_group(process)
                        live_after_stop, stop_wait = drain_group(process.pid, profile["process_group_stop_timeout_seconds"])
                        if live_after_stop: extra_errors.append("Ghidra process group still has live members after stop")
            if sha256(original.read_bytes()) != subject: extra_errors.append("read-only original input changed during analysis")
            if sum(path.stat().st_size for path in paths if path.exists()) > profile["max_log_bytes"]:
                extra_errors.append("bounded Ghidra diagnostic output limit exceeded")
            captured = bytearray()
            for path in paths:
                if not path.exists(): continue
                with path.open("rb") as stream: content = stream.read(profile["max_log_bytes"] + 1)
                captured += path.name.encode() + b"\0" + len(content).to_bytes(8, "big") + content
                text = content.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if path == events:
                        try:
                            event = json.loads(line, object_pairs_hook=no_duplicates)
                            if event.get("level") == "error":
                                extra_errors.append("actual Ghidra error event: " + str(event["message"])[:3900])
                        except (ValueError, KeyError, TypeError):
                            extra_errors.append("actual structured Ghidra diagnostic stream is malformed")
                    if re.match(r"^(?:ERROR|FATAL)\b|^\d{4}-\d\d-\d\d.{1,80}\b(?:ERROR|FATAL)\b", line):
                        extra_errors.append("Ghidra startup/runtime diagnostic: " + line[:3900])
            logs = bytes(captured)
            if result.is_file() and not result.is_symlink() and result.stat().st_size <= profile["max_manifest_bytes"]:
                raw = json.loads(result.read_bytes(), object_pairs_hook=no_duplicates)
            else:
                raw = dict(empty, status="incomplete", capabilities={name: "incomplete" for name in requested})
                extra_errors.append("trusted Ghidra post-script report absent or exceeds bound")
            if retain_directory:
                destination = Path(retain_directory)
                destination.mkdir(parents=True, exist_ok=True)
                for path in paths + [result]:
                    if path.is_file():
                        with path.open("rb") as stream:
                            (destination / path.name).write_bytes(stream.read(profile["max_log_bytes"] + 1))
                (destination / "invocation.json").write_text(json.dumps({"arguments": arguments, "environment_keys": sorted(environment),
                    "exit_code": exit_code, "process_group_peak_rss_bytes": peak_rss, "fault_mode": fault_mode,
                    "effective_process_timeout_seconds": effective_timeout, "process_group_live_pids_after_stop": live_after_stop,
                    "process_group_stop_wait_seconds": stop_wait}, indent=2))
            if exit_code != 0: extra_errors.append("actual Ghidra launcher exit code " + str(exit_code))
    errors = list(dict.fromkeys(raw["errors"] + extra_errors))[:64]
    raw["observations"].extend([{"kind": "note", "name": "actual_headless_exit_code", "value": str(exit_code)},
                                {"kind": "note", "name": "process_group_peak_rss_bytes", "value": str(peak_rss)},
                                {"kind": "note", "name": "process_group_live_pids_after_stop", "value": str(live_after_stop)},
                                {"kind": "note", "name": "process_group_stop_wait_seconds", "value": str(stop_wait)}])
    if fault_mode: raw["observations"].append({"kind": "note", "name": "qualification_fault", "value": fault_mode})
    if fault_mode == "deadline": raw["observations"].append({"kind": "note", "name": "qualification_process_timeout_seconds", "value": "2"})
    status = raw["status"]
    if errors or timed_out: status = "incomplete"
    completed = datetime.datetime.now(datetime.timezone.utc).isoformat()
    analysis = {name: raw[name] for name in ("language_id", "compiler_spec_id", "capabilities", "functions_total", "functions_decompiled", "functions_failed", "export_truncated")}
    analysis.update(started_at=started, completed_at=completed, status=status, timed_out=timed_out or raw["timed_out"], errors=errors,
                    warnings=raw["warnings"], requested_capabilities=requested, log_sha256=sha256(logs))
    report = {"schema_version": SCHEMA, "input": {"sha256": subject, "size": len(data), "kind": kind(data)},
              "producer": identity, "analysis": analysis, "observations": raw["observations"], "outputs": raw["outputs"]}
    if sum(item["size"] for item in report["outputs"]) > profile["max_output_bytes"]:
        raise RuntimeError("actual derived outputs exceed qualified total")
    for item in report["outputs"]:
        actual = base64.b64decode(item["data_base64"], validate=True)
        if len(actual) != item["size"] or sha256(actual) != item["sha256"]: raise RuntimeError("actual derived output identity differs")
    if len(canonical(report)) > profile["max_manifest_bytes"]:
        raise RuntimeError("actual complete manifest exceeds qualified limit")
    return report
