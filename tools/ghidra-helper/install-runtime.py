"""Build-time installation of authenticated official assets; no target binaries run."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import zipfile

ASSETS = Path("/assets")
DESTINATION = Path("/opt")
LOCK = json.loads(Path("/tmp/ghidra-upstream.lock.json").read_text())


def hashed(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


for pin in (LOCK["ghidra"], LOCK["jdk"]):
    path = ASSETS / pin["asset"]
    if path.stat().st_size != pin["size"] or hashed(path) != pin["sha256"]:
        raise RuntimeError("build asset differs from authenticated upstream pin")

ghidra = DESTINATION / "ghidra"
ghidra.mkdir()
with zipfile.ZipFile(ASSETS / LOCK["ghidra"]["asset"]) as archive:
    members = archive.infolist()
    if len(members) > 200000 or sum(item.file_size for item in members) > 4 * 1024 ** 3:
        raise RuntimeError("Ghidra installation exceeds reviewed bounds")
    for item in members:
        parts = Path(item.filename).parts
        if not parts or parts[0] != "ghidra_12.2_PUBLIC" or ".." in parts or Path(item.filename).is_absolute():
            raise RuntimeError("unexpected upstream ZIP path")
        if len(parts) == 1:
            continue
        mode = item.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise RuntimeError("unexpected Ghidra symlink")
        target = ghidra.joinpath(*parts[1:])
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            target.chmod(0o755 if mode & 0o111 else 0o644)

java_raw = DESTINATION / "jdk-install"
java_raw.mkdir()
with tarfile.open(ASSETS / LOCK["jdk"]["asset"], "r:gz") as archive:
    members = archive.getmembers()
    if len(members) > 100000 or sum(item.size for item in members) > 2 * 1024 ** 3:
        raise RuntimeError("JDK installation exceeds reviewed bounds")
    archive.extractall(java_raw, filter="data")
children = list(java_raw.iterdir())
if len(children) != 1 or not children[0].is_dir():
    raise RuntimeError("unexpected official JDK layout")
java = DESTINATION / "ghidra-jdk"
children[0].rename(java)
java_raw.rmdir()
version = subprocess.check_output([str(java / "bin/java"), "-version"], stderr=subprocess.STDOUT, text=True)
if "25.0.5" not in version or "+8" not in version:
    raise RuntimeError("installed JDK runtime does not match release")
decompiler = ghidra / "Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
if not decompiler.is_file():
    raise RuntimeError("official Ghidra Linux AMD64 native decompiler is missing")
output = DESTINATION / "packweir-ghidra"
output.mkdir(exist_ok=True)
stamp = {"engine": "Ghidra", "engine_version": LOCK["ghidra"]["version"],
         "engine_archive_sha256": LOCK["ghidra"]["sha256"], "jdk_version": LOCK["jdk"]["version"],
         "jdk_archive_sha256": LOCK["jdk"]["sha256"], "decompiler_sha256": hashed(decompiler),
         "java_runtime_version_output": version,
         "installed_files": sum(1 for path in ghidra.rglob("*") if path.is_file()),
         "ghidra_installed_bytes": sum(path.stat().st_size for path in ghidra.rglob("*") if path.is_file()),
         "jdk_installed_bytes": sum(path.stat().st_size for path in java.rglob("*") if path.is_file())}
(output / "runtime-install.json").write_text(json.dumps(stamp, indent=2) + "\n")
print(json.dumps(stamp, sort_keys=True))
