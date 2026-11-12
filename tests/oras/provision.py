#!/usr/bin/env python3
"""Acquire official ORAS release assets and verify pinned hashes and GPG identity."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provision(output, archive=None, gpg=None):
    lock = json.loads((HERE / "provision.lock.json").read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    release = f"https://github.com/oras-project/oras/releases/download/v{lock['version']}/"
    assets = [lock["archive"], f"oras_{lock['version']}_checksums.txt",
              f"oras_{lock['version']}_checksums.txt.asc", "KEYS"]
    for name in assets:
        path = output / name
        if name == lock["archive"] and archive:
            shutil.copy2(archive, path)
        elif not path.is_file():
            url = (f"https://raw.githubusercontent.com/oras-project/oras/{lock['source_revision']}/KEYS"
                   if name == "KEYS" else release + name)
            request = urllib.request.Request(url, headers={"User-Agent": "Packweir-ORAS-qualification"})
            with urllib.request.urlopen(request, timeout=120) as response, path.open("wb") as stream:
                shutil.copyfileobj(response, stream)
    archive_path = output / lock["archive"]
    checksums = output / assets[1]
    if digest(archive_path) != lock["archive_sha256"]:
        raise RuntimeError("official ORAS release archive does not match its SHA-256 pin")
    if digest(checksums) != lock["checksums_sha256"]:
        raise RuntimeError("official ORAS checksums file does not match its SHA-256 pin")
    checksum_entries = {parts[1].lstrip("*"): parts[0]
                        for line in checksums.read_text().splitlines() if len(parts := line.split()) == 2}
    if checksum_entries.get(lock["archive"]) != lock["archive_sha256"]:
        raise RuntimeError("official ORAS checksums file does not bind the selected archive")
    gpg = gpg or shutil.which("gpg")
    git_gpg = Path(r"C:\Program Files\Git\usr\bin\gpg.exe")
    if not gpg and os.name == "nt" and git_gpg.is_file():
        gpg = str(git_gpg)
    if not gpg:
        raise RuntimeError("GPG is required to verify the pinned upstream release signing identity")
    def gpg_path(path):
        absolute = Path(path).resolve()
        if os.name == "nt" and Path(gpg).resolve() == git_gpg.resolve():
            return "/" + absolute.drive[0].lower() + absolute.as_posix()[2:]
        return str(absolute)
    authentication = []
    with tempfile.TemporaryDirectory(prefix="packweir-oras-gpg-") as keyring:
        base = [gpg, "--batch", "--no-tty", "--homedir", gpg_path(keyring)]
        for args in (["--import", gpg_path(output / "KEYS")],
                     ["--status-fd", "1", "--verify", gpg_path(output / assets[2]), gpg_path(checksums)]):
            result = subprocess.run(base + args, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=60)
            authentication.append(result.stdout)
            if result.returncode:
                raise RuntimeError("upstream ORAS GPG verification failed: " + result.stdout)
        if f"[GNUPG:] VALIDSIG {lock['signing_fingerprint']} " not in authentication[-1]:
            raise RuntimeError("ORAS checksum signature did not use the pinned release fingerprint")
    (output / "upstream-authentication.log").write_text("\n".join(authentication), encoding="utf-8")
    extracted = output / "extracted"
    extracted.mkdir(exist_ok=True)
    members = []
    with tarfile.open(archive_path, "r:gz") as bundle:
        for member in bundle.getmembers():
            if not member.isfile() or Path(member.name).name != member.name:
                raise RuntimeError("unexpected non-regular or nested ORAS archive member")
            content = bundle.extractfile(member).read()
            members.append({"path": member.name, "size": len(content),
                            "sha256": hashlib.sha256(content).hexdigest()})
            if member.name in ("oras", "LICENSE"):
                (extracted / member.name).write_bytes(content)
    if not (extracted / "oras").is_file() or not (extracted / "LICENSE").is_file():
        raise RuntimeError("ORAS release must contain its executable and license")
    (extracted / "oras").chmod(0o555)
    proof = dict(lock, gpg_verified=True, archive_members=members,
                 executable_sha256=digest(extracted / "oras"), license_sha256=digest(extracted / "LICENSE"))
    # Attestation verification is additional to mandatory offline GPG/hash checks.
    # It is attempted only when a locally authenticated GitHub CLI is available.
    gh = shutil.which("gh")
    proof["github_attestation"] = "unavailable: authenticated GitHub CLI not present"
    if gh and subprocess.run([gh, "auth", "status"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=30).returncode == 0:
        result = subprocess.run([gh, "attestation", "verify", str(archive_path), "--repo",
                                 "oras-project/oras", "--source-ref", f"refs/tags/v{lock['version']}",
                                 "--format", "json"], text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=120)
        (output / "upstream-attestation.log").write_text(result.stdout, encoding="utf-8")
        if result.returncode:
            raise RuntimeError("available GitHub attestation verification failed")
        proof["github_attestation"] = "verified"
    (output / "provision.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--gpg")
    options = parser.parse_args()
    result = provision(options.output, options.archive, options.gpg)
    print(json.dumps(result, indent=2))
