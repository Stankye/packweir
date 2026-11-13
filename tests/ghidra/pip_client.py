"""Invoke hash-pinned pip in isolation; wheels are unpacked, never imported."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK = json.loads((HERE/'client.lock.json').read_text())
WRAPPER = "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('pip',run_name='__main__')"


def acquire(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    path = output/LOCK['filename']
    if not path.exists():
        with urllib.request.urlopen(LOCK['url'], timeout=30) as response:
            raw = response.read(LOCK['size']+1)
        if len(raw) != LOCK['size'] or hashlib.sha256(raw).hexdigest() != LOCK['sha256']:
            raise RuntimeError('Official pip wheel differs from the reviewed pin')
        path.write_bytes(raw)
    if path.stat().st_size != LOCK['size'] or hashlib.sha256(path.read_bytes()).hexdigest() != LOCK['sha256']:
        raise RuntimeError('Cached pip wheel differs from the reviewed pin')
    with zipfile.ZipFile(path) as archive:
        license_name = f'pip-{LOCK["version"]}.dist-info/licenses/LICENSE.txt'
        (output/'LICENSE.PIP.txt').write_bytes(archive.read(license_name))
    version = subprocess.check_output([sys.executable, '-I', '-c', WRAPPER, str(path), '--isolated', '--version'], text=True, timeout=30).strip()
    if not version.startswith('pip '+LOCK['version']+' from ') or str(path) not in version:
        raise RuntimeError('The isolated CLI did not load the exact pinned pip wheel')
    (output/'pip-version.log').write_text(version+'\n')
    return path


def install(project, index_url, expected_sha256, target, output, read_token, timeout=180):
    output = Path(output).resolve()
    target = Path(target).resolve()
    root = (ROOT/'target').resolve()
    if root not in output.parents or root not in target.parents:
        raise ValueError('pip work and installation targets must be below workspace target/')
    if target.exists() and any(target.iterdir()):
        raise ValueError('pip installation target must be new or empty')
    if not re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', project) or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
        raise ValueError('Invalid fixture project or artifact SHA256')
    if not re.fullmatch('[a-f0-9]{64}', read_token):
        raise ValueError('Expected a fresh opaque read credential')
    parsed = urllib.parse.urlparse(index_url)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.username or parsed.password:
        raise ValueError('pip qualification requires an explicit credential-free loopback index URL')
    wheel = acquire(ROOT/'target/ghidra/pip')
    output.mkdir(parents=True, exist_ok=True)
    private = output/'private'
    private.mkdir(mode=0o700, exist_ok=False)
    os.chmod(private, 0o700)
    auth = private/'netrc'
    with os.fdopen(os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        stream.write(f'machine {parsed.hostname} login fixture password {read_token}\n')
    requirements = output/'requirements.txt'
    requirements.write_text(project+'==0.1.0 --hash=sha256:'+expected_sha256+'\n')
    environment = dict(os.environ, NETRC=str(auth), PIP_NO_INPUT='1')
    args = [sys.executable, '-I', '-c', WRAPPER, str(wheel), '--isolated', 'install', '--disable-pip-version-check',
            '--no-input', '--no-cache-dir', '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-compile', '--retries', '0', '--timeout', '15',
            '--index-url', index_url, '--trusted-host', parsed.hostname, '--target', str(target), '-r', str(requirements)]
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, env=environment)
        (output/'pip-install.log').write_bytes((result.stdout+result.stderr).replace(read_token.encode(), b'[REDACTED]'))
    finally:
        auth.unlink(missing_ok=True)
        private.rmdir()
    installed = {p.relative_to(target).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in target.rglob('*') if p.is_file()}
    receipt = {'client': 'pip', 'version': LOCK['version'], 'wheel_sha256': LOCK['sha256'], 'exit_code': result.returncode,
               'project': project, 'index_url': index_url, 'expected_artifact_sha256': expected_sha256,
               'install_target': str(target), 'installed_file_sha256': installed,
               'package_code_executed': False, 'only_binary': True, 'no_dependencies': True, 'require_hashes': True,
               'private_credential_file_removed': not auth.exists()}
    (output/'pip-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt
