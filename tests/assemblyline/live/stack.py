#!/usr/bin/env python3
"""Bounded, namespaced provisioning of the real upstream Assemblyline appliance.

Only the generated run directory contains credentials. Docker operations use a
unique Compose project and never prune, stop, or remove unrelated resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LOCK = json.loads((HERE / 'stack.lock.json').read_text())
PROJECT = re.compile(r'^packweir-al-live-[a-f0-9]{12}$')


def _docker_default():
    if os.name == 'nt':
        path = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Docker/Docker/resources/bin/docker.exe'
        if path.exists():
            return str(path)
    path = '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
    return path if Path(path).exists() else (shutil.which('docker') or 'docker')


def _native(path: Path, docker: str) -> str:
    if os.name != 'nt' and docker.endswith('.exe'):
        return subprocess.check_output(['wslpath', '-w', str(path.resolve())], text=True).strip()
    return str(path.resolve())


def _run(state, args, *, timeout=120, log=None, check=True):
    command = [state['docker'], *args]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')
    if log:
        log_path = Path(state['run_dir']) / log
        with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w', encoding='utf-8') as handle:
            handle.write(result.stdout + result.stderr)
        os.chmod(log_path, 0o600)
    if check and result.returncode:
        # Command output may contain config/credentials. Keep it in target only.
        raise RuntimeError(f'Docker {args[0]} failed ({result.returncode}); see {log or "run directory"}')
    return result


def _load(path):
    state = json.loads(Path(path).read_text())
    if not PROJECT.fullmatch(state.get('project', '')):
        raise ValueError('Refusing a state without an owned unique project name')
    run_dir = Path(state['run_dir']).resolve()
    target = (ROOT / 'target').resolve()
    if run_dir == target or target not in run_dir.parents:
        raise ValueError('Run directory must be a child of this workspace target directory')
    lock_file = Path(state['lock_file']).resolve()
    if lock_file.parent != run_dir:
        raise ValueError('Reviewed run lock must be stored in the owned run directory')
    if hashlib.sha256(lock_file.read_bytes()).hexdigest() != state['lock_sha256']:
        raise ValueError('Reviewed run lock does not match the recorded state hash')
    expected_images = json.loads(lock_file.read_text())['images']
    effective = _env(state)
    if any(effective.get(key) != value for key, value in expected_images.items()):
        raise ValueError('Effective registry images differ from the reviewed run lock')
    return state


def _compose(state, args, **kwargs):
    return _run(state, ['compose', '--project-name', state['project'],
        '--file', _native(Path(state['compose_file']), state['docker']),
        '--env-file', _native(Path(state['run_dir']) / '.env', state['docker']), *args], **kwargs)


def prepare(output: Path, docker: str | None = None) -> Path:
    output = Path(output).resolve()
    target = (ROOT / 'target').resolve()
    if output == target or target not in output.parents:
        raise ValueError('Output must be a new directory below workspace target/')
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o750)
    state_path = output / 'stack-state.json'
    if state_path.exists():
        _load(state_path)
        return state_path
    if (output / '.env').exists():
        raise ValueError('Refusing to replace an existing credentials file')
    project = 'packweir-al-live-' + secrets.token_hex(6)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    values = {key: secrets.token_hex(24) for key in
              ('ELASTIC_PASSWORD', 'FILESTORE_PASSWORD', 'SERVICE_API_KEY', 'AL_ADMIN_PASSWORD', 'FLASK_SECRET')}
    values.update(LOCK['images'])
    values.update({'AL_PORT': str(port), 'AL_ADMIN_USER': 'packweir-live',
        'RUN_GID': str(os.getgid()) if os.name != 'nt' else '1000',
        'YARA_IMAGE': f'packweir/assemblyline-yara:{project}', 'REGISTRY': '',
        'SERVICE_API_HOST': 'http://service-server:5003', 'WORKERS': '1',
        'THREADS': '2', 'AL_LOG_LEVEL': 'INFO'})
    (output / '.env').write_text(''.join(f'{key}={value}\n' for key, value in values.items()), encoding='utf-8')
    (output / 'apikey').write_text('qualification:' + secrets.token_hex(24), encoding='utf-8')
    for name in ('compose.yaml', 'bootstrap.py'):
        shutil.copyfile(HERE / name, output / name)
    shutil.copyfile(HERE / 'config.classification.yml', output / 'classification.yml')
    config = (HERE / 'config.yml').read_text()
    for key, value in values.items():
        config = config.replace('{' + key + '}', value)
    (output / 'config.yml').write_text(config, encoding='utf-8')
    (output / 'manifests').mkdir(exist_ok=True)
    os.chmod(output / 'manifests', 0o750)
    shutil.copyfile(HERE / 'stack.lock.json', output / 'stack.lock.json')
    state = {'schema_version': 1, 'project': project, 'docker': docker or _docker_default(),
        'run_dir': str(output), 'compose_file': str(output / 'compose.yaml'),
        'base_url': f'http://127.0.0.1:{port}', 'user': 'packweir-live', 'classification': 'TLP:C',
        'apikey_file': str(output / 'apikey'), 'identity_file': str(output / 'identity.json'),
        'lock_file': str(output / 'stack.lock.json'),
        'lock_sha256': hashlib.sha256((output / 'stack.lock.json').read_bytes()).hexdigest(),
        'yara_image': values['YARA_IMAGE']}
    state_path.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    # POSIX permissions also apply when the harness runs on a Linux runner.
    for name in ('.env', 'stack-state.json'):
        os.chmod(output / name, 0o600)
    # Only the exact host group is added to core/bootstrap containers. These
    # read-only bind inputs need group access when host/image UIDs differ.
    for name in ('bootstrap.py', 'classification.yml', 'apikey', 'config.yml'):
        os.chmod(output / name, 0o640)
    _compose(state, ['config', '--quiet'], log='compose-validation.log')
    return state_path


def _env(state):
    return dict(line.split('=', 1) for line in (Path(state['run_dir']) / '.env').read_text().splitlines() if '=' in line)


def up(path: Path, timeout=600):
    state = _load(path)
    if state['lock_sha256'] != hashlib.sha256((HERE / 'stack.lock.json').read_bytes()).hexdigest():
        raise ValueError('Source stack lock changed; prepare a new run directory before provisioning')
    deadline = time.monotonic() + timeout
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('Assemblyline provisioning deadline exceeded; owned stack remains for inspection')
        return value
    values = _env(state)
    for name in ('compose.yaml', 'bootstrap.py'):
        shutil.copyfile(HERE / name, Path(state['run_dir']) / name)
    os.chmod(Path(state['run_dir']) / 'bootstrap.py', 0o640)
    # Digest-pinned downloads only; keep the build bounded by the same deadline.
    _compose(state, ['pull', '--ignore-buildable', 'elasticsearch', 'redis', 'minio', 'ui', 'dispatcher', 'service-server', 'extract', 'bootstrap'],
             timeout=remaining(), log='pull.log')
    _run(state, ['build', '--build-arg', f'SERVICE_BASE={LOCK["images"]["SERVICE_BASE_IMAGE"]}',
        '--tag', state['yara_image'], _native(ROOT / 'tools/assemblyline-yara', state['docker'])],
        timeout=remaining(), log='yara-build.log')
    # Lock the local built image by immutable image ID before starting containers.
    image_id = _run(state, ['image', 'inspect', state['yara_image'], '--format', '{{.Id}}']).stdout.strip()
    env_path = Path(state['run_dir']) / '.env'
    env_path.write_text(re.sub(r'^YARA_IMAGE=.*$', f'YARA_IMAGE={image_id}', env_path.read_text(), flags=re.MULTILINE), encoding='utf-8')
    # Read the manifest from the actual downloaded official service image.
    manifest = _run(state, ['run', '--rm', '--name', state['project'] + '-manifest',
        '--label', 'com.docker.compose.project=' + state['project'], '--network', 'none',
        '--memory', '256m', '--cpus', '1', '--entrypoint', 'cat', LOCK['images']['EXTRACT_IMAGE'], 'service_manifest.yml'],
        timeout=remaining(), log='extract-manifest-read.log').stdout.replace('${REGISTRY}', '')
    manifest_dir = Path(state['run_dir']) / 'manifests'
    (manifest_dir / 'extract.yml').write_text(manifest, encoding='utf-8')
    shutil.copyfile(ROOT / 'tools/assemblyline-yara/service_manifest.yml', manifest_dir / 'yara.yml')
    for name in ('extract.yml', 'yara.yml'):
        os.chmod(manifest_dir / name, 0o640)
    # Initialize schema with one upstream process before concurrent Rust/Python
    # startup. Their fresh-index creation otherwise races on an empty datastore.
    _compose(state, ['up', '-d', '--wait', '--wait-timeout', str(max(1, int(remaining()))),
        'elasticsearch', 'redis', 'minio'], timeout=remaining(), log='infrastructure-up.log')
    _compose(state, ['run', '--rm', '--no-deps', 'bootstrap'], timeout=remaining(), log='bootstrap.log')
    _compose(state, ['up', '-d', '--wait', '--wait-timeout', str(max(1, int(remaining()))),
        'ui', 'dispatcher', 'service-server'], timeout=remaining(), log='up.log')
    _compose(state, ['--profile', 'analysis', 'up', '-d', '--no-deps', 'extract', 'yara'], timeout=remaining(), log='analysis-up.log')
    key = Path(state['apikey_file']).read_text().strip()
    request = urllib.request.Request(state['base_url'] + '/api/v4/service/all/', headers={
        'x-user': state['user'], 'x-apikey': key})
    while True:
        try:
            with urllib.request.urlopen(request, timeout=min(10, remaining())) as response:
                body = json.load(response)
            api_response = body.get('api_response', {})
            items = api_response.get('items', []) if isinstance(api_response, dict) else api_response
            if body.get('api_error_message') == '' and len(items) >= 2:
                break
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(min(2, remaining()))
    return identity(path)


def identity(path: Path):
    state = _load(path)
    ps = _compose(state, ['ps', '--all', '--format', 'json'], log='ps.log').stdout
    rows = [json.loads(line) for line in ps.splitlines() if line.strip()]
    ids = [row['ID'] for row in rows]
    # Inspect in memory: Docker's full Config.Env contains ephemeral credentials.
    # Only the explicitly selected fields below are persisted as evidence.
    containers = json.loads(_run(state, ['inspect', *ids]).stdout) if ids else []
    sanitized = []
    for item in containers:
        cfg = item['HostConfig']
        sanitized.append({'id': item['Id'], 'name': item['Name'], 'image_id': item['Image'],
            'configured_image': item['Config']['Image'], 'state': item['State'],
            'memory_limit': cfg['Memory'], 'nano_cpus': cfg['NanoCpus'], 'privileged': cfg['Privileged'],
            'port_bindings': cfg['PortBindings'], 'networks': sorted(item['NetworkSettings']['Networks'])})
    images = {}
    for item in sanitized:
        img = json.loads(_run(state, ['image', 'inspect', item['image_id']]).stdout)[0]
        images[item['image_id']] = {'id': img['Id'], 'repo_digests': img.get('RepoDigests', []), 'architecture': img['Architecture'], 'os': img['Os']}
    manifest = {'schema_version': 1, 'project': state['project'], 'base_url': state['base_url'],
        'lock_sha256': state['lock_sha256'],
        'source_lock_sha256': hashlib.sha256((HERE / 'stack.lock.json').read_bytes()).hexdigest(),
        'containers': sanitized, 'images': images,
        'total_memory_limit': sum(item['memory_limit'] for item in sanitized)}
    Path(state['identity_file']).write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def down(path: Path):
    state = _load(path)
    _compose(state, ['--profile', 'analysis', '--profile', 'setup', 'down', '--volumes', '--remove-orphans', '--timeout', '20'],
             timeout=120, log='down.log')
    return {'project': state['project'], 'cleanup': 'complete'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prep = commands.add_parser('prepare')
    prep.add_argument('--output', type=Path, required=True)
    prep.add_argument('--docker')
    for command in ('up', 'down', 'identity'):
        child = commands.add_parser(command)
        child.add_argument('--state', type=Path, required=True)
        if command == 'up':
            child.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if args.command == 'prepare':
        print(prepare(args.output, args.docker))
    else:
        result = up(args.state, args.timeout) if args.command == 'up' else globals()[args.command](args.state)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
