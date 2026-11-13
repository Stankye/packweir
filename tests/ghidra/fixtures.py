#!/usr/bin/env python3
"""Build nonce-bound ELF64/PE32+ static fixtures with a pinned real compiler.

Only the trusted compiler executes. None of the generated native files, wheel
contents, or package entry points are executed by this generator.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import time
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK_BYTES = (HERE / 'compiler.lock.json').read_bytes()
LOCK = json.loads(LOCK_BYTES)
MARKER = b'PACKWEIR_ASSEMBLYLINE_HARMLESS_MARKER_V1\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def docker_default():
    if os.name == 'nt':
        return r'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    path = '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
    return path if Path(path).exists() else 'docker'


def native(path, docker):
    path = str(Path(path).resolve())
    if os.name != 'nt' and docker.endswith('.exe'):
        return subprocess.check_output(['wslpath', '-w', path], text=True).strip()
    return path


def command(docker, args, log, timeout=120):
    result = subprocess.run([docker, *args], capture_output=True, timeout=timeout)
    Path(log).write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'Compiler provisioning failed ({result.returncode}); see {log}')
    return result.stdout.decode('utf-8', errors='replace').strip()


def acquire(path):
    item = LOCK['compiler']
    if not path.exists():
        start = time.monotonic()
        total = 0
        partial = path.with_suffix(path.suffix + '.part')
        with urllib.request.urlopen(item['url'], timeout=30) as stream, partial.open('wb') as output:
            while data := stream.read(1024 * 1024):
                total += len(data)
                if total > item['size'] or time.monotonic() - start > 180:
                    raise RuntimeError('Compiler download exceeded its byte or time bound')
                output.write(data)
        if partial.stat().st_size != item['size'] or sha(partial.read_bytes()) != item['sha256']:
            raise RuntimeError('Compiler download differs from the reviewed official pin')
        partial.replace(path)
    if path.stat().st_size != item['size'] or sha(path.read_bytes()) != item['sha256']:
        raise RuntimeError('Compiler archive differs from the reviewed official pin')


def section(data, kind):
    if kind == 'elf64':
        assert data[:7] == b'\x7fELF\x02\x01\x01'
        h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        assert h[1] == 62
        headers = [struct.unpack_from('<IIQQQQIIQQ', data, h[5] + i*h[10]) for i in range(h[11])]
        strings = headers[h[12]]
        names = data[strings[4]:strings[4]+strings[5]]
        matches = [h for h in headers if names[h[0]:].split(b'\0', 1)[0] == b'.pw_xor']
        if not matches:
            return None
        assert len(matches) == 1 and matches[0][1] == 1 and not matches[0][2] & 4
        return matches[0][4], matches[0][5]
    assert data[:2] == b'MZ'
    off = struct.unpack_from('<I', data, 60)[0]
    assert data[off:off+4] == b'PE\0\0'
    machine, count = struct.unpack_from('<HH', data, off+4)
    optional = struct.unpack_from('<H', data, off+20)[0]
    assert machine == 0x8664 and struct.unpack_from('<H', data, off+24)[0] == 0x20b
    headers = [data[off+24+optional+i*40:off+24+optional+(i+1)*40] for i in range(count)]
    matches = [h for h in headers if h[:8].split(b'\0', 1)[0] == b'.pw_xor']
    if not matches:
        return None
    assert len(matches) == 1 and not struct.unpack_from('<I', matches[0], 36)[0] & 0x20000000
    raw_size, raw_off = struct.unpack_from('<II', matches[0], 16)
    return raw_off, raw_size


def zip_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return stream.getvalue()


def wheel_bytes(project, files):
    wheel = {'ghidra_fixture/'+name: data for name, data in files.items()}
    dist = project.replace('-', '_')+'-0.1.0.dist-info/'
    wheel[dist+'METADATA'] = f'Metadata-Version: 2.1\nName: {project}\nVersion: 0.1.0\nSummary: Harmless static analysis data; never executed\n'.encode()
    wheel[dist+'WHEEL'] = b'Wheel-Version: 1.0\nGenerator: Packweir qualification\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    for name, data in sorted(wheel.items()):
        writer.writerow([name, 'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='), len(data)])
    writer.writerow([dist+'RECORD', '', ''])
    wheel[dist+'RECORD'] = stream.getvalue().encode()
    return zip_bytes(wheel)


def build_fixtures(output, docker=None, nonce=None):
    output = Path(output).resolve()
    if (ROOT / 'target').resolve() not in output.parents:
        raise ValueError('Fixture output must be a new directory under workspace target/')
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError('Fixture output directory must be empty')
    (output / 'compiler.lock.json').write_bytes(LOCK_BYTES)
    docker = docker or docker_default()
    nonce = nonce or secrets.token_hex(16)
    if not re.fullmatch('[a-f0-9]{32}', nonce):
        raise ValueError('Fixture nonce must be 32 lowercase hexadecimal characters')
    identity = f'{os.getuid()}:{os.getgid()}' if os.name != 'nt' else '1000:1000'
    toolchain = ROOT / 'target/ghidra-toolchain'
    toolchain.mkdir(exist_ok=True)
    archive = toolchain / 'zig.tar.xz'
    acquire(archive)
    shutil.copyfile(HERE / 'Dockerfile.compiler', toolchain / 'Dockerfile')
    license_bytes = (HERE / 'licenses/ZIG-LICENSE').read_bytes().replace(b'\r\n', b'\n')
    if sha(license_bytes) != LOCK['compiler']['license_sha256']:
        raise RuntimeError('Compiler notice differs from the complete upstream license')
    (output / 'LICENSE.ZIG.txt').write_bytes(license_bytes)
    tag = 'packweir/ghidra-fixture-compiler:zig-0.15.2-'+nonce
    command(docker, ['build', '--build-arg', 'BASE_IMAGE='+LOCK['base_image'], '--label', 'io.packweir.ghidra-fixture='+nonce,
                    '--tag', tag, native(toolchain, docker)], output/'compiler-build.log', 240)
    image = command(docker, ['image', 'inspect', tag, '--format', '{{.Id}}'], output/'compiler-image-id.log')
    command(docker, ['image', 'inspect', image], output/'compiler-image.json')
    probe_args = ['run', '--rm', '--network', 'none', '--read-only', '--user', identity, '--memory', '256m', '--cpus', '1', '--pids-limit', '128', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--label', 'io.packweir.ghidra-fixture='+nonce]
    version = command(docker, [*probe_args, '--name', 'packweir-ghidra-version-'+nonce[:12], image, 'version'], output/'compiler-version.log')
    if version != LOCK['compiler']['version']:
        raise RuntimeError('Actual compiler version differs from the reviewed archive')
    probe = "import hashlib,json; p='/opt/zig-x86_64-linux-0.15.2/zig'; h=hashlib.sha256(); f=open(p,'rb'); [h.update(b) for b in iter(lambda:f.read(1048576),b'')]; print(json.dumps({'binary_sha256':h.hexdigest()}))"
    actual_compiler = json.loads(command(docker, [*probe_args, '--name', 'packweir-ghidra-pin-'+nonce[:12], '--entrypoint', 'python', image, '-c', probe], output/'compiler-runtime.json'))
    if actual_compiler['binary_sha256'] != LOCK['compiler']['binary_sha256']:
        raise RuntimeError('Actual compiler executable differs from the reviewed official archive')
    source_dir = output/'source'
    binary_dir = output/'samples'
    source_dir.mkdir()
    binary_dir.mkdir()
    decoded = MARKER + b'Ghidra static fixture nonce: ' + nonce.encode() + b'\n'
    encoded = bytes(b ^ 0x5a for b in decoded)
    template = (HERE/'fixture.c.in').read_text()
    records, commands = {}, []
    for framed in (True, False):
        name = 'encoded' if framed else 'benign'
        source = template.replace('@NONCE@', nonce).replace('@KEY@', '90' if framed else '0').replace('@HAS_FRAME@', '1' if framed else '0').replace('@PAYLOAD_LENGTH@', str(len(encoded))).replace('@ENCODED_BYTES@', ','.join(str(b) for b in encoded))
        (source_dir/(name+'.c')).write_text(source, encoding='utf-8')
        for kind, target in LOCK['targets'].items():
            filename = name+'-'+kind+('.exe' if kind == 'pe32plus' else '.bin')
            args = ['cc', '-target', target, '-O0', '-g0', '-ffreestanding', '-fno-stack-protector', '-fno-sanitize=all', '-fno-builtin', '-nostdlib']
            args += ['-s', '-Wl,--entry,fixture_entry'] if kind == 'pe32plus' else ['-fno-pie', '-no-pie', '-Wl,-e,fixture_entry', '-Wl,--build-id=none']
            args += ['/src/'+name+'.c', '-o', '/out/'+filename]
            commands.append(args)
            command(docker, ['run', '--rm', '--name', 'packweir-ghidra-compile-'+nonce[:12]+'-'+name+'-'+kind,
                '--label', 'io.packweir.ghidra-fixture='+nonce, '--network', 'none', '--read-only', '--user', identity,
                '--memory', '1024m', '--cpus', '2', '--pids-limit', '128', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--env', 'SOURCE_DATE_EPOCH=1577836800',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777', '--mount', 'type=bind,source='+native(source_dir,docker)+',target=/src,readonly',
                '--mount', 'type=bind,source='+native(binary_dir,docker)+',target=/out', image, *args], output/(filename+'.compile.log'), 120)
            path = binary_dir/filename
            data = path.read_bytes()
            assert MARKER.rstrip(b'\n') not in data
            os.chmod(path, 0o644)
            region = section(data, kind)
            record = {'file': 'samples/'+filename, 'sha256': sha(data), 'size': len(data), 'kind': kind, 'generated_binary_executed': False}
            if framed:
                assert region and decoded not in data
                off, size = region
                count = struct.unpack_from('<I', data, off)[0]
                assert count == len(decoded) and count+4 <= size and data[off+4:off+4+count] == encoded
                record['derivation'] = {'operation': 'xor.decode', 'operation_version': '1', 'parameters': {'key_hex': '5a'},
                    'source_span': {'offset': off+4, 'length': count, 'sha256': sha(encoded)},
                    'output_sha256': sha(decoded), 'output_size': len(decoded)}
            else:
                assert region is None
            records[name+'-'+kind] = record
    def native_pair(prefix, contextual=True):
        files = {'elf64.bin': (binary_dir/(prefix+'-elf64.bin')).read_bytes(),
                 'pe32plus.exe': (binary_dir/(prefix+'-pe32plus.exe')).read_bytes(), '__init__.py': b''}
        if contextual:
            files['fixture.c'] = (source_dir/(prefix+'.c')).read_bytes()
            files['README.txt'] = b'Harmless static-analysis fixture data. Native files and package code are never executed.\n'
            files['LICENSE.txt'] = (ROOT/'LICENSE-MIT').read_bytes()
            files['BUILD.json'] = json.dumps({'nonce':nonce,'compiler_archive_sha256':LOCK['compiler']['sha256'],
                'native_sha256':{name:sha(data) for name,data in files.items() if name in ('elf64.bin','pe32plus.exe')}},sort_keys=True).encode()
        return files
    pair = native_pair('encoded')
    (binary_dir/'native-pair.zip').write_bytes(zip_bytes(pair))
    marker_wheel = binary_dir/'packweir_ghidra_fixture-0.1.0-py3-none-any.whl'
    marker_wheel.write_bytes(wheel_bytes('packweir-ghidra-fixture', pair))
    clean_pair = native_pair('benign')
    clean_wheel = binary_dir/'packweir_ghidra_clean_fixture-0.1.0-py3-none-any.whl'
    clean_wheel.write_bytes(wheel_bytes('packweir-ghidra-clean-fixture', clean_pair))
    review_wheel = binary_dir/'packweir_ghidra_review_fixture-0.1.0-py3-none-any.whl'
    review_wheel.write_bytes(wheel_bytes('packweir-ghidra-review-fixture', native_pair('benign', contextual=False)))
    assert MARKER.rstrip(b'\n') not in (binary_dir/'native-pair.zip').read_bytes()
    assert MARKER.rstrip(b'\n') not in (binary_dir/'packweir_ghidra_fixture-0.1.0-py3-none-any.whl').read_bytes()
    assert MARKER.rstrip(b'\n') not in clean_wheel.read_bytes() and MARKER.rstrip(b'\n') not in review_wheel.read_bytes()
    (binary_dir/'unsupported.txt').write_bytes(b'Unsupported text fixture '+nonce.encode()+b'\n')
    (binary_dir/'malformed-elf.bin').write_bytes(b'\x7fELF\x02\x01\x01'+b'\0'*9+nonce.encode())
    (binary_dir/'malformed-pe.exe').write_bytes(b'MZ'+b'\0'*58+struct.pack('<I',4096)+nonce.encode())
    (output/'decoded-expected.bin').write_bytes(decoded)
    manifest = {'schema_version': 1, 'nonce': nonce, 'binary_execution': False, 'compiler_lock_sha256': sha(LOCK_BYTES),
        'compiler_image': image, 'compiler_version': version, 'compile_commands': commands, 'fixtures': records,
        'expected_functions': ['fixture_entry', 'fixture_decode', 'fixture_checksum'], 'expected_pcode_opcode': 'INT_XOR',
        'wheels': {'clean': {'project': 'packweir-ghidra-clean-fixture', 'file': clean_wheel.relative_to(output).as_posix(), 'sha256': sha(clean_wheel.read_bytes())},
                   'marker': {'project': 'packweir-ghidra-fixture', 'file': marker_wheel.relative_to(output).as_posix(), 'sha256': sha(marker_wheel.read_bytes())},
                   'review': {'project': 'packweir-ghidra-review-fixture', 'file': review_wheel.relative_to(output).as_posix(), 'sha256': sha(review_wheel.read_bytes()), 'expected_unmapped_heuristic':'EXTRACT.16'}},
        'decoded_expected': {'file': 'decoded-expected.bin', 'sha256': sha(decoded), 'size': len(decoded)},
        'artifacts': {p.relative_to(output).as_posix(): sha(p.read_bytes()) for p in sorted(output.rglob('*')) if p.is_file()}}
    (output/'fixtures.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--docker')
    parser.add_argument('--nonce')
    args = parser.parse_args()
    result = build_fixtures(args.output, args.docker, args.nonce)
    print(json.dumps({'manifest': str(args.output/'fixtures.json'), 'nonce': result['nonce'], 'fixture_count': len(result['fixtures']), 'binary_execution': False}))
