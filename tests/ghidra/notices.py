"""Retain complete upstream notices from authenticated inputs with the evidence."""
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile

from pip_client import acquire


ROOT = Path(__file__).resolve().parents[2]


def collect(output):
    destination = Path(output) / 'upstream-notices'
    destination.mkdir(exist_ok=True)
    sources = {
        'ASSEMBLYLINE-LICENSE.txt': ROOT/'tests/assemblyline/live/config.UPSTREAM-LICENSE',
        'YARA-LICENSE.txt': ROOT/'tools/assemblyline-yara/licenses/YARA-COPYING',
        'YARA-PYTHON-LICENSE.txt': ROOT/'tools/assemblyline-yara/licenses/yara-python-LICENSE',
        'ZIG-LICENSE.txt': ROOT/'tests/ghidra/licenses/ZIG-LICENSE',
    }
    for name, source in sources.items():
        (destination/name).write_bytes(source.read_bytes().replace(b'\r\n',b'\n'))
    lock = json.loads((ROOT/'tools/ghidra-helper/upstream.lock.json').read_bytes())
    assets = ROOT/'target/ghidra/upstream-assets'
    for kind in ('ghidra','jdk'):
        data=(assets/lock[kind]['asset']).read_bytes()
        if len(data)!=lock[kind]['size'] or hashlib.sha256(data).hexdigest()!=lock[kind]['sha256']:
            raise RuntimeError('Notice archive differs from authenticated upstream pin: '+kind)
    with zipfile.ZipFile(assets/lock['ghidra']['asset']) as archive:
        names=[n for n in archive.namelist() if n.endswith('/LICENSE') and n.count('/')==1]
        if len(names)!=1: raise RuntimeError('Ghidra top-level notice is ambiguous')
        (destination/'GHIDRA-LICENSE.txt').write_bytes(archive.read(names[0]))
    with tarfile.open(assets/lock['jdk']['asset']) as archive:
        for name in ('LICENSE','ASSEMBLY_EXCEPTION','ADDITIONAL_LICENSE_INFO'):
            matches=[n for n in archive.getnames() if n.endswith('/legal/java.base/'+name)]
            if len(matches)!=1: raise RuntimeError('JDK core notice is ambiguous')
            (destination/('TEMURIN-'+name+'.txt')).write_bytes(archive.extractfile(matches[0]).read())
    pip=acquire(ROOT/'target/ghidra/pip')
    (destination/'PIP-LICENSE.txt').write_bytes((pip.parent/'LICENSE.PIP.txt').read_bytes())
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(destination.iterdir()) if p.is_file()}
    (destination/'notices.json').write_text(json.dumps({'notices':hashes,'scope':'full top-level/core notices for evidence; no engine archives distributed'},indent=2)+'\n')
    return hashes
