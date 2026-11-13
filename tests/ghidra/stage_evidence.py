"""Stage only path-safe, hash-verified, credential-scanned public evidence."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from run import shareable


ROOT=Path(__file__).resolve().parents[2]


def sha(data): return hashlib.sha256(data).hexdigest()


def read_regular(root,relative):
    if not isinstance(relative,str) or not relative or '\\' in relative or ':' in relative:
        raise ValueError('Unsafe evidence path')
    name=PurePosixPath(relative)
    if name.is_absolute() or name.as_posix()!=relative or any(p in ('.','..') for p in name.parts):
        raise ValueError('Unsafe evidence path: '+relative)
    path=root
    for part in name.parts:
        path=path/part
        if path.is_symlink(): raise ValueError('Symbolic link in evidence: '+relative)
    if root not in path.resolve().parents or not path.is_file() or path.stat().st_size>128*1024**2:
        raise ValueError('Evidence must be a bounded regular file beneath its root: '+relative)
    return path.read_bytes()


def stage(source,destination):
    source,destination=Path(source).absolute(),Path(destination).absolute()
    if source.resolve()!=source or destination.resolve()!=destination:
        raise ValueError('Evidence roots must not contain symbolic links')
    if (ROOT/'target').resolve() not in destination.parents:
        raise ValueError('Staging destination must be a new directory under target/')
    destination.mkdir(parents=True,exist_ok=False)
    notices={
        'tests/assemblyline/live/config.UPSTREAM-LICENSE':('ASSEMBLYLINE-LICENSE.txt','603d78b114c839f96daa2847ada07d10d666d75cc214a75736b17d1d85417993'),
        'tools/assemblyline-yara/licenses/YARA-COPYING':('YARA-LICENSE.txt','efdabc1c1f655528b8c3a59b03668d446746d87273fab76f8af800b6e8891bd2'),
        'tools/assemblyline-yara/licenses/yara-python-LICENSE':('YARA-PYTHON-LICENSE.txt','c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08'),
        'tests/ghidra/licenses/ZIG-LICENSE':('ZIG-LICENSE.txt','5c537d6853e005298a285d508cff9ac7192cea23576c840d485b2b586a7ff177'),
    }
    verified={}
    for relative,(name,expected) in notices.items():
        data=read_regular(ROOT,relative).replace(b'\r\n',b'\n')
        if sha(data)!=expected: raise ValueError('Pinned upstream notice changed: '+relative)
        verified['notices/'+name]=data
    if (source/'report.json').is_file():
        raw=read_regular(source,'report.json');report=json.loads(raw)
        artifacts=report.get('artifacts')
        if not isinstance(artifacts,dict): raise ValueError('Report must positively allowlist artifacts')
        total=len(raw)
        credentials=[]
        for relative in ('stack/.env','stack/apikey'):
            if not (source/relative).is_file(): continue
            content=read_regular(source,relative).decode()
            if relative.endswith('apikey'): credentials.append(content.strip().encode())
            else:
                for line in content.splitlines():
                    if '=' in line:
                        key,value=line.split('=',1)
                        if value and any(p in key for p in ('PASSWORD','SECRET','KEY')): credentials.append(value.encode())
        for relative,expected in artifacts.items():
            if relative=='report.json' or not shareable(PurePosixPath(relative)):
                raise ValueError('Private or unapproved artifact: '+relative)
            if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected): raise ValueError('Invalid evidence SHA256')
            data=read_regular(source,relative)
            if sha(data)!=expected: raise ValueError('Evidence SHA256 mismatch: '+relative)
            total+=len(data)
            if total>512*1024**2: raise ValueError('Evidence exceeds the 512MiB staging bound')
            verified[relative]=data
        verified['report.json']=raw
        for relative,data in verified.items():
            if any(secret and secret in data for secret in credentials): raise ValueError('Appliance credential found in evidence: '+relative)
    # Copy nothing until every requested path and hash has been checked.
    for relative,data in verified.items():
        path=destination/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    print(json.dumps({'staged_files':len(verified),'source_report_present':(source/'report.json').is_file()}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args();stage(args.source,args.destination)
