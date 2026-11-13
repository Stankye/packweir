"""Real AL/Ghidra observations and actual gateway/native-client qualification."""
import base64
import hashlib
import html
import http.server
import json
from pathlib import Path
import re
import subprocess
import struct
import sys
import threading
import time
import urllib.parse
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT/'tests/assemblyline/live'))
from qualification import CaptureClient, collect_submission, digest, free_port, multipart, submission_params, timestamp, toml, write_json
from pip_client import install as pip_install

SERVICES = ['Extract', 'PackweirYARA', 'PackweirGhidra']
SERVICE_SPEC = {'Extract': {'continue_after_extract': True}}
MARKER = b'PACKWEIR_ASSEMBLYLINE_HARMLESS_MARKER_V1'
TITLE = 'Packweir binary analysis manifest v1'
INFORMATIONAL_WARNINGS = [
    "Ignoring leading '_' chars on no-return name '___raise_securityfailure' specified in file: /opt/ghidra/Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn",
    "Ignoring leading '_' chars on no-return name '___report_rangecheckfailure' specified in file: /opt/ghidra/Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn",
]


class ProductCaptureClient(CaptureClient):
    """Retain exact binary HTTP bodies beside the readable/redacted capture."""
    def request(self,*args,**kwargs):
        status,body,path,proof=super().request(*args,**kwargs)
        if path.read_bytes()!=body and not any(secret.encode() in body for secret in self.secrets):
            raw_path=path.with_suffix('.raw.bin')
            raw_path.write_bytes(body)
            proof['raw_body_file']=raw_path.name
            proof['saved_raw_response_sha256']=digest(body)
            write_json(path.with_suffix('.http.json'),proof)
            write_json(self.directory/'index.json',self.index)
        return status,body,path,proof


def framed(files):
    h = hashlib.sha256()
    for name, data in sorted(files.items()):
        h.update(name.encode()+b'\0'+len(data).to_bytes(8, 'big')+data)
    return h.hexdigest()


def expected_producer():
    tool = ROOT/'tools/ghidra-helper'
    lock = json.loads((tool/'upstream.lock.json').read_bytes())
    archive = ROOT/'target/ghidra/upstream-assets'/lock['ghidra']['asset']
    with zipfile.ZipFile(archive) as z:
        matches = [n for n in z.namelist() if n.endswith('/Ghidra/Features/Decompiler/os/linux_x86_64/decompile')]
        if len(matches) != 1:
            raise RuntimeError('Official Ghidra archive native decompiler is ambiguous')
        native = digest(z.read(matches[0]))
    value = {'engine': 'Ghidra', 'engine_version': lock['ghidra']['version'], 'engine_archive_sha256': lock['ghidra']['sha256'],
             'jdk_version': lock['jdk']['version'], 'jdk_archive_sha256': lock['jdk']['sha256'], 'decompiler_sha256': native,
             'scripts_sha256': framed({name: (tool/'scripts'/name).read_bytes() for name in ('PackweirPre.java', 'PackweirPost.java', 'PackweirThrow.java')}),
             'profile_sha256': digest((tool/'profile.json').read_bytes()),
             'driver_sha256': framed({'runtime.py': (tool/'runtime.py').read_bytes(),
                 'service.py': (ROOT/'tools/assemblyline-ghidra/packweir_ghidra/service.py').read_bytes(),
                 '__init__.py': (ROOT/'tools/assemblyline-ghidra/packweir_ghidra/__init__.py').read_bytes()})}
    value['identity_sha256'] = digest(json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode())
    return value


def manifest_from(result):
    sections = [s for s in result['result']['sections'] if s.get('title_text') == TITLE]
    if len(sections) != 1:
        raise RuntimeError('Real SDK result must retain exactly one typed Ghidra manifest')
    return json.loads(sections[0]['body'])


def verify_manifest(value, original, producer, encoded_expected=None):
    assert value['schema_version'] == 'packweir.binary-analysis.v1'
    assert value['input']['sha256'] == digest(original) and value['input']['size'] == len(original)
    assert value['producer'] == producer
    a = value['analysis']
    assert a['status'] == 'complete' and not a['timed_out'] and not a['errors'] and not a['export_truncated']
    assert a['warnings'] == (INFORMATIONAL_WARNINGS if original[:2] == b'MZ' else [])
    assert a['functions_total'] >= 3 and a['functions_total'] == a['functions_decompiled'] and a['functions_failed'] == 0
    assert set(a['requested_capabilities']) == {'decompile', 'pcode', 'decode_xor'}
    assert all(a['capabilities'][n] == 'complete' for n in a['requested_capabilities'])
    names = {v['name'] for v in value['observations'] if v['kind'] == 'function'}
    assert {'fixture_entry', 'fixture_decode', 'fixture_checksum'} <= names
    kinds = {v['kind'] for v in value['observations']}
    assert {'header', 'section', 'symbol', 'function', 'language', 'compiler'} <= kinds
    outputs = []
    for item in value['outputs']:
        data = base64.b64decode(item['data_base64'], validate=True)
        assert len(data) == item['size'] and digest(data) == item['sha256']
        d = item['derivation']
        assert d['input_sha256'] == digest(original)
        for span in d['source_spans']:
            assert span['length'] > 0 and span['offset']+span['length'] <= len(original)
            assert digest(original[span['offset']:span['offset']+span['length']]) == span['sha256']
        if item['kind'] == 'decoded_bytes':
            assert d['operation'] == 'xor.decode' and d['version'] == '1' and len(d['source_spans']) == 1
            span = d['source_spans'][0]
            key = bytes.fromhex(d['parameters']['key_hex'])
            source = original[span['offset']:span['offset']+span['length']]
            assert data == bytes(b ^ key[i % len(key)] for i, b in enumerate(source))
        outputs.append((item['kind'], data))
    assert any(kind == 'decompiled_c' and b'fixture_decode' in data for kind, data in outputs)
    assert any(kind == 'pcode' and b'INT_XOR' in data for kind, data in outputs)
    decoded = [data for kind,data in outputs if kind == 'decoded_bytes']
    assert decoded == ([encoded_expected] if encoded_expected is not None else [])
    return {'functions': sorted(names), 'output_count': len(outputs), 'decoded_count': len(decoded),
            'peak_rss_bytes': max([int(v['value']) for v in value['observations'] if v['name'] == 'process_group_peak_rss_bytes'] or [0])}


class Origin:
    def __init__(self, fixture_root, fixture_manifest, output):
        self.requests, self.paths, self.samples = [], {}, {}
        self.wheels = fixture_manifest['wheels']
        routes, indexes = {}, {}
        self.routes = routes
        for name,item in fixture_manifest['fixtures'].items():
            route = '/maven/fixtures/'+name+'/0.1.0/'+name+'-0.1.0.bin'
            data = (fixture_root/item['file']).read_bytes()
            self.paths[name] = '/r/native'+route.removeprefix('/maven')
            self.samples[name] = data
            routes[route] = data
        for name,item in self.wheels.items():
            file = fixture_root/item['file']
            self.samples['wheel-'+name] = file.read_bytes()
            routes['/pypi/packages/'+file.name] = file.read_bytes()
            indexes['/pypi/simple/'+item['project']+'/'] = ('<a href="../../packages/'+file.name+'#sha256='+item['sha256']+'">'+file.name+'</a>').encode()
        requests = self.requests
        lock = threading.Lock()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with lock:
                    requests.append({'path':self.path,'at':timestamp(),'authorization_present':bool(self.headers.get('Authorization'))})
                    write_json(output/'package-origin-requests.json', requests)
                if self.headers.get('Authorization'):
                    self.send_error(400, 'Gateway credentials reached the fixture origin')
                    return
                body = routes.get(self.path, indexes.get(self.path))
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/html' if self.path in indexes else 'application/octet-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self,*args): pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
    def add_native(self,name,data):
        route='/maven/fixtures/'+name+'/0.1.0/'+name+'-0.1.0.bin'
        self.routes[route]=data
        self.samples[name]=data
        self.paths[name]='/r/native'+route.removeprefix('/maven')
    def __enter__(self): self.thread.start(); return self
    def __exit__(self,*args): self.server.shutdown(); self.server.server_close(); self.thread.join(5)


def calibrate(client, samples, fixture_root, output, producer):
    known = {digest(data):data for data in samples.values()}
    decoded_expected = (fixture_root/'decoded-expected.bin').read_bytes()
    known[digest(decoded_expected)] = decoded_expected
    for data in samples.values():
        if data[:2] == b'PK':
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for name in archive.namelist():
                    content = archive.read(name); known[digest(content)] = content
    # Official Extract's 7-Zip fallback also emits file-backed PE sections.
    # Recover their bytes independently from the supplied PE headers, so YARA
    # metadata is checked against actual local bytes rather than server claims.
    section_spans=[]
    for original in list(known.values()):
        if original[:2]!=b'MZ' or len(original)<64: continue
        pe=struct.unpack_from('<I',original,60)[0]
        if pe+24>len(original) or original[pe:pe+4]!=b'PE\0\0': continue
        count=struct.unpack_from('<H',original,pe+6)[0]
        optional=struct.unpack_from('<H',original,pe+20)[0]
        assert count<=96 and pe+24+optional+count*40<=len(original)
        for index in range(count):
            position=pe+24+optional+40*index
            name=original[position:position+8].rstrip(b'\0').decode('ascii')
            virtual_size,_,raw_size,offset=struct.unpack_from('<IIII',original,position+8)
            assert offset+raw_size<=len(original)
            for size in set((raw_size,min(raw_size,virtual_size))):
                if not size: continue
                data=original[offset:offset+size]
                known[digest(data)]=data
                section_spans.append({'input_sha256':digest(original),'name':name,'offset':offset,'length':size,'sha256':digest(data)})
    write_json(output/'independent-native-sections.json',section_spans)
    inventory,_,_,envelope = client.api('/api/v4/service/all/','service-inventory')
    installed = {item['name']:item for item in inventory}
    assert all(name in installed and installed[name]['enabled'] and not installed[name]['is_external'] for name in SERVICES)
    for name in SERVICES:
        client.api('/api/v4/service/'+name+'/', 'effective-'+name)
    records, pins, observations = {}, {}, []
    for name,data in samples.items():
        metadata = {'name':name,'params':submission_params(SERVICES,SERVICE_SPEC,'TLP:C'), 'metadata':{'packweir_ghidra_calibration':output.name}}
        body,headers = multipart(metadata,data)
        accepted,_,_,_ = client.api('/api/v4/submit/','calibration-'+name+'-accepted',data=body,headers=headers,
            request_proof={'json':metadata,'artifact_sha256':digest(data),'artifact_size':len(data)})
        record = collect_submission(client,accepted['sid'],'calibration-'+name,timeout=360)
        record['submission_id'] = accepted['sid']; records[name] = record
        for key,result in record['report']['results'].items():
            service = result['response']['service_name']
            assert service in SERVICES
            if key.endswith('.e'):
                # Official Extract produces empty cached results on native/text
                # files. These are retained as out-of-scope evidence, never as
                # authenticated execution metadata or a calibrated service pin.
                assert service == 'Extract' and result['result']['score'] == 0
                assert not result['response']['extracted'] and not result['result']['sections']
                continue
            parts = key.split('.'); assert len(parts) == 4 and parts[3].startswith('c')
            pin = {'version':result['response']['service_version'],'tool_version':result['response'].get('service_tool_version'),
                   'configuration_key':parts[3][1:],'applies_to':{'Extract':['archive/zip'],'PackweirYARA':[],
                       'PackweirGhidra':['executable/linux/','executable/windows/']}[service]}
            if service in pins: assert pins[service] == pin
            pins[service] = pin
            source = known[result['sha256']]
            if service == 'PackweirGhidra':
                value = manifest_from(result)
                encoded = decoded_expected if b'.pw_xor' in source else None
                observations.append({'input_sha256':digest(source),**verify_manifest(value,source,producer,encoded)})
            elif service == 'PackweirYARA':
                sections = [s for s in result['result']['sections'] if s['title_text'] == 'Completed bounded YARA static scan']; assert len(sections) == 1
                execution = json.loads(sections[0]['body'])
                assert execution['input_sha256'] == digest(source) and execution['input_size'] == len(source)
                assert execution['matching_rules'] == (['PackweirQualificationMarker'] if MARKER in source else [])
    assert set(pins) == set(SERVICES)
    policy = {'required_services':pins,'deny_rules':[{'service':'PackweirYARA','heuristic_id':'PACKWEIRYARA.1','signature':'PackweirQualificationMarker'}],
              'informational_rules':[{'service':'Extract','heuristic_id':'EXTRACT.1','signature':None}], 'allow_empty_files':True,'max_result_age_seconds':86400}
    write_json(output/'policy.json',policy); write_json(output/'calibration.json',records); write_json(output/'ghidra-observations.json',observations)
    return policy,envelope['api_server_version'],records


def configuration(output, port, origin_port, state, policy, server_version, producer, context='initial', acknowledge_warnings=True):
    values = {'listen':f'127.0.0.1:{port}','public_url':f'http://127.0.0.1:{port}/','allow_private_upstreams':True,
        'storage':{'kind':'fs','root':str(output/'blobs')}, 'policy':{'revision':'real-ghidra-static-v1','required':['behavior'],'deny_on_failure':['behavior']},
        'repositories':{'native':{'ecosystem':'maven','upstream':f'http://127.0.0.1:{origin_port}/maven/','retain':True},
                        'wheels':{'ecosystem':'pypi','upstream':f'http://127.0.0.1:{origin_port}/pypi/simple/',
                            'download_origins':[f'http://127.0.0.1:{origin_port}/'],'retain':True}},
        'remote_scanners':{'behavior':{'kind':'assemblyline','endpoint':state['base_url'].rstrip('/')+'/', 'server_version':server_version,
            'user_env':'PACKWEIR_LIVE_AL_USER','api_key_env':'PACKWEIR_LIVE_AL_KEY','allow_upload':True,'classification':'TLP:C','retention_days':1,
            'profile_revision':'real-ghidra-static-v1-'+context,'service_spec':SERVICE_SPEC,'policy':policy,
            'binary_analysis':{'service':'PackweirGhidra','identity_sha256':producer['identity_sha256'],
                'required_capabilities':['decompile','pcode','decode_xor'],'candidate_kinds':['elf','pe'],
                'informational_warnings':INFORMATIONAL_WARNINGS if acknowledge_warnings else []},
            'allow_private_network':True,'allow_insecure_http':True,'allow_external_services':False,'allow_privileged_services':True,
            'request_timeout_seconds':15,'analysis_timeout_seconds':360,'poll_interval_seconds':1,'max_poll_failures':2}}}
    path=output/('packweir-'+context+'.toml'); path.write_text('\n'.join(k+'='+toml(v) for k,v in values.items())+'\n')
    return path


def qualify(state, output, executable, database_url, sql, command, base_environment=None, secret_register=None):
    output = Path(output)
    fixture_root = output/'fixtures'
    fixtures = json.loads((fixture_root/'fixtures.json').read_bytes())
    key = Path(state['apikey_file']).read_text().strip()
    private = [key,state['user']]
    for line in (Path(state['run_dir'])/'.env').read_text().splitlines():
        if '=' in line:
            name,value=line.split('=',1)
            if value and any(part in name for part in ('PASSWORD','SECRET','KEY')): private.append(value)
    client=CaptureClient(state['base_url'],output/'server-captures',{'X-USER':state['user'],'X-APIKEY':key},private)
    producer=expected_producer(); write_json(output/'ghidra-producer.json',producer)
    admin,read=uuid.uuid4().hex+uuid.uuid4().hex,uuid.uuid4().hex+uuid.uuid4().hex
    if secret_register: secret_register([admin,read])
    environment=dict(base_environment or __import__('os').environ,DATABASE_URL=database_url,PACKWEIR_ADMIN_TOKEN=admin,PACKWEIR_READ_TOKEN=read,
                     PACKWEIR_LIVE_AL_USER=state['user'],PACKWEIR_LIVE_AL_KEY=key,RUST_LOG='packweir=info')
    results, receipts, capture_cases = {}, {}, []
    decoded=(fixture_root/'decoded-expected.bin').read_bytes(); decoded_sha=digest(decoded)
    with Origin(fixture_root,fixtures,output) as origin:
        policy,server_version,calibration=calibrate(client,origin.samples,fixture_root,output,producer)
        port=free_port(); config=configuration(output,port,origin.server.server_port,state,policy,server_version,producer)
        gateway=None; gateway_log=None
        product=ProductCaptureClient(f'http://127.0.0.1:{port}',output/'product-captures',{'Authorization':'Bearer '+admin},private+[admin,read])

        def start_gateway(label):
            nonlocal gateway,gateway_log
            command([str(executable),'--config',str(config),'validate'],label+'-validate.log',30,env=environment)
            gateway_log=(output/(label+'-gateway.log')).open('w',encoding='utf-8')
            gateway=subprocess.Popen([str(executable),'--config',str(config),'serve'],cwd=ROOT,env=environment,stdout=gateway_log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+45
            while True:
                if gateway.poll() is not None: raise RuntimeError('actual gateway exited: '+label)
                try:
                    status,_,_,_=product.request('/ready',label+'-ready',timeout=3)
                    if status==200: return
                except OSError: pass
                if time.monotonic()>deadline: raise TimeoutError('gateway readiness: '+label)
                time.sleep(.5)

        def stop_gateway():
            if gateway is not None:
                gateway.terminate()
                try: gateway.wait(15)
                except subprocess.TimeoutExpired: gateway.kill(); gateway.wait(5)
            if gateway_log is not None: gateway_log.close()

        def ledger(subject):
            return sql("SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM (SELECT id,job_id,subject,configuration,state,remote_id,created_at,deadline_at,error "
                       f"FROM remote_analysis WHERE subject='{subject}' ORDER BY created_at) t")

        def worker(label):
            command([str(executable),'--config',str(config),'worker','--once'],label+'.log',120,env=environment)

        def due(subject):
            sql(f"UPDATE jobs SET not_before=now()-interval '1 second' WHERE subject='{subject}'; UPDATE remote_analysis SET next_poll_at=now()-interval '1 second' WHERE subject='{subject}';",json_result=False)

        def outputs(subject,label,configuration_id,complete=True):
            endpoint='/api/v1/artifacts/'+subject+'/analysis-outputs'
            status,body,_,_=product.request(endpoint,label+'-outputs'); assert status==200
            data=json.loads(body); assert data['approval_effect']=='none'
            rows=[r for r in data['outputs'] if r['configuration']==configuration_id]
            assert rows and all(r['subject']==subject and r['approval_effect']=='none' and r['producer_identity_sha256']==producer['identity_sha256'] for r in rows)
            for row in rows:
                metadata=row['metadata']
                assert metadata['validation']['source_spans_verified'] is True
                assert metadata['validation']['xor_recomputed']==(row['kind']=='decoded_bytes')
                assert metadata['validation']['semantic_equivalence_verified'] is False
                assert metadata['manifest_validation']['complete'] is complete
                assert metadata['manifest_validation']['input_bytes_verified'] is True
            denied,_,_,_=product.request(endpoint,label+'-outputs-read-denied',headers={'Authorization':'Bearer '+read}); assert denied in (401,403)
            for row in rows:
                status,content,_,proof=product.request(endpoint+'/'+row['id'],label+'-output-'+row['id'])
                assert status==200 and digest(content)==row['output_sha256'] and len(content)==row['size']
                headers={key.lower():value for key,value in proof['response_headers'].items()}
                assert headers.get('content-disposition')=='attachment'
                assert headers.get('x-content-type-options')=='nosniff'
            receipts[label]=rows; write_json(output/'analysis-output-receipts.json',receipts)
            return rows

        def process(name,label=None,warning_control=False):
            label=label or name; data=origin.samples[name]; subject=digest(data)
            old=ledger(subject)
            wheel_name=name.removeprefix('wheel-') if name.startswith('wheel-') else None
            wheel_route=None
            if wheel_name:
                item=fixtures['wheels'][wheel_name]
                status,index,_,_=product.request('/r/wheels/'+item['project']+'/',label+'-simple-index',headers={'Authorization':'Bearer '+read})
                assert status==200
                hrefs=re.findall(r'href="([^"]+)"',index.decode())
                assert len(hrefs)==1
                parsed=urllib.parse.urlsplit(html.unescape(hrefs[0]))
                assert parsed.hostname=='127.0.0.1' and parsed.port==port and not parsed.username and not parsed.password
                wheel_route=parsed.path+('?' + parsed.query if parsed.query else '')
                pip_result=pip_install(item['project'],f'http://127.0.0.1:{port}/r/wheels/',item['sha256'],output/'pip-targets'/label/'pending',output/'pip-clients'/label/'pending',read)
                assert pip_result['exit_code']!=0 and not pip_result['installed_file_sha256']
                status,pending,_,_=product.request(wheel_route,label+'-wheel-pending',headers={'Authorization':'Bearer '+read})
                assert status==503 and pending!=data
            else:
                status,body,_,_=product.request(origin.paths[name],label+'-initial',headers={'Authorization':'Bearer '+read}); assert status==503 and body!=data
            deadline=time.monotonic()+480; submitted=None
            while submitted is None:
                due(subject); worker(label+'-submit')
                rows=ledger(subject); new=[r for r in rows if r['id'] not in {v['id'] for v in old}]
                if new: assert len(new)==1; submitted=new[0]
                if time.monotonic()>deadline: raise TimeoutError('new durable submission: '+label)
            assert submitted['remote_id'] and submitted['state']=='submitted'
            captured=collect_submission(client,submitted['remote_id'],'product-'+label,timeout=360)
            while True:
                due(subject); worker(label+'-poll')
                rows=ledger(subject); current=next(r for r in rows if r['id']==submitted['id'])
                if current['state'] in ('complete','failed'): break
                if time.monotonic()>deadline: raise TimeoutError('product analysis: '+label)
                time.sleep(1)
            assert current['state']=='complete'
            _,body,_,_=product.request('/api/v1/artifacts/'+subject,label+'-inspection'); inspection=json.loads(body)
            evidence=[e for e in inspection['evidence'] if e['check']=='behavior']; assert len(evidence)==1
            e=evidence[0]; details=e['details']
            assert details['subject']==subject and details['submission_id']==submitted['remote_id']
            expected='inconclusive' if warning_control or name=='wheel-review' else 'fail' if name.startswith('encoded-') or name=='wheel-marker' else 'pass'
            assert e['outcome']==expected
            binary=details['binary_analysis']
            assert not binary['missing_inputs']
            native_names=[('encoded-' if wheel_name=='marker' else 'benign-')+kind for kind in ('elf64','pe32plus')] if wheel_name else [name]
            native_inputs={fixtures['fixtures'][n]['sha256']:(fixture_root/fixtures['fixtures'][n]['file']).read_bytes() for n in native_names}
            assert binary['local_native_inputs']==len(native_inputs) and binary['processed_inputs']==len(native_inputs)
            assert {m['input_sha256'] for m in binary['manifests']}==set(native_inputs)
            for item in binary['manifests']:
                native=native_inputs[item['input_sha256']]
                verify_manifest(item['manifest'],native,producer,decoded if b'.pw_xor' in native else None)
            if warning_control:
                assert name=='benign-pe32plus' and details['coverage_complete'] is False and binary['coverage_complete'] is False
                assert details['coverage_reasons']==['binary analysis observations or derivation coverage are incomplete']
                assert binary['reasons']==['binary analysis on '+subject+' is incomplete']
                assert len(binary['manifests'])==1
                validation=binary['manifests'][0]['validation']
                assert validation['reasons']==['analysis contains unacknowledged warnings']
                assert validation['unacknowledged_warnings']==INFORMATIONAL_WARNINGS and not validation['acknowledged_warnings']
                assert not details['matched_deny_rules']
            else:
                assert details['coverage_complete'] is True and not details['coverage_reasons']
                assert binary['coverage_complete'] is True and not binary['reasons']
            assert all(v['status']=='complete' for v in details['coverage'] if v.get('applicable') is True)
            full=captured['report']
            original_yara=[r for r in full['results'].values() if r['sha256']==subject and r['response']['service_name']=='PackweirYARA']
            assert len(original_yara)==1 and original_yara[0]['result']['score']==0
            for native_sha in native_inputs:
                native_yara=[r for r in full['results'].values() if r['sha256']==native_sha and r['response']['service_name']=='PackweirYARA']
                assert len(native_yara)==1 and native_yara[0]['result']['score']==0
            if expected=='fail':
                assert MARKER not in data and details['matched_deny_rules']
                deny=[f for f in details['findings'] if f['disposition']=='deny']; assert deny
                assert all(f['sha256']==decoded_sha and f['service']=='PackweirYARA' and f['heuristic']['heur_id']=='PACKWEIRYARA.1'
                           and any(s['name']=='PackweirQualificationMarker' for s in f['heuristic']['signature']) for f in deny)
                edges={v['parent_sha256'] for v in details['extracted'] if v['child_sha256']==decoded_sha and v['service']=='PackweirGhidra'}
                expected_parents={fixtures['fixtures'][n]['sha256'] for n in ('encoded-elf64','encoded-pe32plus')} if name=='wheel-marker' else {subject}
                assert edges==expected_parents
            elif name=='wheel-review':
                assert not details['matched_deny_rules'] and any(f['service']=='Extract' and f['heuristic']['heur_id']=='EXTRACT.16' and f['disposition']=='review' for f in details['findings'])
            rows=outputs(subject,label,current['configuration'],complete=not warning_control)
            if name=='wheel-marker':
                decoded_rows=[r for r in rows if r['kind']=='decoded_bytes']; assert len(decoded_rows)==2
                assert {r['input_sha256'] for r in decoded_rows}==expected_parents and {r['output_sha256'] for r in decoded_rows}=={decoded_sha}
            if wheel_name:
                item=fixtures['wheels'][wheel_name]
                installed=pip_install(item['project'],f'http://127.0.0.1:{port}/r/wheels/',item['sha256'],output/'pip-targets'/label/'final',output/'pip-clients'/label/'final',read)
                if expected=='pass':
                    assert installed['exit_code']==0
                    for kind in ('elf64','pe32plus'):
                        member='ghidra_fixture/'+('elf64.bin' if kind=='elf64' else 'pe32plus.exe')
                        assert installed['installed_file_sha256'][member]==fixtures['fixtures']['benign-'+kind]['sha256']
                else: assert installed['exit_code']!=0 and not installed['installed_file_sha256']
                status,served,_,_=product.request(wheel_route,label+'-wheel-delivery',headers={'Authorization':'Bearer '+read})
                assert status==(200 if expected=='pass' else 503 if expected=='inconclusive' else 403)
                assert (served==data)==(expected=='pass')
            else:
                status,served,_,_=product.request(origin.paths[name],label+'-delivery',headers={'Authorization':'Bearer '+read})
                assert status==(200 if expected=='pass' else 503 if expected=='inconclusive' else 403)
                assert (served==data)==(expected=='pass')
            result={'subject':subject,'submission_id':submitted['remote_id'],'ledger':current,'outcome':e['outcome'],'delivery_status':status,
                    'captured':captured,'inspection':inspection,'output_receipt_ids':[r['id'] for r in rows]}
            results[label]=result; write_json(output/'product-results.json',results)
            return result

        try:
            config=configuration(output,port,origin.server.server_port,state,policy,server_version,producer,context='conservative-pe',acknowledge_warnings=False)
            start_gateway('conservative-pe')
            process('benign-pe32plus','pe-unacknowledged-catalog-warnings',warning_control=True)
            stop_gateway()
            config=configuration(output,port,origin.server.server_port,state,policy,server_version,producer)
            start_gateway('initial')
            for name in ('benign-elf64','benign-pe32plus','encoded-elf64','encoded-pe32plus','wheel-clean','wheel-marker','wheel-review'):
                process(name)
            # A true new local context must get a new SID and new immutable
            # output receipts while reusing exact old vendor cache records.
            before=results['wheel-clean']; stop_gateway()
            compose=[state['docker'],'compose','--project-name',state['project'],'--file',state['compose_file'],'--env-file',str(Path(state['run_dir'])/'.env'), '--profile','analysis','--profile','ghidra']
            if __import__('os').name!='nt' and state['docker'].endswith('.exe'):
                compose[compose.index('--file')+1]=subprocess.check_output(['wslpath','-w',state['compose_file']],text=True).strip()
                compose[compose.index('--env-file')+1]=subprocess.check_output(['wslpath','-w',str(Path(state['run_dir'])/'.env')],text=True).strip()
            command(compose+['restart','--timeout','15','yara','ghidra'],'custom-service-restart.log',60)
            config=configuration(output,port,origin.server.server_port,state,policy,server_version,producer,context='after-custom-restart')
            start_gateway('after-custom-restart')
            after=process('wheel-clean','wheel-clean-after-restart')
            assert before['submission_id']!=after['submission_id'] and before['ledger']['configuration']!=after['ledger']['configuration']
            old_results=before['captured']['report']['results']; new_results=after['captured']['report']['results']
            assert set(old_results)==set(new_results)
            full_keys=[k for k in old_results if not k.endswith('.e')]
            assert all(old_results[k]['created']==new_results[k]['created'] for k in full_keys)
            assert {'PackweirYARA','PackweirGhidra'} <= {old_results[k]['response']['service_name'] for k in full_keys}
            assert set(before['output_receipt_ids']).isdisjoint(after['output_receipt_ids'])
            _,body,_,_=product.request('/api/v1/artifacts/'+after['subject']+'/analysis-outputs','restart-all-receipts')
            retained_receipts={r['id'] for r in json.loads(body)['outputs']}
            assert set(before['output_receipt_ids'])|set(after['output_receipt_ids'])<=retained_receipts
            write_json(output/'restart-cache-proof.json',{'old_submission':before['submission_id'],'new_submission':after['submission_id'],
                'all_actual_result_keys_stable':True,'all_full_record_creation_times_preserved':True,
                'full_records_compared':len(full_keys),'ui_synthetic_empty_records_excluded':len(old_results)-len(full_keys),
                'both_restarted_custom_services_have_preserved_full_records':True,'new_context_receipts':True,'old_receipts_retained':True})
            # This SHA was never calibrated. Stopping only this run's required
            # Ghidra worker leaves a genuine unfinished vendor submission.
            pending_name='ghidra-unavailable'
            pending_data=origin.samples['benign-elf64']+b'\0PACKWEIR_GHIDRA_UNAVAILABLE_'+fixtures['nonce'].encode()
            origin.add_native(pending_name,pending_data)
            pending_sha=digest(pending_data)
            assert not ledger(pending_sha)
            command(compose+['stop','--timeout','10','ghidra'],'ghidra-unavailable-stop.log',45)
            try:
                status,served,_,_=product.request(origin.paths[pending_name],'ghidra-unavailable-initial',headers={'Authorization':'Bearer '+read})
                assert status==503 and served!=pending_data
                first=[]
                for attempt in range(16):
                    due(pending_sha); worker('ghidra-unavailable-submit-'+str(attempt))
                    first=ledger(pending_sha)
                    if first: break
                assert len(first)==1 and first[0]['state']=='submitted' and first[0]['remote_id']
                remote,status_file,_,_=client.api('/api/v4/submission/'+first[0]['remote_id']+'/', 'ghidra-unavailable-real-status')
                assert remote['state']=='submitted'
                due(pending_sha); worker('ghidra-unavailable-poll')
                pending=ledger(pending_sha)
                assert len(pending)==1 and pending[0]['state']=='submitted' and pending[0]['remote_id']==first[0]['remote_id']
                sql(f"UPDATE remote_analysis SET deadline_at=now()+interval '1 second' WHERE subject='{pending_sha}';",json_result=False)
                time.sleep(1.1); due(pending_sha); worker('ghidra-unavailable-expire')
                expired=ledger(pending_sha)
                assert len(expired)==1 and expired[0]['id']==first[0]['id'] and expired[0]['state']=='failed'
                status,served,_,_=product.request(origin.paths[pending_name],'ghidra-unavailable-delivery',headers={'Authorization':'Bearer '+read})
                assert status==503 and served!=pending_data
                _,body,_,_=product.request('/api/v1/artifacts/'+pending_sha,'ghidra-unavailable-inspection')
                inspection=json.loads(body)
                assert not any(e['check']=='behavior' and e['outcome']=='pass' for e in inspection['evidence'])
                _,body,_,_=product.request('/api/v1/artifacts/'+pending_sha+'/analysis-outputs','ghidra-unavailable-outputs')
                assert not json.loads(body)['outputs']
                fault={'kind':'required_actual_ghidra_worker_stopped_then_local_deadline_shortened','subject':pending_sha,
                    'submission_id':first[0]['remote_id'],'initial':first,'pending':pending,'expired':expired,
                    'server_status_file':status_file.relative_to(output).as_posix(),'delivery_status':status,'analysis_outputs':0,'inspection':inspection}
                results[pending_name]=fault
                write_json(output/'ghidra-unavailable.json',fault); write_json(output/'product-results.json',results)
            finally:
                command(compose+['start','ghidra'],'ghidra-unavailable-restore.log',45)
            assert not any(v['authorization_present'] for v in origin.requests)
            for alias,name in [('benign','benign-elf64'),('harmless-finding','encoded-elf64'),('archive-child','wheel-marker')]:
                result=results[name]; c=result['captured']; capture_cases.append({'name':alias,'subject':result['subject'],'submission_id':result['submission_id'],
                    'captured_at':c['captured_at'],'report_file':c['report_file'],'tree_file':c['tree_file'],'policy_file':'policy.json'})
            write_json(output/'live-capture-manifest.json',{'provenance':'authenticated_real_assemblyline_v4','cases':capture_cases})
        finally:
            stop_gateway()
    return {'cases':results,'manifest':'live-capture-manifest.json','server_version':server_version,'producer':producer,
            'fixture_nonce':fixtures['nonce'],'analysis_output_receipt_count':sum(len(v) for v in receipts.values())}
