"""Disposable BunkerWeb staging and rollback. Fixed synthetic targets only.

Requires Docker on an ephemeral CI runner. Does not accept a WAF URL, credentials,
external configuration, or a production Docker context.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from har2bw import inventory, build  # noqa: E402

IMAGE = 'bunkerity/bunkerweb-all-in-one:1.6.18'
PYTHON = 'python:3.12-slim'
HOST = 'flow.example.test'
OWNER = '01234567-89ab-4cde-8123-0123456789ab'
OTHER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
PREFIX = 'har2bw-staging'
EVIDENCE = Path('staging-results')


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=360)


def docker(*args, check=True):
    return run('docker', *args, check=check)


def request(path, method='GET', headers=None, trusted=False, attack=False):
    code = '''import http.client,json,sys
p=json.loads(sys.argv[1]); c=http.client.HTTPConnection("172.29.83.10",8080,timeout=5)
c.request(p["method"],p["path"],headers={"Host":"flow.example.test","User-Agent":"Mozilla/5.0 HAR2BW-staging",**p["headers"]})
r=c.getresponse(); print(json.dumps({"status":r.status,"body":r.read().decode(errors="replace")})); c.close()
'''
    peer = PREFIX+('-trusted' if trusted else '-attack' if attack else '-client')
    result = docker('exec', peer, 'python', '-c', code,
                    json.dumps({'path': path, 'method': method, 'headers': headers or {}}))
    return json.loads(result.stdout)


def audit():
    code = 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/__audit", timeout=5).read().decode())'
    return json.loads(docker('exec', PREFIX+'-backend', 'python', '-c', code).stdout)


def check(label, path, expected, records, **kwargs):
    before = audit()
    result = request(path, **kwargs)
    if result['status'] != expected:
        raise AssertionError(f'{label}: expected {expected}, got {result}')
    # BunkerWeb intercepts error bodies; independently prove backend auth ran.
    after = audit()
    if label in ('unauthenticated', 'cross-object', 'authorized'):
        if len(after) != len(before)+1 or after[-1] != {'path':path, 'method':'GET', 'status':expected}:
            raise AssertionError(f'{label}: backend authorization not exercised')
    if label == 'waf-sqli' and after != before:
        raise AssertionError('Attack reached the backend instead of being blocked by the WAF')
    records.append({'check': label, 'status': expected})


def policy(include_new):
    paths = ['/public', '/q?cache=synthetic', '/api/object/'+OWNER]
    if include_new:
        paths.append('/new')
    data = {'log': {'entries': [{'request': {'method': 'GET', 'url': 'https://'+HOST+p},
                                'response': {'status': 200}} for p in paths]}}
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)/'synthetic.har'
        source.write_text(json.dumps(data))
        report = inventory([source], HOST)
    return build(report, [r['id'] for r in report['candidates']],
                 networks=['10.77.0.0/24'], trusted_real_ip=True,
                 sensitive=True, dynamic=True, unrestricted_query=True)


def start(conf, guard, phase):
    print(f'{phase}: applying saved control-plane configuration', flush=True)
    # Preserve WAF bans; use a distinct synthetic client for each independent phase.
    phase_index = {'baseline':0, 'candidate':1, 'rollback':2}[phase]
    for suffix, base_ip in (('client',40), ('attack',50)):
        docker('rm', '-f', PREFIX+'-'+suffix, check=False)
        docker('run', '-d', '--name', PREFIX+'-'+suffix, '--network', PREFIX,
               '--ip', f'172.29.83.{base_ip+phase_index}', PYTHON, 'sleep', '1800')
    docker('rm', '-f', PREFIX+'-waf', check=False)
    env = {'SERVER_NAME': HOST, 'MULTISITE': 'yes', 'SERVICE_UI': 'no',
           'SERVICE_API': 'no', 'SERVICE_SCHEDULER': 'yes',
           'USE_REVERSE_PROXY': 'yes', 'REVERSE_PROXY_HOST': 'http://172.29.83.20:8000',
           'USE_MODSECURITY': 'yes', 'USE_MODSECURITY_CRS': 'yes', 'SECURITY_MODE': 'block',
           'USE_REAL_IP': 'yes', 'REAL_IP_FROM': '172.29.83.30/32',
           'REAL_IP_HEADER': 'X-Forwarded-For', 'REAL_IP_RECURSIVE': 'yes',
           'CUSTOM_CONF_HTTP_har2bw': conf,
           HOST+'_CUSTOM_CONF_SERVER_HTTP_har2bw': guard}
    args = ['run', '-d', '--name', PREFIX+'-waf', '--network', PREFIX,
            '--ip', '172.29.83.10', '-v', PREFIX+'-data:/data']
    for key, value in env.items():
        args += ['-e', key+'='+value]
    docker(*args, IMAGE)
    deadline = time.monotonic()+240
    while time.monotonic() < deadline:
        try:
            if (request('/public')['status'] == 200
                    and request('/new')['status'] == (200 if phase == 'candidate' else 403)):
                break
        except (subprocess.SubprocessError, ValueError):
            pass
        time.sleep(3)
    else:
        raise AssertionError('BunkerWeb did not serve approved public path within 240 seconds')
    syntax = docker('exec', PREFIX+'-waf', 'nginx', '-t')
    (EVIDENCE/(phase+'-syntax.txt')).write_text(syntax.stdout+syntax.stderr)
    effective = docker('exec', PREFIX+'-waf', 'nginx', '-T')
    # Preserve only synthetic configuration in the CI artifact.
    (EVIDENCE/(phase+'-nginx.txt')).write_text(effective.stdout+effective.stderr)
    if 'modsecurity on;' not in effective.stdout or 'h2bw_' not in effective.stdout:
        raise AssertionError('WAF or generated guards are missing from effective NGINX configuration')
    docker('exec', PREFIX+'-waf', 'cat', '/usr/share/bunkerweb/VERSION')


def exercise(phase, new_status):
    results = []
    check('public', '/public', 200, results)
    check('candidate-transition', '/new', new_status, results)
    check('default-deny', '/internal', 403, results)
    check('wrong-method', '/public', 403, results, method='POST')
    check('query-default-deny', '/public?x=1', 403, results)
    check('reviewed-query', '/q?x=1', 200, results)
    check('encoded-path', '/%70ublic', 403, results)
    check('dot-path', '/x/../public', 403, results)
    check('double-slash', '//public', 403, results)
    check('unauthenticated', '/api/object/'+OWNER, 401, results)
    check('authorized', '/api/object/'+OWNER, 200, results,
          headers={'Authorization': 'Bearer synthetic-user-a'})
    check('cross-object', '/api/object/'+OTHER, 403, results,
          headers={'Authorization': 'Bearer synthetic-user-a'})
    check('untrusted-forwarded-ip', '/internal', 403, results,
          headers={'X-Forwarded-For': '10.77.0.5'})
    check('trusted-external-client', '/internal', 403, results, trusted=True,
          headers={'X-Forwarded-For': '198.51.100.44'})
    check('trusted-internal-client', '/internal', 200, results, trusted=True,
          headers={'X-Forwarded-For': '10.77.0.5'})
    # ModSecurity must block an attack on an otherwise explicitly allowed query endpoint.
    check('waf-sqli', '/q?id=1%27%20OR%201%3D1--', 403, results, attack=True)
    (EVIDENCE/(phase+'-checks.json')).write_text(json.dumps(results, indent=2))
    logs = docker('logs', PREFIX+'-waf')
    (EVIDENCE/(phase+'-logs.txt')).write_text(logs.stdout+logs.stderr)
    print(f'{phase}: {len(results)} checks passed', flush=True)
    return results


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('This staging harness only runs on a disposable GitHub-hosted runner')
    if docker('context', 'show').stdout.strip() != 'default' or os.environ.get('DOCKER_HOST'):
        raise SystemExit('Refusing a non-local Docker context')
    EVIDENCE.mkdir(exist_ok=True)
    docker('pull', IMAGE)
    docker('pull', PYTHON)
    docker('network', 'create', '--subnet', '172.29.83.0/24', PREFIX)
    docker('volume', 'create', PREFIX+'-data')
    try:
        backend = str(Path('staging/backend.py').resolve())
        docker('run', '-d', '--name', PREFIX+'-backend', '--network', PREFIX,
               '--ip', '172.29.83.20', '-v', backend+':/app/backend.py:ro',
               PYTHON, 'python', '/app/backend.py')
        for suffix, ip in (('trusted', '30'),):
            docker('run', '-d', '--name', PREFIX+'-'+suffix, '--network', PREFIX,
                   '--ip', '172.29.83.'+ip, PYTHON, 'sleep', '1800')
        baseline = policy(False)
        digest = hashlib.sha256(''.join(baseline).encode()).hexdigest()
        # Snapshot the exact original control-plane input before applying the candidate.
        (EVIDENCE/'baseline-http.conf').write_text(baseline[0])
        (EVIDENCE/'baseline-server.conf').write_text(baseline[1])
        phases = {}
        start(*baseline, 'baseline')
        phases['baseline'] = exercise('baseline', 403)
        candidate = policy(True)
        start(*candidate, 'candidate')
        phases['candidate'] = exercise('candidate', 200)
        restored = ((EVIDENCE/'baseline-http.conf').read_text(),
                    (EVIDENCE/'baseline-server.conf').read_text())
        if hashlib.sha256(''.join(restored).encode()).hexdigest() != digest:
            raise AssertionError('Rollback snapshot checksum mismatch')
        start(*restored, 'rollback')
        phases['rollback'] = exercise('rollback', 403)
        image = json.loads(docker('image', 'inspect', IMAGE).stdout)[0]
        (EVIDENCE/'result.json').write_text(json.dumps({
            'image': IMAGE, 'image_digests': image['RepoDigests'],
            'baseline_sha256': digest, 'rollback_sha256': digest,
            'phases': phases, 'scope': 'synthetic isolated CI only; no customer environment accessed',
            'result': 'passed'}, indent=2))
    finally:
        logs = docker('logs', PREFIX+'-waf', check=False)
        (EVIDENCE/'final-logs.txt').write_text(logs.stdout+logs.stderr)
        for suffix in ('waf', 'backend', 'trusted', 'client', 'attack'):
            docker('rm', '-f', PREFIX+'-'+suffix, check=False)
        docker('volume', 'rm', PREFIX+'-data', check=False)
        docker('network', 'rm', PREFIX, check=False)


if __name__ == '__main__':
    main()
