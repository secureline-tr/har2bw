"""Optional integration test against installed nginx, on loopback only."""
import json
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from har2bw import inventory, build

def status(url, method='GET'):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code

def main():
    with tempfile.TemporaryDirectory(prefix='har2bw-test-') as d:
        p=Path(d)
        uuid='01234567-89ab-4cde-8123-0123456789ab'
        rows=[('GET','/a.js'),('GET','/api/form/'+uuid+'/17'),('POST','/api/approve')]
        har={'log':{'entries':[{'request':{'method':m,'url':'https://flow.example.test'+u},'response':{'status':200}} for m,u in rows]}}
        (p/'sample.har').write_text(json.dumps(har))
        r=inventory([p/'sample.har'],'flow.example.test')
        conf,guard=build(r,[x['id'] for x in r['candidates']],dynamic=True,sensitive=True)
        (p/'map.conf').write_text(conf); (p/'guard.conf').write_text(guard)
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
        (p/'nginx.conf').write_text(f'''pid {p}/nginx.pid;
error_log {p}/error.log;
events {{ worker_connections 32; }}
http {{
    access_log off;
    client_body_temp_path {p}/body;
    proxy_temp_path {p}/proxy;
    fastcgi_temp_path {p}/fastcgi;
    uwsgi_temp_path {p}/uwsgi;
    scgi_temp_path {p}/scgi;
    include {p}/map.conf;
    server {{
        listen 127.0.0.1:{port};
        include {p}/guard.conf;
        location / {{ return 200 "OK"; }}
    }}
}}''')
        cmd=['nginx','-p',d,'-c',str(p/'nginx.conf')]
        subprocess.run(cmd+['-t'],check=True)
        proc=subprocess.Popen(cmd+['-g','daemon off;'])
        try:
            base=f'http://127.0.0.1:{port}'
            for _ in range(40):
                try:
                    status(base+'/a.js');break
                except OSError: time.sleep(.05)
            cases=[('GET','/a.js',200),('POST','/a.js',403),('GET','/A.js',403),('GET','/admin',403),('GET','/api/form/'+uuid+'/17',200),('GET','/api/form/'+uuid+'/18',403),('GET','/api/form/invalid/17',403),('POST','/api/approve',200),('GET','/api/approve',403)]
            for method,path,expected in cases:
                got=status(base+path,method)
                assert got==expected,(method,path,got,expected)
            print(f'NGINX integration: {len(cases)}/{len(cases)} cases passed')
        finally:
            proc.terminate();proc.wait(timeout=5)

if __name__=='__main__': main()
