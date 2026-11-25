#!/usr/bin/env python3
"""Offline HAR inventory and explicitly approved BunkerWeb policy draft generator."""
import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from review_bundle import VERSION, approval_document, artifacts, validate_approval, write_private

UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
UUID_RX = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
INT_RX = '[0-9]{1,9}'
SAFE = re.compile(r'/[A-Za-z0-9_./~-]*\Z')
HOST = re.compile(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z')
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
STATIC = {'javascript', 'css', 'font', 'image'}
MAX_BYTES = 128 * 1024 * 1024
# Generic path fragments that always trigger a manual-review warning. Deployments
# can extend (never shrink) this list with --risk-terms FILE.
HIGH_RISK_TERMS = ('upload', 'download', 'export', 'token', 'password', '/admin', '/account/', '/oauth/')


def category(path):
    p = path.lower()
    if '/api/' in p or '/handler/' in p or p.endswith('.ashx'):
        return 'api'
    if any(x in p for x in ('/account/', '/oauth/', '/login', '/logout', '/sessioncheck', '/mailing.aspx')):
        return 'session'
    if '/bundles/' in p:
        return 'bundle'
    if p.endswith(('.js', '.mjs', '/signalr/hubs')):
        return 'javascript'
    if p.endswith('.css'):
        return 'css'
    if p.endswith(('.woff', '.woff2', '.ttf', '.otf', '.eot')):
        return 'font'
    if p.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.avif')):
        return 'image'
    if p.endswith('.html'):
        return 'html'
    return 'page'


def load_risk_terms(path):
    """Read extra lowercase warning fragments from a JSON array of strings."""
    try:
        terms = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError):
        raise ValueError('Invalid risk-terms file') from None
    if (not isinstance(terms, list) or len(terms) > 500
            or any(not isinstance(t, str) or not t or len(t) > 128 for t in terms)):
        raise ValueError('Risk terms must be a JSON array of up to 500 short strings')
    return tuple(terms)


def shape(path, numeric_ids=False):
    if not SAFE.fullmatch(path) or '//' in path or any(s in ('.', '..') for s in path.split('/')):
        return '<unreviewable-path>', 'unsupported'
    parts, kind = [], 'exact'
    for seg in path.split('/'):
        if UUID.fullmatch(seg):
            parts.append('<uuid>')
            if kind != 'unsupported':
                kind = 'dynamic'
        elif numeric_ids and re.fullmatch(r'[0-9]{1,9}', seg):
            parts.append('<int>')
            if kind != 'unsupported':
                kind = 'dynamic'
        elif (len(seg) > 64 or re.fullmatch(r'\d+', seg)
              or re.fullmatch(r'[A-Za-z0-9_-]{24,}', seg) and any(c.isdigit() for c in seg)
              or re.search(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', seg)):
            parts.append('<opaque>')
            kind = 'unsupported'
        else:
            parts.append(seg)
    return '/'.join(parts), kind


def inventory(files, host, numeric_ids=False, risk_terms=()):
    if not HOST.fullmatch(host) or '..' in host:
        raise ValueError('Invalid hostname (use lowercase DNS name, no scheme or port)')
    if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
        raise ValueError('Invalid DNS hostname')
    if not files:
        raise ValueError('At least one HAR is required')
    if sum(Path(f).stat().st_size for f in files) > MAX_BYTES:
        raise ValueError('Combined HAR input exceeds 128 MiB')
    groups, skipped = {}, Counter()
    for filename in files:
        if Path(filename).stat().st_size > MAX_BYTES:
            raise ValueError('HAR exceeds 128 MiB limit')
        try:
            with Path(filename).open('rb') as source:
                raw = source.read(MAX_BYTES+1)
            if len(raw) > MAX_BYTES:
                raise ValueError()
            data = json.loads(raw.decode('utf-8-sig'))
            entries = data['log']['entries']
            if not isinstance(entries, list):
                raise ValueError()
        except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
            raise ValueError('Invalid HAR structure') from None
        for entry in entries:
            try:
                req = entry['request']
                raw_url = req['url']
                if not isinstance(raw_url, str) or any(ord(c) < 33 or ord(c) == 127 for c in raw_url) or '\\' in raw_url:
                    raise ValueError()
                u = urlsplit(raw_url)
                if u.scheme not in ('http', 'https') or u.hostname != host or u.username is not None or u.password is not None or u.port not in (None, 443 if u.scheme == 'https' else 80):
                    skipped['other_origin'] += 1
                    continue
                method = req['method']
                status = entry['response']['status']
                if method not in METHODS or type(status) is not int or not 0 <= status <= 599:
                    raise ValueError()
                path = u.path or '/'
                pathshape, kind = shape(path, numeric_ids)
            except (KeyError, TypeError, ValueError, AttributeError):
                skipped['invalid_entry'] += 1
                continue
            cat = category(path) if kind != 'unsupported' else 'unknown'
            key = (method, pathshape, kind, cat)
            if key not in groups:
                groups[key] = {'id': hashlib.sha256(json.dumps([host, *key]).encode()).hexdigest()[:16], 'method': method, 'path': pathshape, 'kind': kind, 'category': cat, 'statuses': Counter(), 'query': False, 'count': 0}
            row = groups[key]
            row['count'] += 1
            row['query'] |= bool(u.query)
            row['statuses'][str(status)] += 1
    terms = tuple(dict.fromkeys((*HIGH_RISK_TERMS, *(t.lower() for t in risk_terms))))
    rows = sorted(groups.values(), key=lambda r: (r['category'], r['path'], r['method']))
    for r in rows:
        r['statuses'] = dict(sorted(r['statuses'].items()))
        r['observed_success'] = any(200 <= int(s) < 300 for s in r['statuses'])
        r['review'] = 'asset' if r['category'] in STATIC and r['method'] in ('GET','HEAD') and r['kind'] == 'exact' else 'sensitive'
        r['warnings'] = []
        if r['review'] == 'sensitive':
            r['warnings'].append('Verify backend authorization, session scope and response content')
        if r['method'] not in ('GET','HEAD'):
            r['warnings'].append('Potential state change; test using non-production records')
        if '<uuid>' in r['path']:
            r['warnings'].append('UUID pattern covers other IDs; verify object-level authorization')
        if '<int>' in r['path']:
            r['warnings'].append('Numeric pattern covers other IDs; verify object-level authorization')
        if r['query']:
            r['warnings'].append('Query values omitted; generated URI rule does not restrict query strings')
        if any(x in r['path'].lower() for x in terms):
            r['warnings'].append('High-risk application operation or sensitive data; manual review required')
        if r['kind'] == 'unsupported':
            r['warnings'].append('Unsafe or opaque path; no rule can be generated')
        r['observed_redirect'] = any(int(s) in (301,302,303,307,308) for s in r['statuses'])
        r['eligible'] = r['kind'] != 'unsupported' and (r['observed_success'] or r['observed_redirect'])
    return {'schema_version':1,'version':VERSION,'host':host,'entries':sum(r['count'] for r in rows),'skipped':dict(skipped),
            'options':{'numeric_ids':bool(numeric_ids),'risk_terms':list(terms)},'candidates':rows}


def build(report, approvals, networks=(), dynamic=False, unrestricted_query=False, sensitive=False, redirect_only=False, trusted_real_ip=False, numeric=False):
    if not isinstance(approvals, list) or any(not isinstance(x,str) for x in approvals):
        raise ValueError('Approval file must be a JSON array of candidate IDs')
    selected = set(approvals)
    rows = {r['id']:r for r in report['candidates']}
    if selected - rows.keys():
        raise ValueError('Unknown candidate ID: regenerate the review file')
    if not selected:
        raise ValueError('No approved candidates; no policy produced')
    prefix = 'h2bw_' + hashlib.sha256(report['host'].encode()).hexdigest()[:10]
    result = ['# HAR2BW DRAFT - review before deployment', '# Service: '+report['host'], '# Query strings and request bodies are NOT authorization checks.']
    if networks and not trusted_real_ip:
        raise ValueError('Internal bypass requires explicit confirmation of trusted real-IP configuration')
    nets = sorted({str(ipaddress.ip_network(n, strict=True)) for n in networks})
    if any(ipaddress.ip_network(n).prefixlen == 0 for n in nets):
        raise ValueError('Catch-all internal network is forbidden')
    result.extend(['',f'geo ${prefix}_internal {{','    default 0;'])
    result.extend('    '+n+' 1;' for n in nets)
    result.extend(['}', '', f'map "${prefix}_internal:$request_method:$uri" ${prefix}_block {{','    default 1;','    ~^1: 0;'])
    query_rules = []
    last = None
    for r in report['candidates']:
        if r['id'] not in selected:
            continue
        if not r['eligible']:
            raise ValueError('Candidate has no observed 2xx/redirect or unsupported path: '+r['id'])
        if not r['observed_success'] and not redirect_only:
            raise ValueError('Redirect-only candidate requires --allow-redirect-only: '+r['id'])
        if r['review'] == 'sensitive' and not sensitive:
            raise ValueError('Sensitive candidate requires --allow-sensitive: '+r['id'])
        if '<uuid>' in r['path'] and not dynamic:
            raise ValueError('Dynamic candidate requires --allow-dynamic: '+r['id'])
        if '<int>' in r['path'] and not numeric:
            raise ValueError('Numeric candidate requires --allow-numeric: '+r['id'])
        if r['query'] and not unrestricted_query:
            raise ValueError('Unrestricted query requires --allow-unrestricted-query: '+r['id'])
        if last != r['category']:
            result.append('    # '+r['category'])
            last = r['category']
        pattern = r['path'].replace('.', '[.]').replace('<uuid>', UUID_RX).replace('<int>', INT_RX)
        if r['query'] and unrestricted_query:
            query_rules.append(f'    "~^{r["method"]}:{pattern}:\\?$" 0;')
        result.append(f'    "~^0:{r["method"]}:{pattern}$" 0;')
    result.extend(['}', ''])
    result.extend([f'map "$request_method:$uri:$is_args" ${prefix}_query_block {{',
                   '    default 1;', '    ~:$ 0;', *query_rules, '}', '',
                   f'map $request_uri ${prefix}_unsafe_path {{', '    default 0;',
                   '    ~^[^?]*% 1;',
                   '"~^[^?]*(?://|/[.]{1,2}(?:/|[?]|$))" 1;', '}', ''])
    guard = f'# Service SERVER_HTTP custom config for {report["host"]}\nif (${prefix}_block) {{\n    return 403;\n}}\nif (${prefix}_unsafe_path) {{\n    return 403;\n}}\nif (${prefix}_query_block) {{\n    return 403;\n}}\n'
    return '\n'.join(result), guard


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', action='version', version=VERSION)
    sub = p.add_subparsers(dest='cmd',required=True)
    for name in ('scan','generate'):
        s=sub.add_parser(name)
        s.add_argument('--host',required=True)
        s.add_argument('--numeric-ids',action='store_true',help='Generalize 1-9 digit path segments to <int> (use the same flag for scan and generate)')
        s.add_argument('--risk-terms',type=Path,help='JSON array of extra path fragments that add a manual-review warning (same file for scan and generate)')
        s.add_argument('har',nargs='+')
        s.add_argument('--out',type=Path,required=True)
        if name=='generate':
            s.add_argument('--approve',type=Path,required=True)
            s.add_argument('--internal',action='append',default=[])
            s.add_argument('--confirm-trusted-real-ip',action='store_true',help='Confirm trusted proxies and spoofing tests before internal bypass')
            s.add_argument('--allow-sensitive',action='store_true')
            s.add_argument('--allow-redirect-only',action='store_true')
            s.add_argument('--allow-dynamic',action='store_true')
            s.add_argument('--allow-numeric',action='store_true')
            s.add_argument('--allow-unrestricted-query',action='store_true')
    a=p.parse_args()
    try:
        report=inventory(a.har,a.host.lower(),a.numeric_ids,load_risk_terms(a.risk_terms) if a.risk_terms else ())
        if a.cmd=='scan':
            output={'report.json':json.dumps(report,indent=2,ensure_ascii=False)+'\n','approve.json':json.dumps(approval_document(report, []),indent=2)+'\n'}
        else:
            try:
                approvals=json.loads(a.approve.read_text(encoding='utf-8'))
            except (ValueError,UnicodeError):
                raise ValueError('Invalid approval JSON') from None
            approvals=validate_approval(report,approvals)
            conf,guard=build(report,approvals,a.internal,a.allow_dynamic,a.allow_unrestricted_query,a.allow_sensitive,a.allow_redirect_only,a.confirm_trusted_real_ip,a.allow_numeric)
            output=artifacts(report,approvals,conf,guard,{'internal':a.internal,'trusted_real_ip':a.confirm_trusted_real_ip,'dynamic':a.allow_dynamic,'unrestricted_query':a.allow_unrestricted_query,'sensitive':a.allow_sensitive,'redirect_only':a.allow_redirect_only,'numeric':a.allow_numeric})
        write_private(a.out,output)
        print(f'{report["entries"]} target requests; {len(report["candidates"])} candidates. Output: {a.out}')
    except (ValueError,OSError) as e:
        p.exit(2,f'Error: {e}\n')

if __name__=='__main__':
    main()
