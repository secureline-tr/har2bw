"""Explicit read-only BunkerWeb config snapshot over verified HTTPS."""
import argparse
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from review_bundle import write_private

MAX_RESPONSE = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('API redirects are forbidden')


class Client:
    def __init__(self, base_url, token, ca_file=None):
        u = urlsplit(base_url)
        if (u.scheme != 'https' or not u.hostname or u.username is not None
                or u.password is not None or u.query or u.fragment
                or not re.fullmatch(r'https://[A-Za-z0-9.:-]+(?:/[A-Za-z0-9_-]+)*/?', base_url)):
            raise ValueError('Use an HTTPS API origin with an optional safe root path')
        if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError('A valid read-only API bearer token is required')
        self.base = base_url.rstrip('/')
        self._token = token
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def _get(self, path):
        req = urllib.request.Request(self.base+path, method='GET', headers={
            'Authorization': 'Bearer '+self._token, 'Accept': 'application/json'})
        try:
            with self._opener.open(req, timeout=15) as response:
                data = response.read(MAX_RESPONSE+1)
                if len(data) > MAX_RESPONSE:
                    raise ValueError('API response exceeds 2 MiB')
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise ValueError('Unexpected API response structure')
                return result
        except urllib.error.HTTPError as exc:
            exc.close()
            raise ValueError(f'API returned HTTP {exc.code}; response body withheld') from None
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise ValueError('API transport or JSON response failed; details withheld') from None

    def snapshot(self, service, config_type, name):
        if any(not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*', x)
               or x in ('.', '..') for x in (service, name)):
            raise ValueError('Invalid service or configuration name')
        if config_type not in ('http', 'server_http'):
            raise ValueError('Only HTTP review configurations are supported')
        schema = self._get('/openapi.json')
        paths = schema.get('paths')
        if not isinstance(paths, dict):
            raise ValueError('Invalid OpenAPI paths')
        endpoint = paths.get('/configs/{service}/{type}/{name}')
        operation = endpoint.get('get') if isinstance(endpoint, dict) else None
        if not isinstance(operation, dict):
            raise ValueError('Target OpenAPI does not advertise the supported config read contract')
        payload = self._get(f'/configs/{service}/{config_type}/{name}?with_data=true')
        if payload.get('status') == 'error':
            raise ValueError('API reported a configuration read error; details withheld')
        return {'schema_version': 1, 'service': service, 'type': config_type,
                'name': name, 'api_version': schema.get('info', {}).get('version') if isinstance(schema.get('info'), dict) else None,
                'payload': payload, 'warning': 'Sensitive local snapshot; not a complete backup or proof of enforcement'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', required=True)
    p.add_argument('--service', required=True)
    p.add_argument('--type', choices=['http', 'server_http'], required=True)
    p.add_argument('--name', required=True)
    p.add_argument('--ca-file')
    p.add_argument('--out', required=True)
    a = p.parse_args()
    try:
        client = Client(a.url, os.environ.get('HAR2BW_API_TOKEN', ''), a.ca_file)
        snapshot = client.snapshot(a.service, a.type, a.name)
        write_private(a.out, {'snapshot.json': json.dumps(snapshot, indent=2)+'\n'})
        print('Read-only snapshot saved; no WAF changes made')
    except (ValueError, OSError) as exc:
        p.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
