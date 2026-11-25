"""Security regressions and end-to-end release contracts, synthetic data only."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch
from har2bw import inventory, build, shape
from review_bundle import approval_document, validate_approval, artifacts, archive, write_private
from bunkerweb_api import Client, NoRedirect, MAX_RESPONSE
from nginx_review import compare


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.har = self.root/'input.har'
        self.data = {'log': {'entries': [{'request': {'url': 'https://flow.example.test/a.js',
                         'method': 'GET'}, 'response': {'status': 200}}]}}
        self.har.write_text(json.dumps(self.data))
        self.report = inventory([self.har], 'flow.example.test')
        self.ids = [r['id'] for r in self.report['candidates']]

    def test_approval_binding(self):
        approval = approval_document(self.report, self.ids)
        self.assertEqual(validate_approval(self.report, approval), self.ids)
        self.data['log']['entries'][0]['request']['url'] += '?secret=hidden'
        self.har.write_text(json.dumps(self.data))
        changed = inventory([self.har], 'flow.example.test')
        with self.assertRaisesRegex(ValueError, 'Review changed'):
            validate_approval(changed, approval)
        for value in (self.ids, {}, None):
            with self.assertRaises(ValueError):
                validate_approval(self.report, value)

    def test_query_is_opt_in_for_assets(self):
        self.data['log']['entries'][0]['request']['url'] += '?secret=hidden'
        self.har.write_text(json.dumps(self.data))
        report = inventory([self.har], 'flow.example.test')
        with self.assertRaisesRegex(ValueError, 'query'):
            build(report, self.ids)
        conf, guard = build(report, self.ids, unrestricted_query=True)
        self.assertNotIn('hidden', conf)
        self.assertIn('_query_block', guard)
        self.assertIn('GET:/a[.]js:', conf)

    def test_short_numbers_are_not_exported(self):
        for path in ('/users/17', '/orders/1', '/account/12345'):
            redacted, kind = shape(path)
            self.assertEqual(kind, 'unsupported')
            self.assertIn('<opaque>', redacted)

    def test_malformed_urls_not_normalized_into_allow_rules(self):
        for url in ('https://flow.example.test/a\n.js', ' https://flow.example.test/a.js',
                    'https://flow.example.test/a\\b'):
            self.data['log']['entries'][0]['request']['url'] = url
            self.har.write_text(json.dumps(self.data))
            self.assertEqual(inventory([self.har], 'flow.example.test')['candidates'], [])

    def test_invalid_hosts(self):
        for host in ('foo.-bar', 'foo-.bar', 'a'*64+'.test', 'foo..bar'):
            with self.assertRaises(ValueError):
                inventory([self.har], host)

    def test_bundle_integrity_and_permissions(self):
        conf, guard = build(self.report, self.ids)
        files = artifacts(self.report, self.ids, conf, guard, {})
        manifest = json.loads(files['manifest.json'])
        for name, digest in manifest['sha256'].items():
            self.assertEqual(hashlib.sha256(files[name].encode()).hexdigest(), digest)
        self.assertTrue(archive(files).startswith(b'PK'))
        out = self.root/'output'
        write_private(out, files)
        if os.name == 'posix':
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            self.assertEqual((out/'approve.json').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            write_private(out, files)

    def test_cli_scan_generate_and_stale(self):
        scan, output = self.root/'scan', self.root/'draft'
        base = [sys.executable, 'har2bw.py']
        args = ['--host', 'flow.example.test', str(self.har)]
        subprocess.run(base+['scan']+args+['--out', str(scan)], check=True, capture_output=True)
        approval = json.loads((scan/'approve.json').read_text())
        approval['approved_ids'] = self.ids
        (scan/'approve.json').write_text(json.dumps(approval))
        cmd = base+['generate']+args+['--approve', str(scan/'approve.json'), '--out', str(output)]
        subprocess.run(cmd, check=True, capture_output=True)
        self.assertTrue((output/'manifest.json').is_file())
        self.data['log']['entries'][0]['response']['status'] = 403
        self.har.write_text(json.dumps(self.data))
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Review changed', result.stderr)

    def test_duplicate_candidates_and_unknown_config(self):
        text = 'map "$internal:$uri" $block {\n~^0:/a[.]js$ 0;\n~^0:/a[.]js$ 0;\ninclude /secret;\n}\n'
        result = compare(self.report, text)
        self.assertEqual(result['duplicate_rule_groups'], [[2, 3]])
        self.assertEqual(result['unknown_lines'], [4])
        self.assertNotIn('/secret', json.dumps(result))


class ApiTests(unittest.TestCase):
    def client(self):
        return Client('https://api.example.test/root', 'SYNTHETIC_TOKEN')

    def response(self, payload):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(payload).encode()
        return response

    def test_read_only_contract_and_encoding(self):
        c = self.client()
        c._opener = Mock()
        schema = {'paths': {'/configs/{service}/{type}/{name}': {'get': {}}}, 'info': {'version': 'test'}}
        c._opener.open.side_effect = [self.response(schema), self.response({'status': 'success', 'data': {}})]
        result = c.snapshot('flow.example.test', 'server_http', 'allowlist')
        self.assertEqual(result['api_version'], 'test')
        requests = [call.args[0] for call in c._opener.open.call_args_list]
        self.assertTrue(all(r.get_method() == 'GET' for r in requests))
        self.assertEqual(requests[1].full_url, 'https://api.example.test/root/configs/flow.example.test/server_http/allowlist?with_data=true')
        self.assertNotIn('SYNTHETIC_TOKEN', json.dumps(result))

    def test_invalid_connection_and_path(self):
        for url in ('http://localhost', 'https://u:p@api.test', 'https://api.test/?x=1',
                    'https://api.test/../foo', 'https://api.test/#x'):
            with self.assertRaises(ValueError):
                Client(url, 'token')
        with self.assertRaises(ValueError):
            Client('https://api.test', 'token\nheader')
        c = self.client()
        with self.assertRaises(ValueError):
            c.snapshot('../secret', 'http', 'name')
        with self.assertRaises(ValueError):
            c.snapshot('global', 'modsec', 'name')

    def test_redirect_refused(self):
        with self.assertRaisesRegex(ValueError, 'redirects'):
            NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.test')

    def test_response_limits_and_no_secret_errors(self):
        c = self.client()
        c._opener = Mock()
        c._opener.open.return_value = self.response({})
        c._opener.open.return_value.read.return_value = b'x'*(MAX_RESPONSE+1)
        with self.assertRaisesRegex(ValueError, '2 MiB'):
            c._get('/openapi.json')
        c._opener.open.side_effect = urllib.error.HTTPError('https://secret', 403, 'SECRET', {}, io.BytesIO(b'SECRET'))
        with self.assertRaises(ValueError) as exc:
            c._get('/openapi.json')
        self.assertNotIn('SECRET', str(exc.exception))

    def test_contract_missing(self):
        c = self.client()
        with patch.object(c, '_get', return_value={'paths': {}}) as get:
            with self.assertRaisesRegex(ValueError, 'contract'):
                c.snapshot('global', 'http', 'name')
            self.assertEqual(get.call_count, 1)


if __name__ == '__main__':
    unittest.main()
