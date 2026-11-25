"""v1.1 regressions: numeric gate, risk terms, overlap hints, API error paths."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bunkerweb_api import Client
from har2bw import INT_RX, UUID_RX, build, inventory, load_risk_terms, shape
from nginx_review import compare, parse
from policy_diff import compare as diff_compare
from review_bundle import approval_document, validate_approval

HOST = 'flow.example.test'


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def report(self, rows, **kw):
        har = self.root/'a.har'
        har.write_text(json.dumps({'log': {'entries': [
            {'request': {'url': u, 'method': m}, 'response': {'status': s}} for m, u, s in rows]}}))
        return inventory([har], HOST, **kw)


class NumericTests(Base):
    def test_default_still_redacts_numbers(self):
        self.assertEqual(shape('/items/42')[1], 'unsupported')
        self.assertEqual(shape('/items/42', True), ('/items/<int>', 'dynamic'))

    def test_long_numbers_stay_opaque(self):
        self.assertEqual(shape('/items/1234567890', True)[1], 'unsupported')

    def test_numeric_requires_gate_and_binds_report(self):
        r = self.report([('GET', f'https://{HOST}/items/42', 200)], numeric_ids=True)
        ids = [r['candidates'][0]['id']]
        self.assertIn('Numeric pattern', ' '.join(r['candidates'][0]['warnings']))
        with self.assertRaisesRegex(ValueError, 'allow-numeric'):
            build(r, ids, sensitive=True)
        conf, _ = build(r, ids, sensitive=True, numeric=True)
        self.assertIn('/items/'+INT_RX+'$', conf)
        plain = self.report([('GET', f'https://{HOST}/items/42', 200)])
        with self.assertRaisesRegex(ValueError, 'Review changed'):
            validate_approval(plain, approval_document(r, ids))

    def test_numeric_roundtrip_in_review_parser(self):
        r = self.report([('GET', f'https://{HOST}/items/42', 200)], numeric_ids=True)
        conf, _ = build(r, [r['candidates'][0]['id']], sensitive=True, numeric=True)
        rules, unknown = parse(conf)
        self.assertEqual(rules[0]['path'], '/items/<int>')
        self.assertNotIn(rules[0]['line'], unknown)  # guard maps are reported as unknown, not rules
        self.assertEqual(compare(r, conf)['observations'][0]['status'], 'textual_match')


class RiskTermTests(Base):
    def test_extra_terms_add_warnings_only(self):
        base = self.report([('GET', f'https://{HOST}/special/page', 200)])
        extra = self.report([('GET', f'https://{HOST}/special/page', 200)], risk_terms=('/Special',))
        self.assertNotIn('High-risk', ' '.join(base['candidates'][0]['warnings']))
        self.assertIn('High-risk', ' '.join(extra['candidates'][0]['warnings']))
        self.assertEqual(base['candidates'][0]['id'], extra['candidates'][0]['id'])

    def test_generic_terms_warn_by_default(self):
        r = self.report([('POST', f'https://{HOST}/files/upload', 200)])
        self.assertIn('High-risk', ' '.join(r['candidates'][0]['warnings']))

    def test_risk_term_file_validation(self):
        good = self.root/'t.json'
        good.write_text('["/x"]')
        self.assertEqual(load_risk_terms(good), ('/x',))
        for bad in ('{}', '[1]', '[""]', 'nope'):
            good.write_text(bad)
            with self.assertRaises(ValueError):
                load_risk_terms(good)
        with self.assertRaises(ValueError):
            load_risk_terms(self.root/'missing.json')


class OverlapTests(unittest.TestCase):
    def cfg(self, *entries):
        return 'map "$internal:$request_method:$uri" $b {\n    default 1;\n' + ''.join(
            f'    "~^0:{e}$" 0;\n' for e in entries) + '}\n'

    def test_placeholder_rule_covers_literal_rule(self):
        u = '00000000-0000-0000-0000-000000000001'
        cfg = self.cfg(f'GET:/f/{UUID_RX}/x', f'GET:/f/{u}/x', f'POST:/f/{u}/x', 'GET:/f/[0-9]{1,9}', 'GET:/f/5')
        result = compare({'candidates': []}, cfg)
        pairs = {(o['broad_line'], tuple(o['covered_lines'])) for o in result['possible_overlaps']}
        self.assertEqual(pairs, {(3, (4,)), (6, (7,))})  # POST rule is a different method
        self.assertIn('hints', result['warning'])

    def test_unknown_syntax_is_not_overlap(self):
        result = compare({'candidates': []}, self.cfg('GET:/f/.*', 'GET:/f/a'))
        self.assertEqual(result['possible_overlaps'], [])
        self.assertTrue(result['unknown_lines'])

    def test_crlf_and_blank_lines(self):
        cfg = self.cfg('GET:/a').replace('\n', '\r\n\r\n')
        rules, unknown = parse(cfg)
        self.assertEqual(len(rules), 1)
        self.assertFalse(unknown)

    def test_nested_unknown_block_reported(self):
        rules, unknown = parse('geo $g {\n  default 0;\n}\nmap "$internal:$uri" $b {\n    ~^0:/a$ 0;\n}\n')
        self.assertEqual(len(rules), 1)
        self.assertIn(1, unknown)


class DiffTests(unittest.TestCase):
    def test_non_string_ids_rejected(self):
        with self.assertRaises(ValueError):
            diff_compare({'candidates': []}, [1], [])
        with self.assertRaises(ValueError):
            diff_compare({'candidates': []}, [], [None])

    def test_no_change(self):
        r = diff_compare({'candidates': [{'id': 'a'}]}, ['a'], ['a'])
        self.assertEqual([x['id'] for x in r['unchanged']], ['a'])
        self.assertFalse(r['added'] or r['removed'])


class ApiErrorTests(unittest.TestCase):
    def client(self):
        return Client('https://waf.example.test', 'tok')

    def test_constructor_rejections(self):
        for url in ('http://x.test', 'https://u:p@x.test', 'https://x.test?a=1', 'https://x.test/a b'):
            with self.assertRaises(ValueError):
                Client(url, 'tok')
        for token in ('', 'a b', 'tök'):
            with self.assertRaises(ValueError):
                Client('https://x.test', token)

    def test_snapshot_input_validation(self):
        c = self.client()
        for args in (('..', 'http', 'n'), ('s', 'http', 'a/b'), ('s', 'stream', 'n')):
            with self.assertRaises(ValueError):
                c.snapshot(*args)

    def test_missing_contract_and_error_status(self):
        c = self.client()
        with patch.object(c, '_get', return_value={'paths': {}}), self.assertRaisesRegex(ValueError, 'contract'):
            c.snapshot('s', 'http', 'n')
        with patch.object(c, '_get', return_value={'paths': 'x'}), self.assertRaisesRegex(ValueError, 'OpenAPI'):
            c.snapshot('s', 'http', 'n')
        schema = {'paths': {'/configs/{service}/{type}/{name}': {'get': {}}}}
        with patch.object(c, '_get', side_effect=[schema, {'status': 'error', 'msg': 'secret'}]), \
                self.assertRaises(ValueError) as ctx:
            c.snapshot('s', 'http', 'n')
        self.assertNotIn('secret', str(ctx.exception))

    def test_only_get_is_used(self):
        c = self.client()
        calls = []

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b'{}'

        def opener(req, timeout):
            calls.append(req.get_method())
            return Resp()
        c._opener = type('O', (), {'open': staticmethod(opener)})()
        c._get('/openapi.json')
        self.assertEqual(calls, ['GET'])

    def test_non_object_json_rejected(self):
        c = self.client()

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b'[1]'
        c._opener = type('O', (), {'open': staticmethod(lambda req, timeout: Resp())})()
        with self.assertRaises(ValueError):
            c._get('/x')


if __name__ == '__main__':
    unittest.main()
