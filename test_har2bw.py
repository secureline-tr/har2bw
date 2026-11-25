import json
import tempfile
import unittest
from pathlib import Path

from har2bw import build, inventory, shape


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.p=Path(self.tmp.name)/'sample.har'
        self.host='flow.example.test'
    def tearDown(self): self.tmp.cleanup()
    def report(self, rows):
        self.p.write_text(json.dumps({'log':{'entries':[{'request':{'url':url,'method':m,'headers':[{'name':'Authorization','value':'SECRET'}],'postData':{'text':'SECRET'}},'response':{'status':s}} for m,url,s in rows]}}))
        return inventory([self.p],self.host)
    def test_filter_redaction_and_dedup(self):
        r=self.report([('GET','https://flow.example.test/a.js?v=SECRET',200),('GET','https://flow.example.test/a.js?v=OTHER',200),('GET','https://else.test/a.js',200)])
        self.assertEqual(r['entries'],2)
        self.assertEqual(len(r['candidates']),1)
        self.assertNotIn('SECRET',json.dumps(r))
        self.assertEqual(r['skipped']['other_origin'],1)
    def test_default_deny_method_scope(self):
        r=self.report([('GET','https://flow.example.test/a.js',200),('POST','https://flow.example.test/api/do',403)])
        a=next(x for x in r['candidates'] if x['method']=='GET')
        c,g=build(r,[a['id']])
        self.assertIn('default 1;',c)
        self.assertIn('~^0:GET:/a[.]js$',c)
        self.assertNotIn('/api/do',c)
        self.assertIn('return 403;',g)
    def test_failed_only_refused(self):
        r=self.report([('POST','https://flow.example.test/api/do',403)])
        with self.assertRaises(ValueError): build(r,[r['candidates'][0]['id']],sensitive=True)
    def test_redirect_only_refused(self):
        r=self.report([('GET','https://flow.example.test/login',302)])
        with self.assertRaises(ValueError): build(r,[r['candidates'][0]['id']],sensitive=True)
        self.assertIn('GET:/login',build(r,[r['candidates'][0]['id']],sensitive=True,redirect_only=True)[0])
    def test_sensitive_explicit(self):
        r=self.report([('POST','https://flow.example.test/api/do',200)])
        ids=[r['candidates'][0]['id']]
        with self.assertRaises(ValueError): build(r,ids)
        self.assertIn('POST:/api/do',build(r,ids,sensitive=True)[0])
    def test_uuid_and_query_gates(self):
        u='01234567-89ab-4cde-8123-0123456789ab'
        r=self.report([('GET',f'https://flow.example.test/api/form/{u}/details?token=SECRET',200)])
        ids=[r['candidates'][0]['id']]
        self.assertNotIn(u,json.dumps(r))
        with self.assertRaises(ValueError): build(r,ids,sensitive=True,dynamic=True)
        with self.assertRaises(ValueError): build(r,ids,sensitive=True,unrestricted_query=True)
        c,_=build(r,ids,sensitive=True,dynamic=True,unrestricted_query=True)
        self.assertIn('{12}/details$',c)
    def test_injection_and_opaque(self):
        for path in ['/foo%2fbar','/a/../b','/a//b','/a;return','/a"','/a/123456789']:
            self.assertEqual(shape(path)[1],'unsupported')
    def test_empty_and_unknown_approval(self):
        r=self.report([('GET','https://flow.example.test/a.js',200)])
        for a in ([],['not-an-id']):
            with self.assertRaises(ValueError): build(r,a)
    def test_internal_validation(self):
        r=self.report([('GET','https://flow.example.test/a.js',200)])
        ids=[r['candidates'][0]['id']]
        with self.assertRaises(ValueError): build(r,ids,['0.0.0.0/0'],trusted_real_ip=True)
        with self.assertRaises(ValueError): build(r,ids,['10.1.0.0/24'])
        self.assertIn('10.1.0.0/24 1;',build(r,ids,['10.1.0.0/24'],trusted_real_ip=True)[0])

if __name__=='__main__': unittest.main()
