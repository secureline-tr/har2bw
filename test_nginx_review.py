import unittest
from nginx_review import compare, parse
from har2bw import UUID_RX

class ReviewTests(unittest.TestCase):
    def test_method_scoped(self):
        config = """map "$internal:$request_method:$uri" $block {
    default 1;
    ~^1: 0;
    "~^0:GET:/a[.]js$" 0;
}
"""
        report = {"candidates":[{"id":"a","method":"GET","path":"/a.js"},{"id":"b","method":"POST","path":"/a.js"}]}
        result = compare(report,config)
        self.assertEqual(result["observations"][0]["status"],"textual_match")
        self.assertEqual(result["observations"][1]["status"],"review_missing_or_unsupported")
    def test_legacy_method_map(self):
        config = """map $request_method $get_block {
    default 1;
    GET 0;
}
map "$internal:$uri" $block {
    default 1;
    ~*^0:/A[.]js$ $get_block;
}
"""
        result = compare({"candidates":[{"id":"a","method":"GET","path":"/a.js"}]},config)
        self.assertEqual(result["observations"][0]["status"],"textual_match")
    def test_unknown_regex(self):
        rules, unknown = parse('map "$internal:$uri" $block {\n    ~^0:/.*$ 0;\n}\n')
        self.assertFalse(rules)
        self.assertEqual(unknown,[2])
    def test_unknown_variable(self):
        rules, unknown = parse('map "$internal:$uri" $block {\n    ~^0:/a$ $unknown;\n}\n')
        self.assertEqual(rules[0]["methods"],[])
        self.assertEqual(unknown,[2])
    def test_uuid(self):
        config = 'map "$internal:$uri" $block {\n    "~^0:/form/'+UUID_RX+'/17$" 0;\n}\n'
        rules, unknown = parse(config)
        self.assertEqual(rules[0]["path"],"/form/<uuid>/17")
        self.assertFalse(unknown)
    def test_unobserved(self):
        result = compare({"candidates":[]},'map "$internal:$uri" $block {\n    ~^0:/a$ 0;\n}\n')
        self.assertEqual(result["unobserved_rule_lines"],[2])
