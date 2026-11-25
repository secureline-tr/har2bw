"""Turkish UI completeness and state preservation (synthetic data only)."""
import ast
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from har2bw import inventory
from i18n import EXACT_TR, MESSAGES, tx

WIDGETS = {'checkbox', 'button', 'text_input', 'text_area', 'file_uploader', 'selectbox', 'download_button',
           'metric', 'subheader', 'caption', 'warning', 'title', 'form_submit_button', 'expander', 'header', 'info', 'success'}
ENGLISH_LABELS = ('Analyze', 'Clear review', 'Generate draft', 'Requests', 'Candidates', 'HAR files', 'Target hostname',
                  'Global HTTP draft', 'Download review bundle', 'Download comparison')


class StaticTests(unittest.TestCase):
    def test_no_hardcoded_widget_labels_in_web(self):
        tree = ast.parse(Path('web.py').read_text(encoding='utf-8'))
        bad = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in WIDGETS
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                bad.append((node.lineno, node.args[0].value))
        self.assertEqual([b for b in bad if b[1] != 'Language / Dil'], [], 'wrap labels in t()')

    def test_every_widget_has_a_key_when_label_is_translated(self):
        # Without a key a label change creates a new widget and drops uploads and checkbox state.
        tree = ast.parse(Path('web.py').read_text(encoding='utf-8'))
        keyed = {'checkbox', 'text_input', 'text_area', 'file_uploader'}
        missing = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in keyed
                    and not any(k.arg == 'key' for k in node.keywords)):
                missing.append(node.lineno)
        self.assertEqual(missing, [])

    def test_tr_has_no_english_labels_left(self):
        for key, text in MESSAGES['tr'].items():
            if key.startswith(('gate_', 'dl_')) or key in ('analyze', 'generate', 'clear', 'har_files', 'host'):
                self.assertNotIn(text, MESSAGES['en'].values(), key)
        for label in ENGLISH_LABELS:
            self.assertNotIn(label, MESSAGES['tr'].values())

    def test_known_warnings_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            har = Path(tmp)/'a.har'
            u = '01234567-89ab-4cde-8123-0123456789ab'
            rows = [('POST', f'/api/upload/{u}/9?x=1', 200), ('GET', '/a.js?v=1', 200), ('GET', '/n/123456789012', 200),
                    ('GET', '/items/42', 200), ('GET', '/x%2fy', 200)]
            har.write_text(json.dumps({'log': {'entries': [{'request': {'url': 'https://flow.example.test'+p, 'method': m},
                                                            'response': {'status': s}} for m, p, s in rows]}}))
            report = inventory([har], 'flow.example.test', numeric_ids=True)
        warnings = {w for r in report['candidates'] for w in r['warnings']}
        self.assertGreaterEqual(len(warnings), 6)
        for w in warnings:
            self.assertNotEqual(tx(w, 'tr'), w, w)
            self.assertEqual(tx(w, 'en'), w)
        self.assertEqual(tx('Some new unknown message', 'tr'), 'Some new unknown message')

    def test_comparison_warning_is_translated(self):
        from nginx_review import compare
        warning = compare({'candidates': []}, 'map "$internal:$uri" $b {\n}\n')['warning']
        self.assertIn(warning, EXACT_TR)


@unittest.skipUnless(importlib.util.find_spec('streamlit'), 'UI dependencies not installed')
class UiTests(unittest.TestCase):
    def app(self):
        from streamlit.testing.v1 import AppTest
        return AppTest.from_file('web.py', default_timeout=30).run()

    def test_turkish_labels(self):
        report = inventory(['sample.har'], 'flow.example.test')
        app = self.app()
        app.session_state['report'] = report
        app.session_state['review_id'] = 'rid'
        app.run()
        app.sidebar.selectbox[0].set_value('tr').run()
        self.assertFalse(app.exception)
        labels = [b.label for b in app.button] + [c.label for c in app.checkbox] + [m.label for m in app.metric]
        for english in ENGLISH_LABELS:
            self.assertFalse([x for x in labels if english in x], english)
        self.assertIn('Analiz et', [b.label for b in app.button])
        self.assertIn('varlık', ' '.join(c.label for c in app.checkbox))
        self.assertIn('hassas', ' '.join(c.label for c in app.checkbox))
        self.assertEqual(app.text_input(key='host').value, 'flow.example.test')

    def test_widget_state_survives_language_switch(self):
        app = self.app()
        app.checkbox(key='numeric_ids').check().run()
        app.sidebar.selectbox[0].set_value('tr').run()
        self.assertTrue(app.checkbox(key='numeric_ids').value, 'keyed widgets must keep state when the label changes')
        app.sidebar.selectbox[0].set_value('en').run()
        self.assertTrue(app.checkbox(key='numeric_ids').value)

    def test_turkish_error_message(self):
        report = inventory(['sample.har'], 'flow.example.test')
        app = self.app()
        app.sidebar.selectbox[0].set_value('tr').run()
        app.session_state['report'] = report
        app.session_state['review_id'] = 'rid'
        app.run()
        next(b for b in app.button if b.label == 'Taslak oluştur').click().run()
        self.assertTrue(app.error)
        self.assertIn('Onaylı aday yok', app.error[0].value)


if __name__ == '__main__':
    unittest.main()
