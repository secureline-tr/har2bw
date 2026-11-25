"""UI regression tests; skipped only in the standard-library CLI test job."""
import importlib.util
import unittest


@unittest.skipUnless(importlib.util.find_spec('streamlit'), 'UI dependencies not installed')
class WebTests(unittest.TestCase):
    def app(self):
        from streamlit.testing.v1 import AppTest
        return AppTest.from_file('web.py').run()

    def test_startup_and_analyze_disabled(self):
        app = self.app()
        self.assertFalse(app.exception)
        self.assertTrue(app.title[0].value.startswith('HAR2BW'))
        self.assertTrue(next(b for b in app.button if b.label == 'Analyze').disabled)

    def test_host_change_invalidates_review_and_export(self):
        app = self.app()
        app.session_state['report'] = {'host': 'flow.example.test', 'entries': 0, 'candidates': []}
        app.session_state['review_id'] = 'old-review'
        app.session_state['draft'] = ('old-review', 'old-conf', 'old-guard', b'old')
        app.text_input[0].set_value('other.example.test').run()
        self.assertFalse(app.exception)
        self.assertNotIn('report', app.session_state)
        self.assertNotIn('draft', app.session_state)

    def test_clear_review(self):
        app = self.app()
        app.session_state['report'] = {'host': 'flow.example.test', 'entries': 0, 'candidates': []}
        app.session_state['review_id'] = 'old'
        next(b for b in app.button if b.label == 'Clear review').click().run()
        self.assertFalse(app.exception)
        self.assertNotIn('report', app.session_state)

    def test_review_generate_bundle(self):
        from har2bw import inventory
        app = self.app()
        report = inventory(['sample.har'], 'flow.example.test')
        app.session_state['report'] = report
        app.session_state['review_id'] = 'synthetic-review'
        app.run()
        self.assertFalse(app.exception)
        row = next(r for r in report['candidates'] if r['eligible'] and r['review']=='asset')
        app.checkbox(key='synthetic-review'+row['id']).check()
        for box in app.checkbox:
            if box.label.startswith('I accept unrestricted'):
                box.check()
        next(b for b in app.button if b.label == 'Generate draft').click().run()
        self.assertFalse(app.exception)
        draft = app.session_state['draft']
        self.assertTrue(draft[3].startswith(b'PK'))
        self.assertIn('default 1;', draft[1])

    def test_empty_approval_has_no_export(self):
        from har2bw import inventory
        app = self.app()
        app.session_state['report'] = inventory(['sample.har'], 'flow.example.test')
        app.session_state['review_id'] = 'empty-review'
        app.run()
        next(b for b in app.button if b.label == 'Generate draft').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(app.error)
        self.assertNotIn('draft', app.session_state)
