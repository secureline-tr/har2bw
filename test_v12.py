"""History, rollback plan, reports, i18n, auth and UI integration tests (synthetic data only)."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import auth
import history
import rollback_plan
from har2bw import build, inventory
from i18n import MESSAGES, t
from reporting import _cell, comparison_csv, make_pdf, report_csv, report_pdf
from review_bundle import artifacts


def bundle(text='x'):
    report = {'host': 'flow.example.test', 'candidates': [{'id': 'a'}], 'entries': 1}
    files = artifacts({**report, 'candidates': [{'id': 'a'}, {'id': 'b'}]}, ['a'], text, 'guard', {})
    return files


class HistoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ws = Path(tmp.name)/'ws'
        self.root = history.project_root(self.ws, 'proj-a')

    def test_project_names(self):
        for bad in ('', '../x', 'A', 'a b', '-a', 'a'*41, None):
            with self.assertRaises(ValueError):
                history.project_root(self.ws, bad)
        self.assertEqual(history.list_projects(self.ws), [])

    def test_versions_chain_and_permissions(self):
        v1 = history.save(self.root, bundle('one'), 'first')
        v2 = history.save(self.root, bundle('two'))
        self.assertTrue(v1.startswith('v0001-') and v2.startswith('v0002-'))
        self.assertEqual([v['version'] for v in history.list_versions(self.root)], [v1, v2])
        self.assertEqual(history.verify(self.root, v2), [])
        mode = stat.S_IMODE((self.root/v1/'har2bw-http.conf').stat().st_mode)
        self.assertEqual(mode, 0o400)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)

    def test_tamper_and_missing_parent_detected(self):
        v1 = history.save(self.root, bundle('one'))
        v2 = history.save(self.root, bundle('two'))
        target = self.root/v1/'har2bw-http.conf'
        target.chmod(0o600)
        target.write_text('evil')
        self.assertTrue(any('changed' in p for p in history.verify(self.root, v1)))
        import shutil
        shutil.rmtree(self.root/v1)
        self.assertIn('Parent version is missing', history.verify(self.root, v2))
        self.assertTrue(history.verify(self.root, 'v9999-000000000000'))
        with self.assertRaises(ValueError):
            history.diff(self.root, '../x', v2)

    def test_diff_and_validation(self):
        v1 = history.save(self.root, bundle('one'))
        v2 = history.save(self.root, bundle('two'))
        d = history.diff(self.root, v1, v2)
        self.assertIn('har2bw-http.conf', d['changed_files'])
        self.assertEqual(d['added_ids'], [])
        with self.assertRaises(ValueError):
            history.save(self.root, {})
        with self.assertRaises(ValueError):
            history.save(self.root, {'a.txt': 'x'})


class RollbackTests(unittest.TestCase):
    snap = {'name': 'allow', 'payload': {'config': {'data': 'current\n'}}}

    def test_statuses(self):
        self.assertEqual(rollback_plan.plan('current\n', self.snap, 'allow')['status'], 'identical')
        different = rollback_plan.plan('known\n', self.snap, 'allow')
        self.assertEqual(different['status'], 'different')
        self.assertTrue(any(line.startswith('-known') for line in different['diff']))
        unknown = rollback_plan.plan('x', {'payload': {'config': {}}}, 'allow')
        self.assertTrue(unknown['unknown_shape'])
        self.assertIsNone(rollback_plan.extract_config([]))

    def test_plan_is_manual_only(self):
        text = rollback_plan.render(rollback_plan.plan('known\n', self.snap, 'allow'))
        self.assertIn('does not apply, reload or roll back', text)
        self.assertIn('staging', text)
        import ast
        tree = ast.parse(Path(rollback_plan.__file__).read_text())
        imported = {n.names[0].name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
        imported |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertFalse(imported & {'urllib', 'requests', 'subprocess', 'socket', 'http', 'ssl', 'bunkerweb_api'})


class ReportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.report = inventory(['sample.har'], 'flow.example.test')

    def test_csv_neutralizes_formulas(self):
        for value in ('=1+1', '+x', '-x', '@x', '\tx'):
            self.assertTrue(_cell(value).startswith("'"))
        self.assertEqual(_cell('/a'), '/a')
        rows = report_csv(self.report).splitlines()
        self.assertEqual(len(rows), len(self.report['candidates'])+1)
        self.assertIn("'=cmd", comparison_csv({'unknown_lines': ['=cmd']}))

    def test_pdf_structure_and_turkish_folding(self):
        pdf = report_pdf(self.report, 'tr')
        self.assertTrue(pdf.startswith(b'%PDF-1.4') and pdf.rstrip().endswith(b'%%EOF'))
        self.assertNotIn(b'/JS', pdf)
        many = make_pdf('başlık (x)', ['satır ğüşiöç'] * 130)
        self.assertEqual(many.count(b'/Type /Page '), 3)
        self.assertIn(b'baslik', many)


class I18nAuthTests(unittest.TestCase):
    def test_keys_match_and_fallback(self):
        self.assertEqual(set(MESSAGES['en']), set(MESSAGES['tr']))
        self.assertEqual(t('nope', 'tr'), 'nope')
        self.assertEqual(t('title', 'xx'), MESSAGES['en']['title'])
        self.assertIn('v1', t('saved_history', 'tr', version='v1'))

    def test_password_rules(self):
        self.assertIsNone(auth.configured_password({}))
        with self.assertRaises(ValueError):
            auth.configured_password({'HAR2BW_UI_PASSWORD': 'short'})
        self.assertEqual(auth.configured_password({'HAR2BW_UI_PASSWORD': 'x'*12}), 'x'*12)
        self.assertTrue(auth.check('abc', 'abc'))
        self.assertFalse(auth.check('abc', 'abd'))
        self.assertFalse(auth.check('abc', 'äbc'))


@unittest.skipUnless(importlib.util.find_spec('streamlit'), 'UI dependencies not installed')
class UiTests(unittest.TestCase):
    def app(self):
        from streamlit.testing.v1 import AppTest
        return AppTest.from_file('web.py', default_timeout=30).run()

    def test_turkish_title(self):
        app = self.app()
        app.sidebar.selectbox[0].set_value('tr').run()
        self.assertFalse(app.exception)
        self.assertIn('Politika', app.title[0].value)

    def test_password_gate(self):
        with patch.dict(os.environ, {'HAR2BW_UI_PASSWORD': 'correct-horse-battery'}):
            app = self.app()
            self.assertFalse(app.exception)
            self.assertFalse([b for b in app.button if b.label == 'Analyze'])
            app.text_input[0].set_value('wrong-password-xx')
            app.button[0].click().run()
            self.assertTrue(app.error)
            self.assertNotIn('authenticated', app.session_state)
            app.text_input[0].set_value('correct-horse-battery')
            app.button[0].click().run()
            self.assertTrue(app.session_state['authenticated'])

    def test_short_password_blocks_ui(self):
        with patch.dict(os.environ, {'HAR2BW_UI_PASSWORD': 'short'}):
            app = self.app()
            self.assertTrue(app.error)
            self.assertFalse([b for b in app.button if b.label == 'Analyze'])

    def test_save_to_project_history(self):
        with tempfile.TemporaryDirectory() as ws, patch.dict(os.environ, {'HAR2BW_WORKSPACE': ws}):
            Path(ws, 'demo', 'history').mkdir(parents=True)
            report = inventory(['sample.har'], 'flow.example.test')
            row = next(r for r in report['candidates'] if r['eligible'] and r['review'] == 'asset')
            app = self.app()
            next(s for s in app.selectbox if s.label == 'Project').set_value('demo')
            app.session_state['report'] = report
            app.session_state['review_id'] = 'rid'
            app.run()
            app.checkbox(key='rid'+row['id']).check()
            for box in app.checkbox:
                if box.label.startswith('I accept unrestricted'):
                    box.check()
            next(b for b in app.button if b.label == 'Generate draft').click().run()
            self.assertFalse(app.exception)
            next(b for b in app.button if b.label.startswith('Save reviewed bundle')).click().run()
            self.assertFalse(app.exception)
            versions = history.list_versions(history.project_root(ws, 'demo'))
            self.assertEqual(len(versions), 1)
            self.assertEqual(history.verify(history.project_root(ws, 'demo'), versions[0]['version']), [])
            self.assertTrue(build(report, [row['id']], unrestricted_query=True))


if __name__ == '__main__':
    unittest.main()
