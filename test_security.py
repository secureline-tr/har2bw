"""Repository hygiene: no secrets, customer artifacts or non-synthetic fixtures are tracked."""
import json
import re
import subprocess
import unittest
from pathlib import Path
from urllib.parse import urlsplit

PATTERNS = {
    'private key': re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----'),
    'AWS access key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    'GitHub token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    'Slack token': re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}\b'),
    'Anthropic/OpenAI key': re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b'),
    'JWT': re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
}
FORBIDDEN_SUFFIXES = ('.zip', '.pem', '.key', '.p12', '.pfx', '.log')
FORBIDDEN_NAMES = {'report.json', 'approve.json', 'manifest.json', 'snapshot.json', 'comparison.json',
                   'har2bw-http.conf', 'har2bw-server-http.conf', '.env'}


def tracked():
    out = subprocess.run(['git', 'ls-files'], capture_output=True, text=True, check=False)  # nosec B603 B607
    return [Path(p) for p in out.stdout.splitlines() if Path(p).is_file()]


class HygieneTests(unittest.TestCase):
    def test_no_secret_patterns(self):
        for path in tracked():
            if path.name == 'test_security.py':
                continue
            text = path.read_text(encoding='utf-8', errors='ignore')
            for name, rx in PATTERNS.items():
                self.assertIsNone(rx.search(text), f'{name} pattern in {path}')

    def test_no_customer_artifacts_tracked(self):
        for path in tracked():
            self.assertNotIn(path.name, FORBIDDEN_NAMES, path)
            self.assertFalse(path.name.endswith(FORBIDDEN_SUFFIXES), path)
            if path.suffix == '.har':
                self.assertEqual(path.name, 'sample.har', 'only the synthetic sample HAR may be tracked')

    def test_sample_har_is_synthetic(self):
        data = json.loads(Path('sample.har').read_text(encoding='utf-8'))
        hosts = {urlsplit(e['request']['url']).hostname for e in data['log']['entries']}
        self.assertTrue(hosts and all(h.endswith('.example.test') for h in hosts), hosts)
        text = Path('sample.har').read_text(encoding='utf-8').lower()
        for header in ('"cookie"', '"set-cookie"', '"authorization"'):
            self.assertNotIn(header, text)

    def test_gitignore_blocks_runtime_data(self):
        ignore = Path('.gitignore').read_text()
        for entry in ('*.har', 'workspace/', '*.zip', '.env'):
            self.assertIn(entry, ignore)


if __name__ == '__main__':
    unittest.main()
