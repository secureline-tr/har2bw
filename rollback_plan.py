"""Generate a manual rollback plan. Reads local files only; never contacts or changes a WAF."""
import argparse
import difflib
import json
from pathlib import Path

import history

NOTE = ('This is a plan for a human operator. HAR2BW does not apply, reload or roll back anything. '
        'A single config snippet is not a complete backup.')


def extract_config(snapshot):
    """Return the config text from a bunkerweb_api snapshot, or None if the shape is unknown."""
    payload = snapshot.get('payload') if isinstance(snapshot, dict) else None
    if not isinstance(payload, dict):
        return None
    config = payload.get('config', payload)
    data = config.get('data') if isinstance(config, dict) else None
    return data if isinstance(data, str) else None


def plan(known_good_text, snapshot, target):
    """Compare the saved known-good draft with the current snapshot; return a plan dict."""
    current = extract_config(snapshot)
    if current is None:
        status, lines = 'unknown', []
    elif current == known_good_text:
        status, lines = 'identical', []
    else:
        status = 'different'
        lines = list(difflib.unified_diff(known_good_text.splitlines(), current.splitlines(),
                                          'known-good', 'current', lineterm='', n=2))[:400]
    steps = [
        'Export the CURRENT configuration and settings to a protected location (full backup, not only this snippet).',
        f'In an isolated staging service first, restore the known-good text for {target} through the same control plane.',
        'Run nginx -t and confirm the scheduler reload succeeded.',
        'Repeat functional tests: approved methods/paths allowed; denied methods, query strings, encoded paths, '
        'dot segments and cross-object requests denied.',
        'Only after human review consider production. Record who applied it and when.',
    ]
    return {'status': status, 'target': target, 'diff': lines, 'steps': steps, 'note': NOTE,
            'unknown_shape': status == 'unknown'}


def render(result):
    out = ['# Manual rollback plan', '', f'Target: {result["target"]}', f'Comparison: {result["status"]}', '', result['note'], '']
    if result['unknown_shape']:
        out += ['The snapshot has an unrecognized shape; compare it manually.', '']
    out += [f'{i}. {s}' for i, s in enumerate(result['steps'], 1)]
    if result['diff']:
        out += ['', '## Difference (known-good vs current)', '```diff', *result['diff'], '```']
    return '\n'.join(out)+'\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace', type=Path, required=True)
    p.add_argument('--project', required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--file', default='har2bw-server-http.conf', choices=['har2bw-http.conf', 'har2bw-server-http.conf'])
    p.add_argument('--snapshot', type=Path, required=True)
    a = p.parse_args()
    try:
        root = history.project_root(a.workspace, a.project)
        problems = history.verify(root, a.version)
        if problems:
            raise ValueError('History verification failed: '+'; '.join(problems))
        _, files = history._load(root, a.version)
        snapshot = json.loads(a.snapshot.read_text(encoding='utf-8'))
        print(render(plan(files[a.file], snapshot, snapshot.get('name', a.file))), end='')
    except (ValueError, OSError, KeyError) as exc:
        p.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
