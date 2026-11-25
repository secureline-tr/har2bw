"""Local, append-only review history. Never deploys, reloads or edits a live WAF."""
import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from review_bundle import write_private

VERSION_RX = re.compile(r'v[0-9]{4}-[0-9a-f]{12}\Z')
PROJECT_RX = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?\Z')
MAX_FILE = 8 * 1024 * 1024


def project_root(workspace, name):
    """Return <workspace>/<name>/history for a validated project name."""
    if not isinstance(name, str) or not PROJECT_RX.fullmatch(name):
        raise ValueError('Project names use lowercase letters, digits and hyphens (max 40)')
    return Path(workspace)/name/'history'


def list_projects(workspace):
    root = Path(workspace)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and PROJECT_RX.fullmatch(p.name))


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def save(root, files, note=''):
    """Store a review bundle (name -> text) as the next immutable version."""
    if not isinstance(files, dict) or not files or 'manifest.json' not in files:
        raise ValueError('A review bundle with manifest.json is required')
    if any(len(v.encode()) > MAX_FILE for v in files.values()):
        raise ValueError('Bundle file too large')
    root = Path(root)
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700, exist_ok=True)
    root.parent.chmod(0o700)
    root.chmod(0o700)
    existing = sorted(p.name for p in root.iterdir() if VERSION_RX.fullmatch(p.name))
    number = int(existing[-1][1:5]) + 1 if existing else 1
    if number > 9999:
        raise ValueError('History is full')
    parent = existing[-1] if existing else None
    body = {k: files[k] for k in sorted(files)}
    meta = {'schema_version': 1, 'number': number, 'parent': parent, 'note': str(note)[:200],
            'sha256': {k: _digest(v) for k, v in body.items()}}
    chain = _digest(json.dumps([parent, meta['sha256']], sort_keys=True))
    meta['chain_sha256'] = chain
    name = f'v{number:04d}-{chain[:12]}'
    write_private(root/name, {**body, 'history.json': json.dumps(meta, indent=2)+'\n'})
    for child in (root/name).iterdir():
        child.chmod(stat.S_IRUSR)
    return name


def list_versions(root):
    root = Path(root)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.iterdir()):
        if VERSION_RX.fullmatch(p.name) and (p/'history.json').is_file():
            meta = json.loads((p/'history.json').read_text(encoding='utf-8'))
            out.append({'version': p.name, 'note': meta.get('note', ''), 'parent': meta.get('parent')})
    return out


def _load(root, version):
    if not VERSION_RX.fullmatch(version):
        raise ValueError('Invalid version name')
    directory = Path(root)/version
    if not directory.is_dir():
        raise ValueError('Unknown version')
    meta = json.loads((directory/'history.json').read_text(encoding='utf-8'))
    files = {k: (directory/k).read_text(encoding='utf-8') for k in meta['sha256']
             if Path(k).name == k and (directory/k).is_file()}
    return meta, files


def verify(root, version):
    """Check stored files and the parent chain. Returns a list of problems."""
    try:
        meta, files = _load(root, version)
    except (OSError, ValueError, KeyError):
        return ['Version is missing or unreadable']
    problems = [f'Missing or changed: {k}' for k, h in meta['sha256'].items()
                if k not in files or _digest(files[k]) != h]
    expected = _digest(json.dumps([meta.get('parent'), meta['sha256']], sort_keys=True))
    if meta.get('chain_sha256') != expected or not version.endswith(expected[:12]):
        problems.append('Chain digest mismatch')
    parent = meta.get('parent')
    if parent and not (Path(root)/parent).is_dir():
        problems.append('Parent version is missing')
    return problems


def diff(root, old, new):
    """Compare approved candidate IDs and generated drafts of two versions."""
    (_, a), (_, b) = _load(root, old), _load(root, new)
    ids = [set(json.loads(f['approve.json'])['approved_ids']) if 'approve.json' in f else set() for f in (a, b)]
    return {'added_ids': sorted(ids[1]-ids[0]), 'removed_ids': sorted(ids[0]-ids[1]),
            'changed_files': sorted(k for k in set(a)|set(b) if a.get(k) != b.get(k) and k != 'manifest.json'),
            'warning': 'Textual comparison of reviewed drafts; not proof of effective access.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace', type=Path, default=Path(os.environ.get('HAR2BW_WORKSPACE', 'workspace')))
    p.add_argument('--project', required=True)
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('save')
    s.add_argument('bundle', type=Path, help='Directory produced by `har2bw generate`')
    s.add_argument('--note', default='')
    sub.add_parser('list')
    sub.add_parser('verify').add_argument('version')
    d = sub.add_parser('diff')
    d.add_argument('old')
    d.add_argument('new')
    a = p.parse_args()
    try:
        root = project_root(a.workspace, a.project)
        if a.cmd == 'save':
            files = {f.name: f.read_text(encoding='utf-8') for f in sorted(a.bundle.iterdir()) if f.is_file()}
            print(save(root, files, a.note))
        elif a.cmd == 'list':
            print(json.dumps(list_versions(root), indent=2))
        elif a.cmd == 'verify':
            problems = verify(root, a.version)
            print(json.dumps({'version': a.version, 'ok': not problems, 'problems': problems}, indent=2))
            if problems:
                raise SystemExit(1)
        else:
            print(json.dumps(diff(root, a.old, a.new), indent=2))
    except (ValueError, OSError, KeyError) as exc:
        p.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
