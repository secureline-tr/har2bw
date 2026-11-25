"""Versioned approvals and local review artifacts. Never deploys configuration."""
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

VERSION = '1.0.0'


def fingerprint(report):
    return hashlib.sha256(json.dumps(report, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def approval_document(report, ids):
    if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
        raise ValueError('Approvals must be a list of candidate IDs')
    if set(ids) - {r['id'] for r in report['candidates']}:
        raise ValueError('Unknown candidate IDs')
    return {'schema_version': 1, 'report_sha256': fingerprint(report),
            'host': report['host'], 'approved_ids': sorted(set(ids))}


def validate_approval(report, approval):
    if not isinstance(approval, dict) or approval.get('schema_version') != 1:
        raise ValueError('Use a versioned approval document from the current scan')
    if approval.get('host') != report['host'] or approval.get('report_sha256') != fingerprint(report):
        raise ValueError('Review changed: analyze and approve again')
    return approval_document(report, approval.get('approved_ids'))['approved_ids']


def artifacts(report, ids, conf, guard, options):
    files = {'har2bw-http.conf': conf, 'har2bw-server-http.conf': guard,
             'approve.json': json.dumps(approval_document(report, ids), indent=2)+'\n'}
    manifest = {'version': VERSION, 'host': report['host'], 'report_sha256': fingerprint(report),
                'review_options': options, 'deployment': 'manual-only',
                'sha256': {k: hashlib.sha256(v.encode()).hexdigest() for k, v in files.items()}}
    files['manifest.json'] = json.dumps(manifest, indent=2)+'\n'
    return files


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name, content in sorted(files.items()):
            bundle.writestr(name, content)
    return output.getvalue()


def write_private(directory, files):
    """Create a fresh owner-only directory; never overwrite an existing export."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, content in files.items():
        if Path(name).name != name:
            raise ValueError('Invalid artifact filename')
        fd = os.open(directory/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as target:
            target.write(content)
