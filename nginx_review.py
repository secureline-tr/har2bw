"""Compare observed HAR candidates with recognizable NGINX map entries.

This is a textual inventory, not an NGINX interpreter or authorization test.
Unknown directives and regexes are never executed.
"""
import argparse
import json
import re
from pathlib import Path

from har2bw import INT_RX, UUID_RX, inventory, load_risk_terms

ENTRY = re.compile(r'^\s*(?:"(~\*?\^0:[^"]+)"|(~\*?\^0:\S+))\s+(0|\$[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$')
METHOD_MAP = re.compile(r'^\s*map\s+\$request_method\s+(\$[A-Za-z_][A-Za-z0-9_]*)\s*\{\s*$')
METHOD = re.compile(r'^\s*(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+0;\s*$')
PATH_MAP = re.compile(r'^\s*map\s+"(\$[A-Za-z_][A-Za-z0-9_]*:)(\$request_method:)?\$uri"\s+\$[A-Za-z_][A-Za-z0-9_]*\s*\{\s*$')
SAFE_PATH = re.compile(r'/[A-Za-z0-9_./~<>\-]*\Z')
SENTINEL_UUID = '00000000-0000-0000-0000-000000000000'

def parse(config):
    """Recognize only line-oriented method maps and external path map entries."""
    if not isinstance(config, str) or len(config.encode()) > 2*1024*1024:
        raise ValueError('Configuration exceeds 2 MiB or is not text')
    methods, rules, unknown = {}, [], []
    mode, current, body, start = None, None, [], 0
    for lineno, raw in enumerate(config.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if mode == 'method':
            if line == '}':
                allowed = [METHOD.fullmatch(x) for x in body if x != 'default 1;']
                if body.count('default 1;') == 1 and allowed and all(allowed):
                    methods[current] = sorted({x.group(1) for x in allowed})
                else:
                    unknown.append(start)
                mode = None
            else:
                body.append(line)
            continue
        if mode == 'path':
            if line == '}':
                mode = None
                continue
            if line in ('default 1;', '~^1: 0;'):
                continue
            match = ENTRY.fullmatch(line)
            if not match:
                unknown.append(lineno)
                continue
            pattern = match.group(1) or match.group(2)
            target = match.group(3)
            casefold = pattern.startswith('~*')
            pattern = pattern.split(':', 1)[1]
            if not pattern.endswith('$'):
                unknown.append(lineno)
                continue
            pattern = pattern[:-1]
            explicit = None
            if current:
                explicit, sep, pattern = pattern.partition(':')
                if not sep or not METHOD.fullmatch(explicit+' 0;'):
                    unknown.append(lineno)
                    continue
            path = pattern.replace(UUID_RX, '<uuid>').replace(INT_RX, '<int>').replace('[.]', '.')
            # Bare dots are regex wildcards, not literal paths.
            canonical = path.replace('.', '[.]').replace('<uuid>', UUID_RX).replace('<int>', INT_RX)
            if canonical != pattern or not SAFE_PATH.fullmatch(path) or any(x in path.replace('<uuid>', '').replace('<int>', '') for x in '<>'):
                unknown.append(lineno)
                continue
            rules.append({'line':lineno,'path':path,'casefold':casefold,'explicit':explicit,'target':target})
            continue
        if mode == 'skip':
            if line == '}':
                mode = None
            continue
        m = METHOD_MAP.fullmatch(line)
        p = PATH_MAP.fullmatch(line)
        if m:
            mode, current, body, start = 'method', m.group(1), [], lineno
        elif p:
            mode, current = 'path', bool(p.group(2))
        elif line.startswith('geo ') and line.endswith('{'):
            mode = 'skip'
            unknown.append(lineno)
        else:
            unknown.append(lineno)
    if mode:
        unknown.append(len(config.splitlines()))
    for rule in rules:
        allowed = None if rule['target'] == '0' else methods.get(rule['target'], [])
        if rule['explicit']:
            allowed = [rule['explicit']] if allowed is None or rule['explicit'] in allowed else []
        rule['methods'] = allowed
        if allowed == []:
            unknown.append(rule['line'])
    return rules, sorted(set(unknown))

def _covers(broad, narrow):
    """True if the placeholder-bearing rule path `broad` textually matches `narrow`."""
    if broad['path'] == narrow['path'] or '<' not in broad['path']:
        return False
    regex = ''.join(
        UUID_RX if tok == '<uuid>' else INT_RX if tok == '<int>' else re.escape(tok)
        for tok in re.split(r'(<uuid>|<int>)', broad['path']))
    sample = narrow['path'].replace('<uuid>', SENTINEL_UUID).replace('<int>', '0')
    flags = re.IGNORECASE if broad['casefold'] else 0
    return re.fullmatch(regex, sample, flags) is not None


def _methods_overlap(a, b):
    return a is None or b is None or bool(set(a) & set(b))


def overlaps(rules):
    """Placeholder rules that textually also match other listed rules (review hints only)."""
    found = []
    for broad in rules:
        covered = [r['line'] for r in rules
                   if r is not broad and _methods_overlap(broad['methods'], r['methods']) and _covers(broad, r)]
        if covered:
            found.append({'broad_line': broad['line'], 'covered_lines': covered})
    return found


def compare(report, config):
    rules, unknown = parse(config)
    matched = set()
    observations = []
    for row in report['candidates']:
        hits = []
        for rule in rules:
            same = row['path'].lower() == rule['path'].lower() if rule['casefold'] else row['path'] == rule['path']
            if same and (rule['methods'] is None or row['method'] in rule['methods']):
                hits.append(rule['line'])
                matched.add(rule['line'])
        observations.append({'id':row['id'],'method':row['method'],'path':row['path'],
                             'status':'textual_match' if hits else 'review_missing_or_unsupported',
                             'lines':hits})
    duplicates = {}
    for rule in rules:
        key = (rule['path'], rule['casefold'], tuple(rule['methods']) if rule['methods'] is not None else None)
        duplicates.setdefault(key, []).append(rule['line'])
    return {'duplicate_rule_groups':[lines for lines in duplicates.values() if len(lines)>1], 'observations':observations,'possible_overlaps':overlaps(rules),'unobserved_rule_lines':[r['line'] for r in rules if r['line'] not in matched],
            'unknown_lines':unknown,'warning':'Textual matches do not prove effective access. Unobserved rules are not necessarily redundant. Overlaps are textual hints only. Never auto-remove.'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',required=True)
    p.add_argument('--numeric-ids',action='store_true',help='Use the same value as the scan that produced the approval')
    p.add_argument('--risk-terms',type=Path,help='Use the same file as the scan')
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('har',nargs='+')
    a=p.parse_args()
    try:
        if a.config.stat().st_size > 2*1024*1024:
            raise ValueError('Configuration exceeds 2 MiB')
        print(json.dumps(compare(inventory(a.har,a.host.lower(),a.numeric_ids,load_risk_terms(a.risk_terms) if a.risk_terms else ()),a.config.read_text()),indent=2))
    except (ValueError,OSError) as e:
        p.exit(2,f'Error: {e}\n')

if __name__=='__main__':
    main()
