"""CSV and dependency-free PDF reports for a scan and optional comparison. Local files only."""
import argparse
import csv
import io
import unicodedata
from pathlib import Path

from har2bw import inventory, load_risk_terms
from i18n import t
from review_bundle import write_private

COLUMNS = ['id', 'method', 'path', 'kind', 'category', 'review', 'eligible', 'count', 'statuses', 'query', 'warnings']


def _cell(value):
    """Neutralize spreadsheet formula injection from untrusted HAR-derived text."""
    text = str(value)
    return "'"+text if text[:1] in ('=', '+', '-', '@', '\t', '\r') else text


def report_csv(report):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator='\n')
    writer.writerow(COLUMNS)
    for row in report['candidates']:
        writer.writerow([_cell(x) for x in (
            row['id'], row['method'], row['path'], row['kind'], row['category'], row['review'],
            row['eligible'], row['count'], ' '.join(f'{k}:{v}' for k, v in row['statuses'].items()),
            row['query'], ' | '.join(row['warnings']))])
    return out.getvalue()


def comparison_csv(comparison):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator='\n')
    writer.writerow(['section', 'detail'])
    for key in ('duplicate_rule_groups', 'possible_overlaps', 'unobserved_rule_lines', 'unknown_lines'):
        for item in comparison.get(key, []):
            writer.writerow([key, _cell(item)])
    for obs in comparison.get('observations', []):
        writer.writerow(['observation', _cell(f'{obs["status"]} {obs["method"]} {obs["path"]}')])
    writer.writerow(['warning', _cell(comparison.get('warning', ''))])
    return out.getvalue()


def _ascii(text):
    """Built-in PDF fonts cannot show every Turkish letter; fold to ASCII."""
    folded = text.replace('ı', 'i').replace('İ', 'I')
    return unicodedata.normalize('NFKD', folded).encode('ascii', 'ignore').decode()


def _escape(text):
    return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def make_pdf(title, lines, per_page=52):
    """Minimal text-only PDF (Helvetica). No external library, no scripts or links."""
    pages = [lines[i:i+per_page] for i in range(0, len(lines), per_page)] or [[]]
    objects = []

    def add(body):
        objects.append(body)
        return len(objects)
    add('<< /Type /Catalog /Pages 2 0 R >>')
    add(None)  # pages, filled below
    font = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
    page_ids = []
    for number, chunk in enumerate(pages, 1):
        text = ['BT /F1 9 Tf 40 800 Td 11 TL']
        if number == 1:
            text.append(f'({_escape(_ascii(title))}) Tj T*')
        text.extend(f'({_escape(_ascii(line)[:110])}) Tj T*' for line in chunk)
        text.append('ET')
        stream = '\n'.join(text)
        content = add(f'<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream')
        page_ids.append(add(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
                            f'/Resources << /Font << /F1 {font} 0 R >> >> /Contents {content} 0 R >>'))
    objects[1] = '<< /Type /Pages /Kids [' + ' '.join(f'{i} 0 R' for i in page_ids) + f'] /Count {len(page_ids)} >>'
    out = bytearray(b'%PDF-1.4\n')
    offsets = []
    for index, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f'{index} 0 obj\n{body}\nendobj\n'.encode()
    xref = len(out)
    out += f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode()
    out += ''.join(f'{o:010d} 00000 n \n' for o in offsets).encode()
    out += f'trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return bytes(out)


def report_pdf(report, lang='en'):
    lines = [f'Host: {report["host"]}   Requests: {report["entries"]}   Candidates: {len(report["candidates"])}',
             t('report_sensitive', lang), '']
    for row in report['candidates']:
        lines.append(f'{row["method"]} {row["path"]} [{row["review"]}, {"eligible" if row["eligible"] else "not eligible"}]')
        lines.extend('   ! '+w for w in row['warnings'])
    return make_pdf(t('report_title', lang), lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--format', choices=['csv', 'pdf'], required=True)
    p.add_argument('--lang', choices=['en', 'tr'], default='en')
    p.add_argument('--numeric-ids', action='store_true')
    p.add_argument('--risk-terms', type=Path)
    p.add_argument('--out', type=Path, required=True, help='New owner-only directory')
    p.add_argument('har', nargs='+')
    a = p.parse_args()
    try:
        report = inventory(a.har, a.host.lower(), a.numeric_ids, load_risk_terms(a.risk_terms) if a.risk_terms else ())
        if a.format == 'csv':
            write_private(a.out, {'report.csv': report_csv(report)})
        else:
            a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
            import os
            fd = os.open(a.out/'report.pdf', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as target:
                target.write(report_pdf(report, a.lang))
        print(f'Report written to {a.out}')
    except (ValueError, OSError) as exc:
        p.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
