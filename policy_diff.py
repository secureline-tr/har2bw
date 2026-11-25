"""Compare HAR2BW approval sets without parsing/executing arbitrary nginx code."""
import argparse
import json
from pathlib import Path

from har2bw import inventory, load_risk_terms
from review_bundle import validate_approval


def compare(report, previous, proposed):
    known = {r["id"]: r for r in report["candidates"]}
    for value in (previous, proposed):
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError("Approval sets must be JSON arrays of IDs")
    old, new = set(previous), set(proposed)
    if new - known.keys():
        raise ValueError("Unknown proposed candidate IDs")
    def describe(ids):
        return [{"id": i, "candidate": known.get(i)} for i in sorted(ids)]
    return {"added": describe(new-old), "removed": describe(old-new),
            "unchanged": describe(old&new), "unapproved_observed": describe(known.keys()-new),
            "previous_not_observed": describe(old-known.keys())}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--numeric-ids",action="store_true",help="Use the same value as the scan that produced the approval")
    p.add_argument("--risk-terms",type=Path,help="Use the same file as the scan")
    p.add_argument("--previous", type=Path, required=True)
    p.add_argument("--proposed", type=Path, required=True)
    p.add_argument("har", nargs="+")
    a=p.parse_args()
    try:
        report=inventory(a.har,a.host.lower(),a.numeric_ids,load_risk_terms(a.risk_terms) if a.risk_terms else ())
        previous=json.loads(a.previous.read_text())
        proposed=json.loads(a.proposed.read_text())
        if isinstance(previous,dict):
            if previous.get('host') != report['host']:
                raise ValueError('Previous approval belongs to another host')
            previous=previous.get('approved_ids')
        if isinstance(proposed,dict):
            proposed=validate_approval(report,proposed)
        result=compare(report,previous,proposed)
        print(json.dumps(result,indent=2))
    except (ValueError,OSError) as e:
        p.exit(2,f"Error: {e}\n")

if __name__=="__main__":
    main()
