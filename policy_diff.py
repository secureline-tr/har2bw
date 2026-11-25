"""Compare HAR2BW approval sets without parsing/executing arbitrary nginx code."""
import argparse
import json
from pathlib import Path
from har2bw import inventory

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
    p.add_argument("--previous", type=Path, required=True)
    p.add_argument("--proposed", type=Path, required=True)
    p.add_argument("har", nargs="+")
    a=p.parse_args()
    try:
        report=inventory(a.har,a.host.lower())
        result=compare(report,json.loads(a.previous.read_text()),json.loads(a.proposed.read_text()))
        print(json.dumps(result,indent=2))
    except (ValueError,OSError) as e:
        p.exit(2,f"Error: {e}\n")

if __name__=="__main__":
    main()
