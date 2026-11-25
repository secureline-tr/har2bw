# Local UI and deployment review

Run locally using Python 3.12:
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    streamlit run web.py

Or: docker compose up --build
Open http://127.0.0.1:8501. Do not expose the UI to untrusted networks. It has no multi-user authentication. HARs are processed locally; avoid shared environments. Clear browser sessions after review.

Compare previously approved IDs with a proposed set:
    python policy_diff.py --host flow.example.test --previous old.json --proposed new.json sample.har

This is an approval-set comparison, not a parser for arbitrary existing nginx policies. Unobserved paths are not necessarily redundant; never remove automatically.

Before BunkerWeb deployment: export current custom configs and settings to a protected location, preserve the known-good revision, review generated drafts, verify trusted real IP handling, apply only to a staging service, run nginx -t, confirm successful scheduler reload and positive/negative functional tests. Roll back by restoring the saved config using the same control plane; repeat syntax, reload and request tests. Do not store customer snapshots in Git.

API writes and deployment are intentionally excluded. The optional snapshot utility is read-only; no automated network deployment is performed.

## v1.0.0 manual staging procedure

1. Re-scan with v1 and review the versioned approval document. Do not reuse legacy
   ID arrays or bypass a report hash mismatch. Select only authorized endpoints.
2. Review every warning and explicit gate. Static query requests now also require
   query acknowledgement; arbitrary query values remain a backend responsibility.
3. Export a review bundle and verify its checksums. Store a complete known-good
   BunkerWeb backup separately; one config snippet is not a full backup.
4. In an isolated staging service, place the HTTP draft in Global HTTP and the
   guard in that service's SERVER_HTTP. Inspect existing maps and variable names.
5. Run nginx -t using the staging control plane, confirm the scheduler applied the
   desired revision, and exercise approved/denied methods, query requests, encoded
   paths, dot segments, unauthenticated users and cross-object access.
6. If CIDRs are used, verify real-IP trust and spoofing resistance. Internal
   clients still face query/path guards and existing WAF rules.
7. Restore the saved configuration through the same control plane, confirm syntax
   and reload success, and repeat functional checks to prove rollback.
8. Only after human review should production rollout be considered. HAR2BW has
   no write/reload API and never executes this procedure automatically.

The optional API snapshot utility now implements GET-only HTTPS reads. It checks
OpenAPI capability but does not certify a particular installed version. Integration
was tested using synthetic responses; verify your target's response wrapper and
read ACLs before use. See README for invocation and CA/token handling.
