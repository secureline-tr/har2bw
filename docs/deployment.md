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

API deployment is intentionally not implemented until the target BunkerWeb version, API contract, authentication, staging scope and rollback behavior are verified. No automated network deployment is performed.
