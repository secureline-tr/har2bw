# HAR2BW 1.0.0

Local HAR inventory, explicit review, and default-deny BunkerWeb policy drafts.
Python 3.11+; CLI uses the standard library. The web UI needs `requirements.txt`.
No automatic deployment, reload, rule deletion, or WAF disabling.

## Scan and generate

Capture authorized synthetic traffic in DevTools. Keep customer HAR files outside
Git. Analyze one or more HARs for one exact DNS hostname:

```sh
python har2bw.py scan --host flow.example.test sample.har --out review
```

Review `review/report.json`. In `review/approve.json`, populate `approved_ids`
with only the reviewed candidate IDs. Preserve `schema_version`, `host` and
`report_sha256`. Empty approvals cannot generate policies. Changes to the derived
inventory invalidate approval; re-scan and review rather than editing its digest.
Legacy bare ID arrays are intentionally rejected by generation in v1.

```sh
python har2bw.py generate --host flow.example.test sample.har \
  --approve review/approve.json --out policy
python har2bw.py --version
```

Outputs are two NGINX drafts, the bound approval and a checksum manifest, created
in a fresh owner-only directory with owner-only files. The manifest detects
accidental changes; it is not a digital signature. Downloads from the browser
inherit your browser's filesystem permissions.

Review gates are explicit: `--allow-sensitive`, `--allow-dynamic`,
`--allow-redirect-only`, and `--allow-unrestricted-query`. Query strings are denied
by default, including for static assets. The query flag permits arbitrary query
values only for approved method/path candidates observed with queries. It does
not validate query parameters or bodies. UUID patterns cover other objects and
require backend object authorization. Numeric segments (including short IDs) and
opaque/unsafe paths are redacted and cannot generate rules.

Internal CIDR bypass is optional. `--internal CIDR` additionally requires
`--confirm-trusted-real-ip`; verify trusted proxy ranges and spoofed client-IP
headers in staging. Catch-all networks are rejected. Query and raw-path guards
still apply to internal clients. This never bypasses BunkerWeb's WAF protections.

## Local review UI

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
streamlit run web.py
# Or: docker compose up --build
```

Open `http://127.0.0.1:8501`. Upload multiple HARs, analyze, inspect risks, select
individual candidates, acknowledge applicable gates, and export a review ZIP.
Changing hostname or HAR content invalidates the previous review and draft.
Upload an existing HTTP config to inspect textual matches, missing/unsupported
observations, unobserved rules and duplicate rule groups. No uploaded config is
executed. Clear the review and close the browser session after use. The UI is
single-user and must not be publicly exposed; CORS/XSRF remain enabled.

## Compare policies

```sh
python nginx_review.py --host flow.example.test --config existing.conf sample.har
python policy_diff.py --host flow.example.test \
  --previous old-approve.json --proposed review/approve.json sample.har
```

The parser recognizes a conservative subset of line-oriented NGINX maps, never
executes arbitrary regexes/includes, and reports unknown lines. Matches describe
text, not effective access: map order, includes, guard wiring and other controls
must be reviewed separately. Unobserved and duplicate rules are review candidates,
never proof that deletion is safe. Approval-set comparison also accepts legacy
ID arrays for historical review; generation does not.

## Optional read-only API snapshot

`bunkerweb_api.py` reads an explicitly named HTTP snippet over verified HTTPS.
Use a least-privilege read token via `HAR2BW_API_TOKEN`, not command-line arguments.
It checks the target OpenAPI for the config GET contract, rejects redirects,
disables ambient HTTP proxies, bounds response size and stores a private snapshot.
Use `--ca-file` for a private CA; there is no insecure TLS mode.

```sh
python bunkerweb_api.py --url https://waf-api.example.test \
  --service flow.example.test --type server_http --name allowlist --out snapshots/review
```

Only GET requests are implemented. The response wrapper is retained as JSON for
manual inspection; a snippet snapshot is not a complete rollback backup. No live
endpoint was contacted during development. Contract reference:
[BunkerWeb API](https://docs.bunkerweb.io/latest/api/).

## Validation and deployment

```sh
python -m unittest discover -v
python test_nginx.py  # installed NGINX, ephemeral loopback listener only
```

CI runs Python 3.11–3.13, real NGINX checks, UI tests, dependency audit, static
security checks, and Docker health/non-root checks. See
[deployment and rollback](docs/deployment.md) before manual staging validation.

HAR reports and configs remain sensitive: headers, cookies, bodies and query
values are omitted, but arbitrary short text identifiers cannot be reliably
anonymized. Treat every artifact as customer data. Successful responses do not
establish authorization. Encoded paths, repeated slashes and dot-segment aliases
are denied; applications that require those paths need separate manual design.
