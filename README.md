# HAR2BW

Offline HAR to BunkerWeb Policy Generator (Python 3.9+).

## Usage
Capture authorized test traffic using browser DevTools Network / Preserve log. Keep real HAR files outside Git. Use successful public workflows, not unrestricted internal portal traffic.

```bash
python3 har2bw.py scan --host flow.example.test sample.har --out review
```

Review report.json and add only approved candidate IDs to approve.json (JSON array). Generate a draft using the same HAR input:

```bash
python3 har2bw.py generate --host flow.example.test sample.har --approve review/approve.json --out policy
```

Sensitive operations, dynamic UUID patterns, redirect-only candidates and unrestricted non-static query strings require separate explicit flags. See --help. Internal network bypass is optional; only specify trusted CIDRs after verifying the real client IP.

Place the HTTP map in BunkerWeb Global HTTP and guard in the target service SERVER_HTTP. Review conflicts with existing custom configs, run nginx -t, verify scheduler reload, and test allowed and denied requests in staging. Keep prior config for rollback. Do not disable WAF protections.

The tool does not deploy anything. Query strings, bodies and object-level authorization are not enforced by URI matching. Raw HARs and generated reports may contain sensitive data; short path identifiers may escape redaction. A successful HTTP response is not proof of authorization.

## Tests
```bash
python3 -m unittest discover -v
python3 test_nginx.py
```
The second command requires nginx installed and uses loopback only.
