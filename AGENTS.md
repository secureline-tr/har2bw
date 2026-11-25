# HAR2BW contributor instructions

- Process HARs locally. Use synthetic fixtures only; never commit customer HARs,
  credentials, generated customer policies, snapshots or logs.
- Preserve default-deny, method scoping, TLS verification, CORS/XSRF and WAF
  protections. Treat input HAR and NGINX configuration as untrusted data.
- Never execute uploaded configuration or automatically change a live WAF.
  API integration is read-only; deployment and rollback are operator actions.
- Bind approvals to the reviewed report. Re-analysis must invalidate old approvals.
- Unknown policy syntax is unknown, not evidence of effective access or redundancy.
- Run unittest discovery, test_nginx.py with a local loopback NGINX, UI tests,
  Ruff, Bandit and dependency audit. Record unavailable checks honestly.
- Update TODO.md, CHANGELOG.md and user docs with behavior changes.
