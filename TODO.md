# HAR2BW v1.0.0

- [x] Import and verify existing source, tests and all three upstream branches.
- [x] Inspect successful baseline GitHub Actions, including Docker/security/UI jobs.
- [x] Multi-HAR local UI, risk review, explicit approvals and export bundle.
- [x] Conservative existing-policy inventory without executing configuration.
- [x] Missing/unobserved and duplicate rule analysis; no automatic removal.
- [x] Non-root Docker packaging with read-only filesystem and loopback binding.
- [x] Optional HTTPS API integration limited to explicit read-only config snapshots.
- [x] Report-bound approvals and checksum manifest; private CLI output permissions.
- [x] Security review: short numeric IDs, URL normalization, query gates, real-IP acknowledgement.
- [x] AGENTS.md, migration notes and manual staging/rollback instructions.
- [x] Regression tests for CLI, security gates, UI state and API transport contract.
- [x] Local unit/UI tests, NGINX allow/deny integration, Ruff, Bandit and dependency audit.
- [x] Verify release code in GitHub Actions, including Docker health/non-root checks.
  All six jobs passed for `6b4d3c1`: https://github.com/secureline-tr/har2bw/actions/runs/45589851828
  Local validation: 36 unit/UI tests, 16 NGINX request cases, Ruff, Bandit and pip-audit.

## Operator release gates

- [x] Validate BunkerWeb 1.6.18 with synthetic traffic in disposable GitHub-hosted staging.
- [x] Verify guard wiring, proxy trust, backend authorization and rollback: 48 checks passed.
  Evidence: https://github.com/secureline-tr/har2bw/actions/runs/45592324840
  Full scope and checksum evidence: docs/staging-validation.md.
Publication is tracked in PR #2 and GitHub Releases after the final commit checks.

The original v0.1–v0.6 milestones are consolidated into v1.0.0; historical tags
are not retroactively created. Automatic API writes/deployments are out of scope
under the project safety constraint. No live WAF was changed.
