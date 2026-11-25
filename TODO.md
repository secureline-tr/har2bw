# HAR2BW v1.2.0 roadmap (14 stages)

- [x] 1 NGINX parser and HAR comparison (conservative subset, overlap hints)
- [x] 2 Web UI integration (tables, filters, previous-approval compare)
- [x] 3 Gitleaks history scan in CI + repository hygiene tests
- [x] 4 Project backup/versioning (`history.py`, append-only, checksum chain)
- [x] 5 Rollback: manual plan generator only. A rollback *engine* that changes a WAF is
      out of scope under AGENTS.md; deployment and rollback stay operator actions.
- [x] 6 BunkerWeb API: read-only snapshots; writes remain out of scope
- [x] 7 Authentication: optional shared password; not a user system (UI stays local)
- [x] 8 Multi-project: local workspace per project, git-ignored
- [x] 9 CSV and PDF reports
- [x] 10 Turkish/English UI complete (CLI messages and report data remain English)
- [ ] 11 Branch protection: owner setting, see docs/branch-protection.md
- [x] 12 CI/CD and regression tests (72+ tests; run in CI after the PR is pushed)
- [ ] 13 Release and tag: tags v1.0.0, v1.1.0, v1.2.0 pushed; GitHub Release pages still to publish (docs/release.md)
- [x] 14 BunkerWeb 1.6.18 validation for 1.1.0 and 1.2.0 (staging on main: https://github.com/secureline-tr/har2bw/actions/runs/45612241254)

# HAR2BW v1.1.0 follow-ups

- [x] Run NGINX loopback integration (20/20 cases incl. `<int>`), Ruff, Bandit, pip-audit
      and 54 unit/UI tests locally.
- [x] Full Ruff/Bandit CI scope, packaging, known limitations, extra tests.
- [x] Opt-in gated numeric ID patterns; generic risk terms with additive file.
- [x] Textual overlap hints in policy comparison.
- [x] Cut Actions minutes: no duplicate push+PR runs, staging only on main/manual, stale runs cancelled.
- [x] Verify all CI jobs and re-run isolated BunkerWeb staging/rollback for 1.1.0 (all green).
  PR head `12b63d8`: CI https://github.com/secureline-tr/har2bw/actions/runs/45609272464
  and staging https://github.com/secureline-tr/har2bw/actions/runs/45610029581.
  Merge commit `a061d8a` on main: CI https://github.com/secureline-tr/har2bw/actions/runs/45610226992
  and staging https://github.com/secureline-tr/har2bw/actions/runs/45610226979.
  Earlier PR runs failed only because the account's Actions minutes were exhausted
  (jobs never got a runner); they were re-run after the quota was restored.
  Staging log contents (check counts) were not inspected here; see the run artifacts.
- [x] PR #2 (v1.0.0) is merged (2026-11-25); tags v1.0.0 (`3bea371`), v1.1.0 (`a061d8a`) and
      v1.2.0 (`ad36341`) exist on origin.
- [ ] Publish GitHub Release pages for v1.1.0 and v1.2.0 (notes derived from CHANGELOG.md).
- [ ] Human review of the numeric-ID feature before relying on it in production.

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
Publication: PR #2 is merged and the v1.0.0 tag exists; GitHub Release pages are tracked above.

The original v0.1–v0.6 milestones are consolidated into v1.0.0; historical tags
are not retroactively created. Automatic API writes/deployments are out of scope
under the project safety constraint. No live WAF was changed.
