# Changelog

## Unreleased
- Complete the Turkish UI: all labels, review gates, download buttons, comparison tables,
  warnings and common error messages. Translations are display-only; report data (and its
  hash) stay English. Widgets now have stable keys so uploads and selections survive a
  language switch. Tests guard against untranslated or unkeyed widgets.

## 1.2.0
- Add append-only project history with checksum chain (`history.py`, UI save button).
- Add manual rollback plan generator (`rollback_plan.py`); it reads local files only and
  never applies or rolls back anything.
- Add CSV and dependency-free PDF reports with CSV formula-injection protection.
- Add optional shared UI password (`HAR2BW_UI_PASSWORD`), Turkish/English UI strings,
  local project workspace, comparison tables, candidate filters and approval compare.
- Add gitleaks history scan (pinned binary, checksum-verified) and repository hygiene tests.
- Add branch protection and release procedures under docs/.
- Docker image and build context include the new modules.

## 1.1.0
- Add opt-in `--numeric-ids` / `--allow-numeric`: 1-9 digit segments become an
  `<int>` pattern behind an explicit gate; the option is bound into the report hash.
- Replace application-specific high-risk path terms with generic built-ins plus an
  additive `--risk-terms FILE`. Warnings only; candidate IDs and gates are unchanged.
  Migration: re-scan, as reports now carry `options` and approvals are hash-bound.
- Comparison reports `possible_overlaps` (placeholder rule textually covering another
  rule). Hints only; nothing is auto-removed and unknown syntax is never matched.
- UI: numeric generalization and its review gate; `--numeric-ids`/`--risk-terms` on
  comparison CLIs so approvals stay comparable.
- Add pyproject packaging (console scripts), a Known limitations README section,
  broader tests (API error paths, parser edge cases, numeric/NGINX loopback cases).
- CI now runs full Ruff (configured in pyproject) and Bandit over the whole tree.
- Reduce metered Actions minutes: push runs only on main, staging runs on main or manually, superseded runs are cancelled.

## 1.0.0
- Continue the policy-parser branch with duplicate and missing/unobserved review.
- Bind CLI approvals to the derived inventory and export checksum manifests/ZIPs.
- Invalidate UI reviews when hostname or uploaded HAR changes; add explicit clear.
- Deny queries by default, gate observed query endpoints including static assets,
  and reject encoded, dot-segment and repeated-slash request-path aliases.
- Redact all numeric path segments; require trusted real-IP acknowledgement for CIDRs.
- Add verified HTTPS, read-only API config snapshots with schema capability checks,
  bounded responses, no redirects and no ambient proxies.
- Extend unit, CLI, UI and real NGINX integration tests and CI security coverage.
- Include all review modules in the non-root Docker image and document release gates.

Breaking migration: regenerate legacy approval arrays as versioned approval
objects. Re-review query-bearing assets and short numeric paths. No live changes
or automatic historical tagging are performed.

## 0.1.0
- Offline multi-HAR inventory and host filtering.
- Explicit candidate approval, method-scoped default-deny policy drafts.
- UUID shape detection and sensitive-operation review gates.
- Synthetic fixtures and unit / NGINX integration tests.
