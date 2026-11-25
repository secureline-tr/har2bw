# Changelog

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
