# Release and tagging

Run these only from a merged, green `main`. Tags are public history; do not move or delete them.

1. Confirm the latest `main` commit has green `ci.yml` and `staging.yml` runs.
2. Confirm `review_bundle.VERSION`, `pyproject.toml` and the top CHANGELOG entry agree.
3. Create an annotated tag on that commit, for example `git tag -a v1.2.0 -m "HAR2BW 1.2.0"`,
   then `git push origin v1.2.0` (or use GitHub Releases → Draft a new release → Create tag).
4. Release notes: copy the CHANGELOG entry, link the CI and staging runs, and state which
   checks were not run. Do not attach customer artifacts or staging output you have not reviewed.
5. Older v0.x milestones were consolidated into v1.0.0 and are not tagged retroactively.
