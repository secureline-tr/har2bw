# Branch protection for `main`

A repository setting an owner applies; HAR2BW cannot and does not change it.

1. Settings → Rules → Rulesets → New ruleset → New branch ruleset.
2. Name it `protect-main`, enforcement **Active**, target branch `main` (default branch).
3. Enable: **Restrict deletions**, **Block force pushes**, **Require a pull request before merging**
   (at least 0 approvals for a solo repository; 1 when a second reviewer exists), and
   **Require status checks to pass** with these checks from `ci.yml`:
   `tests (3.11)`, `tests (3.12)`, `tests (3.13)`, `security`, `secrets`, `ui`, `docker`.
4. Leave **Require branches to be up to date** on if you want the merge result tested.
5. The staging workflow runs on `main` and manually, so it is not a required check; run it
   manually on the PR branch before a release (see docs/release.md).

Private repositories need a paid plan for rulesets; public repositories do not.
