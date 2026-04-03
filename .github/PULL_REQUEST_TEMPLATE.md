# Pull request

## Summary

<!-- What does this PR change and why? Link issues with "Fixes #123" or "See #123" where relevant. -->

Use a **title prefix** for the main kind of change when it helps (e.g. `Feature:`, `Bugfix:`, `Docs:`, `Security:`). Apply GitHub labels that fit (`enhancement`, `bug`, …); see [CONTRIBUTING.md](CONTRIBUTING.md) for how they relate to **Towncrier** fragments.

## Checklist

- [ ] `just check` passes locally
- [ ] `just test` passes locally
- [ ] Pre-commit hooks are installed (`just pre-install`) and commits are clean
- [ ] New dependencies: **none**, or justified in the PR description (avoid unless necessary)
- [ ] Label added to best describe changes (multiple can be used)
- [ ] **Changelog:** added `changelog.d/<PR#>.<type>.md` with a valid type (`security`, `feature`, `bugfix`, `patch`, `other`) when required for PRs into `main`, **or** applied the **`skip-changelog`** label, **or** your diff does not touch `src/**` / `pyproject.toml` (or is `uv.lock` only)—see [CONTRIBUTING.md](CONTRIBUTING.md)

## Notes for reviewers

<!-- Optional: risk areas, follow-ups, or context (e.g. security-sensitive paths). -->
