# Pull request

## Summary

<!-- What does this PR change and why? Link issues with "Fixes #123" or "See #123" where relevant. -->

Use a **Conventional Commits** PR title — with **squash merge** (preferred) it becomes the only commit on `main`. If this PR is merged another way, individual commits should be conventional where you want them in release notes (merge commits are never listed). Format: `type: description` or `type(scope): description`. Types: `feat`, `fix`, `docs`, `chore`, `deps`, `refactor`, `test`, `ci`, `rm`. Apply labels (`enhancement`, `bug`, …); see [CONTRIBUTING.md](CONTRIBUTING.md).

## Checklist

- [ ] `just check` passes locally
- [ ] `just test` passes locally
- [ ] Pre-commit hooks are installed (`just pre-install`) and commits are clean
- [ ] New dependencies: **none**, or justified in the PR description (avoid unless necessary)
- [ ] Label added to best describe changes (multiple can be used)

## Notes for reviewers

<!-- Optional: risk areas, follow-ups, or context (e.g. security-sensitive paths). -->
