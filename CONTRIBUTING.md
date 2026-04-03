# Contributing to dnsight

Thank you for helping improve dnsight. The project is open source under the [MIT License](LICENSE). By contributing, you agree that your contributions are licensed under the same terms. You do not retain proprietary ownership over code you submit here.

Maintainers review all changes. Prefer **small, focused pull requests** so review stays fast.

## Getting started

- **Python:** 3.11 or newer (CI exercises multiple versions; **3.14** is a good default for local work).
- **Tooling:** [uv](https://docs.astral.sh/uv/) and [just](https://just.systems/) are expected. With `uv`, use a supported interpreter rather than an arbitrary old patch release.

Clone the repository, then:

```bash
just install        # editable install + dev dependencies
just pre-install    # install pre-commit hooks (use this on every clone)
```

Optional: `just pre` runs pre-commit on all files without committing.

## Before you open a PR

1. Run **`just check`** and **`just test`**; both must pass (this matches CI).
2. Run **`just fix`** if Ruff/formatting fails, then re-run checks.
3. Keep commits readable (clear messages); no formal commit-message scheme required.
4. **Dependencies:** Do not add new runtime or dev dependencies unless they are clearly necessary. If you add one, explain **why** in the PR (smaller dependency trees are a project goal).

## Workflow

- **Branches:** Regular contributors with repo access should work on a **branch on this repository** and open a PR into `main`. If you do not have write access, use a **fork** and open a PR from there.
- **Issues first (recommended):** For non-trivial work—especially behaviour or security-sensitive areas (for example DMARC policy handling, DNSSEC validation)—**open an issue first** and outline the problem and proposed approach so maintainers have context before you invest in a large PR.
- **Templates:** Use the [issue templates](.github/ISSUE_TEMPLATE/) and the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) so reports and reviews stay consistent.

## Project rules (read this)

**[AGENTS.md](AGENTS.md)** is the canonical guide for layout, style, public API (`__all__`), tests, and architecture. In particular:

- Respect the **dependency layers** (`cli` → `sdk` → orchestrator → `checks` → `core`; `checks` → `utils` only).
- **CLI** must not import from `checks/` directly; go through `dnsight.sdk`.
- The default test suite must **not** use real DNS or HTTP; use fakes (see `FakeDNSResolver`, `FakeHTTPClient` in `AGENTS.md` and existing tests).

## Adding a new check (outline)

Use an existing check under `src/dnsight/checks/` as a template. You will typically need to:

1. Implement a **`BaseCheck`** subclass, register it with **`@register`**, and expose a stable entry via `checks/<name>/__init__.py`.
2. Add the corresponding **config slice** and defaults where other checks are wired.
3. Expose behaviour through the **CLI** via the same patterns as existing commands (SDK/orchestrator, not direct `checks/` imports from CLI code).
4. Add **tests** that assert behaviour using fakes, following patterns in `tests/`.

If anything in the config schema or public API is unclear, open an issue before expanding scope.

## Security

For suspected vulnerabilities, choose **Security report** when you open a GitHub issue. Policy and expectations: **[SECURITY.md](SECURITY.md)**.

## Questions

Use **GitHub Issues** for bugs, features, and design discussion. Maintainers will triage and respond when they can.
