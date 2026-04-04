# Contributing to dnsight

Thank you for helping improve dnsight. The project is open source under the [MIT License](LICENSE). By contributing, you agree that your contributions are licensed under the same terms. You do not retain proprietary ownership over code you submit here.

Maintainers review all changes. Prefer **small, focused pull requests** so review stays fast.

## Getting started

- **Python:** 3.11 or newer (CI exercises multiple versions; **3.14** is a good default for local work).
- **Tooling:** [uv](https://docs.astral.sh/uv/) and [just](https://just.systems/) are expected. With `uv`, use a supported interpreter rather than an arbitrary old patch release.

Clone the repository, then:

```bash
just install        # editable install + dev dependencies
just pre-install    # pre-commit + commit-msg (conventional commits)
```

`just pre-install` also enables the **commit-msg** hook ([conventional-pre-commit](https://github.com/compilerla/conventional-pre-commit)).

Optional: `just pre` runs pre-commit on all files without committing.

## CLI (Typer)

New or edited commands under `src/dnsight/cli/` should use **`typing.Annotated`** for all Typer options and arguments (not `param: T = typer.Option(...)`). Defaults belong on the parameter; for flags, avoid duplicating `True`/`False` inside `typer.Option` when using `Annotated`. Shared parameter shapes live in [`src/dnsight/cli/helpers.py`](src/dnsight/cli/helpers.py) and [`src/dnsight/cli/annotations.py`](src/dnsight/cli/annotations.py).

## Before you open a PR

1. Run **`just check`** and **`just test`**; both must pass (this matches CI).
2. Run **`just fix`** if Ruff/formatting fails, then re-run checks.
3. Use **Conventional Commits** for **PR titles** (default **squash** merge uses the title as the only new commit on `main`). If you merge without squash, use conventional messages on the commits you want in the notes. Allowed types: `feat`, `fix`, `docs`, `chore`, `deps`, `refactor`, `test`, `ci`, `rm`. CI enforces **PR titles** via [`.github/workflows/pr-title.yaml`](.github/workflows/pr-title.yaml); enable it as a **required check** on `main` in branch protection.
4. **Dependencies:** Do not add new runtime or dev dependencies unless they are clearly necessary. If you add one, explain **why** in the PR (smaller dependency trees are a project goal).

## Pull requests: labels, titles, and branches

- Use **existing** GitHub labels that fit the work (`enhancement`, `bug`, `security`, `documentation`, `dependencies`, `github_actions`, …). **At least one** when it makes sense; **several** are fine if the PR really spans categories.
- **Titles:** conventional form `type: summary` or `type(scope): summary` (e.g. `feat: add DMARC report`, `fix(cli): handle empty zone`). Map labels mentally (`enhancement` → often `feat`, `bug` → `fix`, etc.).
- **Branches (optional):** use a short slug for the main theme, e.g. `feature/…`, `bugfix/…`, `docs/…`, `security/…`, `chore/…`, `ci/…`, `deps/…`.

Do **not** try to paste every repo label on every PR, and do not worry about triage-only labels unless they help reviewers.

## Merging to `main` (squash vs merge)

- **Preferred: Squash and merge.** One commit lands on `main` per PR, using the **PR title** as the message—this matches release notes (one conventional line per change) and keeps history easy to read. Repo settings can default to squash; branch protection can allow only squash if you want to enforce it.
- **Rebase and merge:** Every commit from the PR appears on `main`. Use **conventional messages on each commit** you care about in release notes; `chore` / `deps` / `ci` / `test` lines are still filtered per [`cliff.toml`](cliff.toml).
- **Create a merge commit:** The GitHub **merge commit** (`Merge pull request #…`) is **omitted** from generated release notes; the commits brought in by the merge still appear if they match conventional types and your parsers. Prefer squash unless you have a reason to keep a merge bubble.

Release note generation never includes those merge-commit messages, regardless of squash default.

## Release notes

There is no per-PR changelog fragment workflow. **[git-cliff](https://git-cliff.org/)** turns conventional history into Markdown (see [`cliff.toml`](cliff.toml)). **`feat`**, **`fix`**, **`docs`**, **`refactor`**, and **`rm`** appear in release notes; **`chore`**, **`deps`**, **`ci`**, and **`test`** are skipped. **Git merge commits** (`Merge pull request …`, `Merge branch …`, etc.) are always skipped.

Preview locally: `just release-notes` (unreleased → default `local/release-notes.md`, gitignored under `local/`) or `just release-notes vX.Y.Z ''` for stdout. With **`GITHUB_TOKEN`** set (e.g. `gh auth token`), PR links are filled in; otherwise the recipe uses **`--offline`**.

## Releasing (maintainers)

1. On **`main`**, with changes merged and CI green.
2. Create and push tag **`vX.Y.Z`** (or create the tag when publishing the GitHub Release).
3. **Publish** the GitHub **Release** for that tag. The [Publish workflow](.github/workflows/publish.yaml) runs on **`release: published`**: checks out the tag, runs **`just release-notes "$TAG" release-notes.md`**, builds, publishes to **PyPI**, then **updates the release body** and attaches **`dist/*`**.

PyPI’s project page uses **`README.md`** as the long description; the **Changelog** link points at **GitHub Releases**.

## Workflow

- **Branches:** Regular contributors with repo access should work on a **branch on this repository** and open a PR into `main`. If you do not have write access, use a **fork** and open a PR from there.
- **Issues first (recommended):** For non-trivial work—especially behaviour or security-sensitive areas (for example DMARC policy handling, DNSSEC validation)—**open an issue first** and outline the problem and proposed approach so maintainers have context before you invest in a large PR.
- **Templates:** Use the [issue templates](.github/ISSUE_TEMPLATE/) and the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) so reports and reviews stay consistent.

## Project rules (read this)

**[AGENTS.md](AGENTS.md)** is the canonical guide for layout, style, public API (`__all__`), tests, and architecture. In particular:

- Respect the **dependency layers** (`cli` → `sdk` → orchestrator → `checks` → `core`; `checks` → `utils` only).
- **CLI** must not import from `checks/` directly; go through `dnsight.sdk`.
- The default test suite must **not** use real DNS or HTTP; use fakes (see `FakeDNSResolver`, `FakeHTTPClient` in `AGENTS.md` and existing tests).

### Local config for manual runs

For optional **manual** audits with real DNS/HTTP and YAML you do not want in git,
use [`local/dnsight-configs/`](local/dnsight-configs/README.md). Files there are
gitignored except the README; see that file for CLI examples. This is separate
from CI: `just test` stays deterministic and offline.

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
