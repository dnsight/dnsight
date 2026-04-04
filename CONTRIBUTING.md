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

## CLI (Typer)

New or edited commands under `src/dnsight/cli/` should use **`typing.Annotated`** for all Typer options and arguments (not `param: T = typer.Option(...)`). Defaults belong on the parameter; for flags, avoid duplicating `True`/`False` inside `typer.Option` when using `Annotated`. Shared parameter shapes live in [`src/dnsight/cli/helpers.py`](src/dnsight/cli/helpers.py) and [`src/dnsight/cli/annotations.py`](src/dnsight/cli/annotations.py).

## Before you open a PR

1. Run **`just check`** and **`just test`**; both must pass (this matches CI).
2. Run **`just fix`** if Ruff/formatting fails, then re-run checks.
3. Keep commits readable (clear messages); no formal commit-message scheme required.
4. **Dependencies:** Do not add new runtime or dev dependencies unless they are clearly necessary. If you add one, explain **why** in the PR (smaller dependency trees are a project goal).

## Pull requests: labels, titles, and branches

- Use **existing** GitHub labels that fit the work (`enhancement`, `bug`, `security`, `documentation`, `dependencies`, `github_actions`, …). **At least one** when it makes sense; **several** are fine if the PR really spans categories.
- Add the **`skip-changelog`** label when this PR must **not** require a Towncrier fragment (Dependabot uses it automatically; humans use it when CI rules say no fragment is needed). Create the label in the repo if it is missing, for example:
  `gh label create "skip-changelog" --color 6A737D --description "Do not require a Towncrier changelog fragment (CI)."`
- **Titles:** prefix with the **primary** kind of change so the queue is easy to scan, for example `Feature:`, `Bugfix:`, `Docs:`, `Security:`, `Chore:`, `CI:`, `Deps:` (map mentally to `enhancement`, `bug`, `documentation`, etc.).
- **Branches (optional):** use a short slug for the main theme, e.g. `feature/…`, `bugfix/…`, `docs/…`, `security/…`, `chore/…`, `ci/…`, `deps/…`.

Do **not** try to paste every repo label on every PR, and do not worry about triage-only labels unless they help reviewers.

## Release notes (Towncrier)

PRs **into `main`** that change **`src/**`**, **`pyproject.toml`**, **`docs/**`**, or **`tools/docgen/**`** must include at least one valid news fragment under **`changelog.d/`**, unless the **`skip-changelog`** label is present or the diff is **`uv.lock` only**. Stacked PRs into other branches are not checked until you open a PR into `main`.

Allowed fragment suffixes (five types only): **`security`**, **`feature`**, **`bugfix`**, **`patch`**, **`other`**. Name files `changelog.d/<PR#>.<suffix>.md` (example: `42.feature.md`). Unknown suffixes fail CI.

**CI enforces the PR number:** every `changelog.d/*.md` file **added or modified** in your PR must start with **this PR’s number** and a dot (from the PR URL, e.g. `…/pull/128` → `128.feature.md`). Open the PR (or refresh to read the number), then name or rename the fragment so you do not collide with another PR’s number. Leading `+` slugs are not accepted when this check runs.

**Filenames vs. PR links:** Towncrier treats the last dot-separated segment that is a type (`feature`, `bugfix`, …) as the category; **everything before that** becomes the issue id in `[#…](…/pull/…)`. So `128.caa.feature.md` becomes issue `128.caa` and breaks the GitHub pull URL. Prefer **`128.feature.md`**. To add **several separate changelog bullets for the same PR** with the same link, use Towncrier’s numeric counter after the type: **`128.feature.1.md`**, **`128.feature.2.md`**, and so on (issue stays `128`). To cover **several points in one bullet**, use **one** fragment file and put multiple Markdown list lines (or paragraphs) in the body.

**GitHub label → fragment (when you need a note):**

| Label (examples) | Prefer fragment |
| --- | --- |
| `enhancement` | `.feature.md` |
| `bug` | `.bugfix.md` or `.patch.md` (bugfix = user-visible fix; patch = small maintenance—use what fits) |
| `security` | `.security.md` |
| `documentation` | `.other.md` (e.g. start the line with `Docs:`) |
| `dependencies` / `github_actions` | Usually no fragment (path rules); optional `.other.md` if you want a release line |

Commands (after `just install`):

```bash
uv run towncrier create 123.feature.md -c "Short user-facing summary."
uv run towncrier check --compare-with origin/main
```

Maintainers roll fragments into **[CHANGELOG.md](CHANGELOG.md)** at release time with `towncrier build` (see **Releasing** below).

## Releasing (maintainers)

1. On **`main`**, with changes merged and CI green.
2. Run **`uv run towncrier build --yes --version X.Y.Z`** using the semver **without** a `v` prefix (the git tag will be `vX.Y.Z`). This updates `CHANGELOG.md` and removes the built fragments from `changelog.d/`.
3. Commit the changelog and fragment removals (e.g. `Prepare release X.Y.Z`) and push to **`main`**.
4. Create and push git tag **`vX.Y.Z`** on that commit (or create the tag via a GitHub Release). The tag must point **after** the changelog commit.
5. **Publish** the GitHub **Release** (not only a draft). The publish workflow verifies that `CHANGELOG.md` contains `## [X.Y.Z]` and that `changelog.d/` has no leftover `*.md` fragments, then builds and uploads to PyPI.

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
