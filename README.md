# dnsight

| | |
| :--- | :--- |
| **Testing** | [![CI](https://github.com/dnsight/dnsight/actions/workflows/ci.yaml/badge.svg)](https://github.com/dnsight/dnsight/actions/workflows/ci.yaml) [![codecov](https://codecov.io/github/dnsight/dnsight/graph/badge.svg?token=B4BKEX1G8O)](https://codecov.io/github/dnsight/dnsight) [![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=dnsight_dnsight&metric=alert_status&token=479932a2a9cce01e25841c72ae83c300d5534029)](https://sonarcloud.io/summary/new_code?id=dnsight_dnsight) |
| **Package** | [![PyPI](https://img.shields.io/pypi/v/dnsight.svg)](https://pypi.org/project/dnsight/) [![Python](https://img.shields.io/pypi/pyversions/dnsight.svg)](https://pypi.org/project/dnsight/) [![Downloads](https://img.shields.io/pypi/dm/dnsight.svg)](https://pypi.org/project/dnsight/) |
| **Meta** | [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Docs](https://img.shields.io/badge/docs-site-blue)](https://dnsight.github.io/dnsight/) |
| **Stack** | [![uv](https://img.shields.io/badge/uv-black?logo=uv)](https://docs.astral.sh/uv/) [![Ruff](https://img.shields.io/badge/ruff-black?logo=ruff)](https://docs.astral.sh/ruff/) [![just](https://img.shields.io/badge/just-black?logo=just)](https://just.systems/) [![SonarCloud](https://img.shields.io/badge/SonarCloud-126ED3?logo=sonarcloud)](https://sonarcloud.io) [![Aikido](https://img.shields.io/badge/Aikido%20Security-645DD7)](https://aikido.dev/) |

**dnsight** is a Python SDK and CLI for auditing DNS, email authentication (SPF, DKIM, DMARC), and related signals. Use it from the shell or import it in your own tooling.

**Python:** supports **3.11+**. If you’re working on the project or want to match what maintainers run day to day, use **3.14** (that’s also what our default CI setup targets). We test against 3.11 through 3.14.

## Install

Same package gives you both the **`dnsight`** command and the importable API. Install however you like:

```bash
pip install dnsight
uv add dnsight                    # in a project
uv tool install dnsight             # standalone tool env
pipx install dnsight              # optional: isolated CLI app
```

## Quickstart (CLI)

```bash
dnsight --help
dnsight audit example.com
dnsight config example > dnsight.yaml
dnsight dmarc generate
```

Global flags (e.g. output format) are on the root command—try `dnsight --help` for options like `--format`.

### Logging (CLI)

Diagnostics go to **stderr** via the `dnsight` logger, using **Rich** (level colours, optional paths and tracebacks). Audit **results on stdout are unchanged** by `--quiet`; quiet only raises the log threshold so INFO/DEBUG lines disappear.

| Flag | Effect |
| --- | --- |
| *(default)* | INFO logs, compact lines (`message · logger.name`) |
| `--quiet` / `-q` | ERROR only on stderr |
| `--verbose` / `-v` | DEBUG, show call paths, Rich tracebacks on errors |

If both `--quiet` and `--verbose` are passed, **`--quiet` wins**.

**Library use:** call `configure()` from `dnsight.core` when you want visible logs. Keyword options include `detailed_log=True` (include file/line in plain mode or path column in Rich mode), `use_rich=True` for coloured output, `rich_tracebacks=True` for exception formatting, and `format_string=...` for a fully custom `logging.Formatter` layout (this forces a plain stderr stream handler).

## Commands

Besides **`version`**, **`docs`** (prints the documentation site URL), **`audit`**, and **`config`**, there’s a group per check: **`caa`**, **`dkim`**, **`dmarc`**, **`dnssec`**, **`headers`**, **`mx`**, **`spf`**. Pass domains (or rely on manifest mode from config) to run the check; some groups add a **`generate`** subcommand for record output. See `dnsight --help` and `dnsight <cmd> --help` for the exact shape.

## Output formats

`-f` / `--format` accepts **rich** (default), **json**, **sarif**, or **markdown**. Use `-o` / `--output` to write to a file instead of stdout.

## Shell completion

Typer can emit completion scripts: `dnsight --install-completion` (and `--show-completion` if you just want to inspect). If you’re hacking on the repo, `tools/dnsight-completion.zsh` is a tiny helper for zsh.

## SDK

```python
from dnsight import run_check_sync, run_domain_sync

audit = run_domain_sync("example.com")
print(audit.critical_count, audit.partial)

dmarc = run_check_sync("dmarc", "example.com")
print(dmarc.passed, len(dmarc.issues))
```

## Hacking on dnsight

You’ll want **[uv](https://docs.astral.sh/uv/)** (we expect at least **0.10.7**) and **[just](https://just.systems/)**. **Python 3.14** is the comfortable default for local work.

```bash
just install       # editable install + dev deps
just pre-install   # pre-commit hooks
just check && just test
```

Ruff, mypy, and friends come from the dev dependency group—you don’t need to install them globally. Process and expectations: [CONTRIBUTING.md](CONTRIBUTING.md). Architecture notes for agents and contributors: [AGENTS.md](AGENTS.md).

## Documentation

The **MkDocs** site (configuration guide, CLI reference, API stubs) is built from **`docs/`** and published to **GitHub Pages** on pushes to **`main`** ([workflow](https://github.com/dnsight/dnsight/actions/workflows/documentation-pages.yaml)). The public URL is **`https://dnsight.github.io/dnsight/`** (see `site_url` in `mkdocs.yml`). The repository must use **Settings → Pages → Source: GitHub Actions** the first time you enable hosting.

**Preview locally:** install the docs dependency group, then serve (live reload on edits):

```bash
uv sync --group docs    # or: just install  # includes all groups
just docs-serve         # http://127.0.0.1:8000
```

Use **`just docs-build`** for a strict production-like build. After changing the CLI tree, run **`just docs-generate`** and commit everything under **`docs/cli/`**; the **Documentation** job in [CI](https://github.com/dnsight/dnsight/actions/workflows/ci.yaml) checks that tree stays in sync and runs **`mkdocs build --strict`**.

This README, **AGENTS.md**, and the code remain the day-to-day sources of truth for behaviour; the site summarises and links outward where useful.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventional commits, and release notes. Releases: [GitHub Releases](https://github.com/dnsight/dnsight/releases). Security: [SECURITY.md](SECURITY.md).

## License

MIT
