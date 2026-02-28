# Default recipe — lists all available commands
default:
    @just --list

# == Environment ================================================================

# Install development dependencies
install:
    uv sync
    uv pip install -e .

# Install from lockfile only (CI)
install-ci:
    uv sync --frozen

# Regenerate uv.lock
lock:
    uv lock

# == Code quality ===============================================================

# Run all checks (lint, format, typecheck, config files)
check:
    #!/usr/bin/env bash
    failed=0
    run_checked() { if ! "$@"; then echo "FAILED: $*"; failed=1; fi; }
    run_checked uv run ruff check src/ tests/
    run_checked uv run ruff format --check src/ tests/
    run_checked uv run mypy src/
    run_checked uv run yamllint $(find . \( -name "*.yml" -o -name "*.yaml" \) | grep -vE "^\./(.venv|src|tests)/")
    run_checked uv run check-jsonschema --builtin-schema github-workflows .github/workflows/*.yaml
    run_checked uv run taplo check $(find . -name "*.toml" | grep -vE "^\./(.venv|src|tests)/")
    exit $failed

# Auto-fix lint and formatting issues
fix:
    #!/usr/bin/env bash
    failed=0
    run_checked() { if ! "$@"; then echo "FAILED: $*"; failed=1; fi; }
    run_checked uv run ruff check --fix src/ tests/
    run_checked uv run ruff format src/ tests/
    run_checked uv run yamlfix $(find . \( -name "*.yml" -o -name "*.yaml" \) | grep -vE "^\./(.venv|src|tests)/")
    run_checked uv run taplo fmt $(find . -name "*.toml" | grep -vE "^\./(.venv|src|tests)/")
    exit $failed

# == Pre-Commit =================================================================

# Install pre-commit hooks
pre-install:
    uv run pre-commit install

# Run pre-commit on all files
pre:
    uv run pre-commit run --all-files

# == Testing ====================================================================

# Run test suite with coverage
test *args:
    uv run pytest {{args}}

# == Build and publish ==========================================================

# Build distribution packages
build: 
    just clean
    uv build

# Publish to PyPI after build
publish: 
    just build
    uv publish

# == Maintenance ================================================================

# Remove build artifacts and cache
clean:
    rm -rf dist/ coverage.xml .coverage  htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/
    find . -type d -name __pycache__ -print0 | xargs -0 rm -rf 2>/dev/null || true
    find . -type f -name "*.pyc" -delete

# Re-create venv from existing lockfile
re-venv:
    uv venv --clear
    just install