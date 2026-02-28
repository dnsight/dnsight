.DEFAULT_GOAL := help

.PHONY: help install install-ci lock fix check test build publish clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Environment ───────────────────────────────────────────────────────────────
install: ## Install development dependencies
	uv sync
	uv pip install e .


install-ci: ## Install from lockfile only (CI)
	uv sync --frozen


lock: ## Regenerate uv.lock
	uv lock

# ── Code quality ──────────────────────────────────────────────────────────────
fix: ## Auto-fix lint and formatting issues
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

check: ## Run all checks (lint, format, typecheck)
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/
	uv run mypy src/

# ── Testing ───────────────────────────────────────────────────────────────────
test: ## Run test suite with coverage
	uv run pytest

# ── Build and publish ─────────────────────────────────────────────────────────
build: clean ## Build distribution packages
	uv build

publish: build ## Publish to PyPI
	uv publish

# ── Maintenance ───────────────────────────────────────────────────────────────
clean: ## Remove build artifacts and cache
	rm -rf dist/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

re-venv: ## Re-create venv from existing lockfile
	uv venv --clear
	$(MAKE) install