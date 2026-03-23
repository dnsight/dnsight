# dnsight — Agent Briefing

Briefing for AI agents (Claude, Cursor, etc.) working on this repo.
Deep design specs live in `.plan/` — read relevant docs there before making non-trivial changes.

---

## Build & Test

```bash
just install       # uv sync + pip install -e .
just check         # ruff, format, mypy, yamllint, check-jsonschema, taplo
just fix           # auto-fix ruff + format violations
just test          # pytest with coverage
just build         # build dist
just publish       # publish to PyPI
```

Always run `just check` and `just test` before considering a change complete.

---

## Code Style

- **Python**: ≥ 3.11. `src/` layout. `py.typed` present. `from __future__ import annotations` in every module.
- **Type checking**: mypy strict. No `Any` on public API. Use `TypeVar`, `Protocol`, precise generics.
- **Lint & format**: Ruff. Run `just fix` before committing.
- **Docstrings**: Google-style on all public modules, classes, functions.
- **Public API**: Explicit `__all__` in every public module.
- **Public surface area**: Keep the exported API as small as stability allows. `__all__` should list names you treat as supported; omit module-local helpers and constants. Use a leading `_` for anything used only inside a module (default: single-module private). For **checks**, the stable entry point is `checks/<name>/__init__.py` — avoid growing a large secondary public API in `rules.py` or `models.py` unless that is deliberate.

---

## Architecture

### Package layout

```text
src/dnsight/
├── core/          # Foundation — no internal imports
│   ├── types.py           # Severity, Status, Capability, enums
│   ├── exceptions.py      # DNSightError, CheckError, ConfigError, CapabilityError
│   ├── models.py          # Issue, Recommendation, CheckResult[T], ZoneResult, DomainResult
│   ├── registry.py        # @register decorator, get(), all_checks(), supporting()
│   ├── throttle.py        # Hierarchical token bucket (ThrottleManager, NoopThrottleManager)
│   ├── concurrency.py     # ConcurrencyManager, ConcurrencyLimiter protocol
│   ├── logger.py          # get_logger(), configure()
│   └── config/            # Blocks, defaults, config manager, parser
├── utils/         # I/O singletons — imports core only
│   ├── dns.py             # DNSResolver protocol, AsyncDNSResolver, FakeDNSResolver, singleton
│   └── http.py            # HTTPClient protocol, AsyncHTTPClient, FakeHTTPClient, singleton
└── checks/        # Business logic — imports core and utils only
    ├── base.py            # BaseCheckData, BaseCheck[T] ABC
    └── dmarc/             # DMARCCheck, models, rules
```

### Dependency rules (never violate)

```text
cli/  →  sdk.py  →  orchestrator.py  →  checks/  →  core/
                                        checks/  →  utils/
```

- `core/` imports nothing from other internal packages
- `checks/` never imports from each other or from orchestrator
- `cli/` imports from `sdk.py` and `core/` only — never directly from `checks/`

### Key patterns

- **BaseCheck**: `_get()`, `_check()`, `_generate()` are the impl hooks. Public `get()`, `check()`, `generate()` handle capability gating and throttle. Static methods on the check class are the direct public API; module-level aliases for convenience.
- **Registry**: Checks self-register with `@register` at import time. `all_checks()` / `get(name)` for discovery.
- **I/O singletons**: `get_resolver()` / `set_resolver()` and `get_http_client()` / `set_http_client()`. Tests inject fakes via `set_*`. Never use real DNS/HTTP in tests.
- **Throttle**: `ThrottleManager.child()` builds parent-chain hierarchy. `wait()` traverses it.
- **Capabilities**: `CHECK`, `GENERATE`. `BaseCheck` gates dispatch; raises `CapabilityError` for unsupported actions.
- **Exceptions (SDK)**: `CapabilityError` and config validation errors belong to the orchestrator/config layer. Check code surfaces DNS/HTTP failures via `CheckError` from utils and partial or completed `CheckResult` with `error`/`issues` as appropriate—not raw resolver exceptions.
- **No caching**: One audit = one run. Pure CPU helpers may use `@lru_cache`; never on DNS/HTTP.

---

## Config System

- Single `dnsight.yaml` config; discovered from CWD or `--config`.
- Precedence (low → high): built-in defaults → top-level config → group config → domain config.
- `include: "*"` with no `exclude` is the default rule.
- Checks use `ChecksReplace` (list) or `ChecksDelta` (`+name`, `-name` string).
- `core/config/defaults.py` holds all default constants.

See `.plan/v2/reference/config-system.md` for full schema.

---

## Quality Bar

- Every change must pass `just check` and `just test` with no regressions.
- Coverage: 100% `core/models` + `core/types`; ≥ 95% `core/config`, `core/registry`; ≥ 85% checks.
- No `Any` on public API. No untyped functions in `src/`.
- New checks require: BaseCheck implementation, `@register`, config slice, unit tests, docstrings.

---

## Gotchas

- Ask before changing security-sensitive logic (DNSSEC validation, DMARC policy evaluation).
- DNS and email edge cases must be handled explicitly — document in docstrings.
- Do not add persistence, scheduling, or HTTP server logic — dnsight is stateless.
- Do not import from `cli/` outside of `cli/`. Do not import from `checks/` in `cli/`.
