# dnsight — Agent Briefing

Briefing for AI agents (Claude, Cursor, etc.) working on this repo.

**Human contributors:** see [CONTRIBUTING.md](CONTRIBUTING.md).

Long-form reference (config schema, per-check normative behaviour) will live under `docs/` (forthcoming). Until then, use **this file**, **module docstrings**, implementation under `src/dnsight/core/config/` and `src/dnsight/core/schema/`, and **tests** as ground truth.

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
├── orchestrator.py  # Generic run_domain, run_zone, run_check_for_target, batch (no per-check symbols)
├── sdk/               # Human-facing: config resolution + thin calls into orchestrator
│   ├── _manager.py    # config_manager; resolve_run_manager; minimal_config_manager
│   ├── run.py         # run_check, run_domain, run_targets, streams (+ sync shims)
│   ├── generate.py    # generate(check_name, params=...)
│   └── aliases.py     # Optional check_*_sync / generate_* wrappers (registry names)
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
cli/  →  sdk/  →  orchestrator.py  →  checks/  →  core/
                                        checks/  →  utils/
```

- `core/` imports nothing from other internal packages
- `checks/` never imports from each other or from orchestrator
- `cli/` imports from `dnsight.sdk` and `core/` only — never directly from `checks/`

**Examples:** Good: `from dnsight.sdk import run_check_sync` in `cli/`. Bad: `from dnsight.checks.dmarc import ...` in `cli/` — use the SDK (or orchestrator patterns), not check packages directly.

### SDK and CLI (same conceptual API)

- **Orchestrator** implements execution only (registry strings, `ConfigManager`, `Runtime`, trees, batch). **SDK** resolves config via `config_manager()` / `resolve_run_manager()` then calls orchestrator; it does not embed check-specific orchestration logic.
- **Single check**: `run_check` / `run_check_sync(name, domain, config_path=..., mgr=..., config=...)` with `name` from `all_checks()`. Optional `dnsight.sdk.aliases` provide async `check_<name>` and `check_<name>_sync` for each registered check, plus typed `generate_*`; programmatic overrides use `config=` and optional `config_slice=` (the matching `Config` field) when `mgr` is unset.
- **Full audit (one root)**: `run_domain` / `run_domain_sync`. **Manifest / execute all targets**: `run_targets` / `run_targets_sync` (deprecated aliases: `run_batch` / `run_batch_sync`). Shared options: `RunAuditOptions` (or equivalent keyword args) for `checks` / `exclude` / `recursive` / `depth`.
- **CLI** (when implemented) should parse argv into the **same keyword arguments** as these SDK functions.

#### SDK programmatic `Config` (single-check only, v1)

Applies to `run_check` / `run_check_sync` and typed aliases that forward programmatic config. **`run_domain` and `run_targets` do not** accept inline `config=`; they use `mgr` + YAML + discovery only.

| Order | Source | Behaviour |
| --- | --- | --- |
| 1 | `mgr=` | Use the passed `ConfigManager` as-is; inline `config=` is ignored for that call. |
| 2 | `config=` not set | Same as `config_manager`: optional `config_path`, else discover `dnsight.yaml`, else built-in defaults (`default_config_manager`). |
| 3 | `config=` set | If a YAML file applies (explicit `config_path` or discovered `dnsight.yaml`), load it, `resolve(domain)`, merge `config=` on top (explicit fields in `config=` win). Then build a **synthetic** single-check manager for that run. If no YAML file exists, build that synthetic manager from `config=` alone. |

**Synthetic manager:** Built by `minimal_config_manager`: one catch-all include rule, no manifest `targets` rows, `enabled_checks` = the one check being run. This is not equivalent to a full multi-target YAML config; pattern nuance is folded into the merged `Config` for that audit.

**Check aliases:** `check_<name>` / `check_<name>_sync` accept `config=` and optional `config_slice=`; when both are set, `config_slice=` sets/overrides that check’s slice on `Config` (e.g. DMARC → `Config.dmarc`).

For the full config precedence model (defaults → top-level → group → domain), see **Config System** below and the code references there.

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

**Where to read the full schema and merge rules:** `core/config/parser/` (YAML v1), `core/config/blocks.py`, `core/config/pattern.py`, `core/config/config_manager.py`, per-check config slices under `core/schema/`, and `tests/core/config/`.

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
