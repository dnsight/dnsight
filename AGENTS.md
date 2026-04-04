# dnsight — Agent Briefing

Briefing for AI agents (Claude, Cursor, etc.) working on this repo.
All changes must be consistent with this file and the quality bar below.
Deep design specs live in `.plan/` (not committed) — read relevant docs there before making non-trivial changes.

---

## Build & Test

```bash
just install       # uv sync + pip install -e .
just check         # ruff, format, mypy, yamllint, check-jsonschema, taplo
just fix           # auto-fix ruff + format violations
just test          # pytest with coverage
just build         # build dist
just publish       # publish to PyPI
just pre-install   # install pre-commit hooks
just pre           # run pre-commit on all files
```

Always run `just check` and `just test` before considering a change complete.

---

## Code Style

- **Python**: ≥ 3.11. `src/` layout. `py.typed` present.
- **Type checking**: mypy strict on `src/`. No `Any` on public API surfaces. Use `TypeVar`, `Protocol`, and precise generics.
- **Lint & format**: Ruff for both lint and format. Run `just fix` before committing.
- **Docstrings**: Google-style on all public modules, classes, and functions. Document contracts, args, returns, and edge cases.
- **Design order**: Types and protocols before implementation. No new behaviour without tests.
- **Public API**: Explicit `__all__` in every public module.

---

## Architecture

### Package layout

```
src/dnsight/
├── __init__.py          # public API surface, __all__, version
├── cli.py               # Typer app root, CLI entrypoint
│
├── core/
│   ├── enums.py         # Severity, Status, Capability, OutputFormat, DNSProvider, IssueIdEnum, RecommendationIdEnum
│   ├── exceptions.py    # DNSightError, CheckError, ConfigError, CapabilityError, …
│   ├── models.py        # Issue, Recommendation, CheckResult[T], GeneratedRecord, ZoneResult, DomainResult
│   ├── registry.py      # module-level singleton: register(), get(), all_checks(), supporting()
│   ├── runtime.py       # Runtime dataclass (config, throttle, concurrency) — orchestrator only
│   ├── throttle.py      # hierarchical token bucket with parent-child; child() method
│   ├── concurrency.py   # global semaphore to cap total in-flight tasks
│   ├── logger.py        # structured logging helpers
│   └── config/
│       ├── defaults.py       # default constants (no internal imports)
│       ├── blocks.py         # ThrottleConfig, DmarcConfig, SpfConfig, Config
│       ├── mergeable.py      # MergeableConfig base with merge/override + resolve()
│       ├── pattern.py        # Pattern class for pattern matching
│       ├── targets.py        # Target, TargetChecks (frozenset), TargetConfig, ResolvedTargetConfig
│       ├── config_manager.py # ConfigManager for config resolution
│       └── parser/           # versioned YAML config file parsing
│
├── utils/
│   ├── dns.py           # DNSResolver protocol, AsyncDNSResolver, FakeDNSResolver, singleton
│   └── http.py          # HTTPClient protocol, AsyncHTTPClient, FakeHTTPClient, singleton
│
└── checks/
    ├── base.py          # BaseCheckData, BaseCheck[CheckDataT] ABC
    ├── dmarc/           # DMARC check package: __init__.py (DMARCCheck), models.py, rules.py
    └── (per-check packages — each self-contained)
```

Modules such as sdk, orchestrator, serialisers, and the full cli/ layout are planned; the current codebase has the structure above.

**Current status:** Implemented: core/, utils/, checks/base, checks/dmarc (package with models, rules), cli.py (scaffold). Planned: sdk, orchestrator, serialisers, remaining checks, full CLI.

### Dependency rules (strict)

```
cli/  →  sdk.py  →  orchestrator.py  →  checks/    →  core/
                                        checks/    →  utils/
                                        serialisers/ →  core/
```

- **core/** — Imports nothing from any other internal package. Foundation only.
- **utils/** — Imports from core only.
- **checks/** — Imports from core and utils only. Never from each other or orchestrator.
- **cli/** — Imports from `sdk.py` and `core/` only — never directly from `checks/` or `orchestrator.py`
- Checks are self-contained: each owns its data model, issue/rec ID enums, config slice, check class, static methods, and module-level re-exports.

### Key patterns

- **BaseCheck ABC**: `checks/base.py` defines `BaseCheckData` and `BaseCheck[CheckDataT]`. Public methods (`get`, `check`, `generate`) handle capability gating and throttle; subclasses implement `_get()`, `_check()`, `_generate()`. Static methods on the check class provide the direct public API; module-level re-exports for convenience.
- **Registry**: `core/registry.py` is a module-level singleton. Checks register with `@register` decorator at class definition. Functions: `register()`, `get()`, `all_checks()`, `supporting()`.
- **I/O Protocols**: `DNSResolver` and `HTTPClient` protocols in `utils/` define the contract. `AsyncDNSResolver` and `AsyncHTTPClient` are the real implementations. Module-level singletons with `get_resolver()` / `set_resolver()` / `get_http_client()` / `set_http_client()`. Tests override via `set_resolver(FakeDNSResolver(...))` / `set_http_client(FakeHTTPClient(...))`. Custom resolvers/clients can be injected by any object satisfying the protocol.
- **Throttle hierarchy**: `ThrottleManager` supports parent-child via `child()`. Orchestrator creates: global → domain → check throttlers. `wait()` traverses the parent chain.
- **Runtime**: `Runtime` is created once per audit by the orchestrator and holds config, throttle, concurrency. **Checks do not receive or import Runtime** — they accept optional `throttler` parameter instead.
- **Capabilities**: Checks declare supported capabilities (`CHECK`, `GENERATE`, `FLATTEN`). `BaseCheck` gates dispatch; `CapabilityError` raised for unsupported actions.
- **TargetChecks**: `TargetChecks` stores enabled check names as a `frozenset[str]` — no hardcoded check-specific fields. The registry is the single source of truth for valid check names; config just stores strings. Adding a new check never requires touching `TargetChecks` or core.
- **No CheckId enum**: There is no static enum of check IDs in core. Checks self-register at import time via `@register`; the registry provides `all_checks()` and `get(name)` for dynamic discovery.
- **No caching in the SDK.** One audit = one run; callers who want reuse implement it. Pure CPU helpers may use `@lru_cache`; never on DNS/HTTP.

See `.plan/v2/reference/architecture.md`, `.plan/v2/reference/patterns.md` for full detail.

---

## Config System

- Single `dnsight.yaml` (or `.json`) config file; discovered from CWD or `--config`.
- **Precedence** (low → high): built-in defaults → top-level check config → group config → group+check config → domain config → domain+check config.
- **CLI-only overlay:** Overlay and merge (file + CLI args → one config) live in the CLI package only. SDK and checks only see a config object. CLI merges overlay into config and passes the result to `audit(config)` or per-check entrypoints.
- **Merge immutability:** Merge never mutates the base (e.g. run default). Use copy-then-merge: return a new instance. Cache resolved config per (domain, check) for the run so each pair is merged once.
- Domains can belong to multiple groups; groups are merged in definition order (later wins).
- List fields support `+key` (append) and `-key` (remove) modifiers.
- Throttle and concurrency are configurable at every level; most specific (minimum) wins.
- **Defaults:** `core/config/defaults.py` holds all default constants. Config blocks in `core/config/blocks.py` use these defaults.
- **Config versioned migration:** Deferred. Currently single-version parse.

See `.plan/v2/reference/config-system.md` for full schema, precedence, CLI/audit, and implementation guide.

---

## Quality Bar

- Every change must pass `just check` and `just test` with no regressions.
- Coverage targets:
  - 100% — `core/models`, `core/enums`
  - ≥ 95% — `core/config`, `core/registry`, `core/runtime`
  - ≥ 90% — `orchestrator`, `serialisers`, `cli`
  - ≥ 85% — individual checks
- No `Any` on public API. No untyped functions in `src/`.
- New checks require: BaseCheck implementation, `@register` decorator, config slice, unit tests, docstrings.

---

## Gotchas

- Ask before changing security-sensitive logic (DNSSEC chain validation, DMARC policy evaluation).
- DNS and email edge cases must be handled explicitly — document in docstrings, not just comments.
- Do not add persistence, scheduling, or HTTP server logic — dnsight is stateless by design. No caching in the SDK; one audit = one run. Pure CPU helpers may use `@lru_cache`; never on DNS/HTTP.
- Do not import from `cli/` anywhere outside `cli/`. Do not import from `checks/` in `cli/`.
